# SafeSync

SafeSync is a deliberately narrow, Windows-only local two-way folder
synchronizer for two explicitly selected directories. Version 0.4 supports
regular-file creation, modification, confirmed deletion, identity-backed file
and directory moves, conflict preservation, continuous watch mode, persistent
journaling, idempotent process-crash recovery, and a live local interface with
journaled conflict resolution.

SafeSync remains alpha software. Start with disposable directories and retain an
independent backup of valuable data.

## Supported Environment

- Windows with NTFS or another local filesystem that supplies stable file IDs
- CPython 3.11, 3.12, or 3.13
- `python.exe` available as `python` on `PATH` (select **Add python.exe to
  PATH** in the Windows Python installer)
- Two existing, distinct, non-overlapping local directories

Symbolic links, junctions, reparse points, permissions, alternate data streams,
and cross-platform synchronization are rejected or unsupported. Network shares
and cloud-placeholder directories are outside the verified scope.

## Clean Install

From a fresh clone in PowerShell:

```powershell
python --version
python -m venv .venv-clean
.venv-clean\Scripts\python.exe -m pip install --upgrade pip
.venv-clean\Scripts\python.exe -m pip install -e ".[test]"
.venv-clean\Scripts\python.exe -m unittest -v
.venv-clean\Scripts\python.exe -m tests.crash_evidence
.venv-clean\Scripts\python.exe -m tests.resolution_crash_evidence
```

The editable install is used only so the tests exercise the checked-out source.
Runtime and test dependencies are declared in `pyproject.toml`; no pre-existing
Python packages, project state, or downloaded Playwright browser are required.
The Windows browser test drives the installed system Microsoft Edge and skips
cleanly when run on another platform or a Windows image without Edge.

## Commands

Both roots must already exist. Examples below use disposable directories.

```powershell
safesync init C:\sync-left C:\sync-right
safesync dry-run C:\sync-left C:\sync-right
safesync --verbose sync C:\sync-left C:\sync-right
safesync inspect C:\sync-left C:\sync-right
safesync recover C:\sync-left C:\sync-right
safesync delete C:\sync-left C:\sync-right left documents\old.txt
safesync watch C:\sync-left C:\sync-right --settle 1 --full-scan 30
safesync ui C:\sync-left C:\sync-right
```

`init` binds state to the canonical root pair without copying files. `sync`
recovers journaled work before planning current changes. `dry-run` creates no
control data and changes neither root. `inspect` reports pending work, conflicts,
deletion intents, and temporary files. `recover` explicitly resumes interrupted
work.

`delete` confirms a file that the user already removed from the named side, then
synchronizes. It refuses a path without last-good-sync history, a path that still
exists, or an expected hash that no longer matches history.

`watch` observes both roots. It waits for the entire event stream to remain quiet
for `--settle` seconds before reconciliation. A delete is propagated only after a
direct delete event remains absent through that interval. Move events do not
become deletion evidence. A mandatory full scan runs every `--full-scan` seconds,
and an overflow notification forces one; a full scan can recover missed creates
and modifications but intentionally cannot promote an unexplained absence into a
deletion. Writes made by SafeSync may wake the observer, but state comparison
makes those wakes no-ops instead of copies back in the opposite direction.

`ui` starts a loopback-only web interface and opens it in the default browser.
Use `--no-browser` to print the URL without opening it or `--port` to select a
fixed local port. The interface shows both roots, regular-file hashes and sizes,
pending journal operations and temp files, open conflicts, watch events,
persistent operation history, full journal, and last-good state. It can run a
one-shot sync, start or stop watch mode, and resolve conflicts by choosing left,
choosing right, or keeping both. Each launch uses an unguessable request token;
mutating API requests without that token are refused.

Choosing one side writes the immutable stored version to both roots. For an
edit-versus-delete conflict, choosing the deleted side honors the deletion only
after the survivor has a verified trash backup. `keep both` creates deterministic
conflict-suffixed files on both roots; for delete conflicts it preserves the
survivor at that alternate path while honoring deletion at the original path.
Move conflicts converge the selected paths on both roots. Stored conflict copies
remain as recovery evidence after resolution.

## Classification

- **Creation:** absent from last-good state and present on one side.
- **Modification:** same relative path and a SHA-256 content change. Timestamps
  are observations only and never decide equality.
- **Confirmed deletion:** present at last good sync, now absent, with an explicit
  CLI intent or a settled direct watch delete event.
- **Move:** an old path disappeared and exactly one new path has the same
  persisted filesystem identity. Content hash verifies the operation but never
  establishes identity. Ambiguous identities are not folded into a move.
- **Conflict:** both sides independently departed from last-good state, or one
  side deleted while the other edited, or moves diverged.
- **Recovery:** deterministic operation identity and journal status identify an
  interrupted operation. Recovery finishes that operation rather than planning a
  duplicate.

An unexplained disappearance is logged as `skip unconfirmed deletion`. The word
`skip` describes the refused synchronization action; it is not a unittest skip.
The peer file and last-good state remain unchanged.

## Safety Invariants

- A completed source file is never replaced with a partial copy.
- A destination replacement occurs only after a same-directory temporary file is
  flushed, SHA-256 verified, and checked against its journaled precondition.
- Conflicting byte sequences survive at deterministic conflict paths; retries do
  not create additional conflict files.
- A propagated deletion first creates and verifies a deterministic trash backup.
  Delete recovery never resurrects a committed tombstone.
- A move creates and verifies the destination before removing the old name. File
  moves use a hard link when available, so an interrupted move retains at least
  one name for the content.
- Every operational path is guarded beneath one selected root. Overlap, traversal,
  links/reparse points, reserved Windows names, trailing dots/spaces, ADS syntax,
  and case-insensitive collisions stop safely.
- One writer lock protects state and journal transitions.
- A process-local reentrant lock serializes UI, watcher, and server threads; the
  filesystem lock independently excludes other SafeSync processes.
- A resolution transaction persists the complete multi-operation batch before
  any destination changes. Every copy/delete still uses the ordinary journal,
  hash preconditions, temp flushing, verification, and atomic replacement.
- Malformed, truncated, unsupported, or inconsistent metadata stops instead of
  being guessed through.
- Repeating unchanged sync or recovery produces a byte-identical persistent
  filesystem snapshot and no additional conflict or temporary files.

State, configuration, deletion intents, resolution transactions, the operation
journal, persistent operation history, process lock, trash backups, and conflict
copies live under `.safesync` in the left root. Human-readable operation logging
is also emitted to stderr with `--verbose`;
destination-side trash backups live under that destination's `.safesync`
directory. Committed journal entries are compacted only after state is atomically
replaced.

## Verification Coverage

The unittest suite uses real temporary directories and real filesystem calls. It
covers both directions for create, change, confirmed delete, and move; deliberately
misleading timestamps; duplicate contents with distinct identities; a 1,000-image
directory rename; editor temp-file/flush/rename replacement; an actively writing
second process; event-loss full-scan fallback; Windows locks, junctions, and path
boundaries; and parent-forced worker termination followed by two recoveries.
The combined crash/concurrency matrix enumerates create, change, confirmed
delete, and move in both directions at every checkpoint reachable by that
operation. At each checkpoint two real writer threads change a synchronized file
independently on both sides before the parent kills the worker; recovery must
retain each writer's bytes exactly once and recovery two must match the complete
snapshot byte for byte.

Named crash checkpoints are `after_journal_prepared`, `during_temp_copy`,
`after_temp_fsync`, `after_atomic_replace`, `after_delete_backup`,
`after_delete_unlink`, `after_move_destination`, `during_move_tree`,
`after_move_unlink`, `after_journal_commit`, and `after_state_commit`. Tests use
only checkpoints reachable by the operation under test. The parent confirms the
worker is alive at the checkpoint, kills it with the operating-system process
API, verifies an abnormal exit code, and compares complete pre/post recovery
snapshots. `python -m tests.crash_evidence` prints hashes, metadata, process exit
evidence, and path-level stage differences for the hardest binary conflict case.
`python -m tests.resolution_crash_evidence` does the same for a UI-equivalent
resolution killed after its first required destination copy but before the batch
and state are finalized. Resolution tests kill a separate worker at intent,
batch-journal, temp-copy, fsync, atomic-replace, journal-commit, per-operation,
state-commit, and transaction-commit boundaries, then compare the full filesystem
after recovery one and recovery two byte for byte.

HTTP tests exercise token refusal, live status, conflict resolution, watch
start/stop, concurrent dashboard readers, and mid-copy journal/temp visibility.
A real headless Edge test drives the shipped HTML and JavaScript at desktop and
mobile viewports, resolves a conflict, watches a live file converge, captures
nonblank screenshots, and checks viewport overflow. These run under unittest;
the interface is not certified by manual clicking or screenshots alone.

Platform-specific tests use unittest skip decorators outside Windows. GitHub
Actions repeats the clean package install and full suite on Windows with Python
3.11, 3.12, and 3.13.

## Limits

The suite is evidence for the tested Windows filesystem and process-kill
boundaries, not a proof for every storage stack. It does not establish durability
across power loss, storage-controller cache loss, filesystem corruption, failing
hardware, kernel failure, remote filesystems, cloud hydration, or hostile
processes. Windows/Python provides no portable directory-fsync guarantee equal to
that available on some Unix filesystems.

SafeSync writers serialize, but ordinary applications do not honor its lock. If
an external application changes a resolution destination after the transaction
is prepared, its SHA-256 precondition fails. SafeSync leaves the live edit and all
immutable conflict copies intact and refuses recovery rather than guessing. That
pending transaction currently requires the destination to be restored to the
journaled hash before automatic recovery can continue; version 0.4 has no UI
command to discard or rebase an ambiguous prepared resolution.

Live dashboard reads intentionally do not acquire the writer lock so they can
display mid-copy state. They read atomically replaced metadata and are
observational snapshots, not synchronization decisions; every mutation reacquires
both locks and revalidates live hashes.

Watchdog and periodic scans reduce event-loss risk but cannot prove that an OS
event was delivered. Consequently, SafeSync refuses deletion based only on a full
walk after an event gap or restart. Directory moves are optimized only when all
members have unique persisted identities and a consistent old/new prefix; other
cases degrade to conservative creates plus refused unexplained absences.
