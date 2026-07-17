# SafeSync

SafeSync is a deliberately narrow, Windows-only local two-way folder
synchronizer for two explicitly selected directories. Version 0.3 supports
regular-file creation, modification, confirmed deletion, identity-backed file
and directory moves, conflict preservation, continuous watch mode, persistent
journaling, and idempotent process-crash recovery.

SafeSync remains alpha software. Start with disposable directories and retain an
independent backup of valuable data.

## Supported Environment

- Windows with NTFS or another local filesystem that supplies stable file IDs
- CPython 3.11, 3.12, or 3.13
- Two existing, distinct, non-overlapping local directories

Symbolic links, junctions, reparse points, permissions, alternate data streams,
and cross-platform synchronization are rejected or unsupported. Network shares
and cloud-placeholder directories are outside the verified scope.

## Clean Install

From a fresh clone in PowerShell:

```powershell
python -m venv .venv-clean
.venv-clean\Scripts\python.exe -m pip install --upgrade pip
.venv-clean\Scripts\python.exe -m pip install -e .
.venv-clean\Scripts\python.exe -m unittest -v
.venv-clean\Scripts\python.exe -m tests.crash_evidence
```

The editable install is used only so the tests exercise the checked-out source.
Runtime dependencies are declared in `pyproject.toml`; no pre-existing packages
or project state are required.

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
- Malformed, truncated, unsupported, or inconsistent metadata stops instead of
  being guessed through.
- Repeating unchanged sync or recovery produces a byte-identical persistent
  filesystem snapshot and no additional conflict or temporary files.

State, configuration, deletion intents, the operation journal, process lock,
trash backups, and conflict copies live under `.safesync` in the left root.
Human-readable operation logging is emitted to stderr with `--verbose`;
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

Named crash checkpoints are `after_journal_prepared`, `during_temp_copy`,
`after_temp_fsync`, `after_atomic_replace`, `after_delete_backup`,
`after_delete_unlink`, `after_move_destination`, `during_move_tree`,
`after_move_unlink`, `after_journal_commit`, and `after_state_commit`. Tests use
only checkpoints reachable by the operation under test. The parent confirms the
worker is alive at the checkpoint, kills it with the operating-system process
API, verifies an abnormal exit code, and compares complete pre/post recovery
snapshots. `python -m tests.crash_evidence` prints hashes, metadata, process exit
evidence, and path-level stage differences for the hardest binary conflict case.

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

Watchdog and periodic scans reduce event-loss risk but cannot prove that an OS
event was delivered. Consequently, SafeSync refuses deletion based only on a full
walk after an event gap or restart. Directory moves are optimized only when all
members have unique persisted identities and a consistent old/new prefix; other
cases degrade to conservative creates plus refused unexplained absences.
