# SafeSync

SafeSync is a deliberately narrow, Windows-only local two-way folder
synchronizer. It supports regular-file creation and modification, SHA-256-based
change detection, conflict preservation, same-directory atomic replacement,
persistent journaling, and idempotent process-crash recovery.

Deletion propagation, rename detection, symbolic links, junctions, permissions,
and metadata synchronization are intentionally unsupported. Do not use this
alpha release as the only copy of valuable data.

## Install

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install .
```

## Workflow

Both roots must already exist, be disposable while evaluating the tool, and be
distinct non-overlapping directories.

```powershell
safesync init C:\sync-left C:\sync-right
safesync dry-run C:\sync-left C:\sync-right
safesync --verbose sync C:\sync-left C:\sync-right
safesync inspect C:\sync-left C:\sync-right
safesync recover C:\sync-left C:\sync-right
```

`init` binds state to the exact canonical root pair without copying files.
`sync` first recovers journaled work and then synchronizes current changes.
`dry-run` plans without creating control files or changing either root.
`inspect` reports state count, pending journal operations, conflicts, and temp
files. `recover` explicitly resumes an interrupted synchronization and finishes
the resulting plan.

State, configuration, the operation journal, the process lock, and deterministic
conflict copies live under `.safesync` in the left root. Successful synchronization
compacts committed journal entries after the state file is atomically replaced.

## Safety invariants

- Source files are read-only to SafeSync and are rehashed after copying.
- A destination is replaced only after a same-directory temp copy is flushed and
  its SHA-256 hash is verified.
- The destination's planned prior hash or planned absence is journaled and checked
  again immediately before replacement.
- Independently changed originals remain in place and both exact contents are
  stored at deterministic conflict paths.
- Every operation path is relative to a selected root. Root overlap, traversal,
  symlinks, junctions, reparse points, Windows reserved names, trailing dots or
  spaces, alternate data-stream syntax, and case-insensitive collisions stop.
- One writer lock protects state and journal transitions.
- Malformed, truncated, unsupported, or internally inconsistent metadata stops
  before synchronization guesses.
- A previously recorded file that becomes absent is treated as an unsupported
  deletion. Neither side nor its prior state record is changed.
- Recovery operation IDs are derived from the complete intended transition.
  Repeating recovery converges without additional conflict files.

## Classification

A path absent from prior state and present on one side is a creation. A recorded
path that becomes absent is an unsupported deletion and is refused. A content
hash change at the same relative path is a modification. Renames are not inferred:
they appear as one refused deletion and one creation.

A conflict means both current hashes independently differ from the last successful
left and right hashes and from each other. A recovery attempt is recognized by its
deterministic operation ID, source hash, destination precondition, and destination.

## Verification

```powershell
python -m unittest -v
python -m tests.crash_evidence
```

The suite uses real temporary directories, real copying and replacement, Windows
file locks and junctions, misleading timestamps, deterministic randomized files,
and parent-forced worker termination. Named checkpoints are
`after_journal_prepared`, `during_temp_copy`, `after_temp_fsync`,
`after_atomic_replace`, and `after_journal_commit`.
The state/journal ordering boundary `after_state_commit` is also externally killed
in the recovery matrix.

## Limits

The tests demonstrate recovery from process termination on the tested Windows
filesystem. They do not prove durability across machine power loss, storage
controller cache loss, filesystem corruption, failing hardware, kernel failure,
or a hostile process changing a destination in the final instant between the
precondition check and `os.replace`. Windows does not expose a portable Python
directory-fsync guarantee equivalent to durable directory entry flushing on some
Unix filesystems.
