# SafeSync

SafeSync is a deliberately narrow local two-way folder synchronizer. It supports
regular-file creation and modification, hash-based conflict detection, atomic
replacement, persistent operation journaling, and idempotent crash recovery.
Deletion propagation, rename detection, symbolic links, and metadata sync are
intentionally unsupported.

```powershell
python -m safesync LEFT_DIRECTORY RIGHT_DIRECTORY --dry-run --verbose
python -m safesync LEFT_DIRECTORY RIGHT_DIRECTORY --verbose
python -m unittest discover -v
```

State, journal, and deterministic conflict copies live under `.safesync` in the
left selected root. Both roots must already exist, must not overlap, and may not
be symbolic links.

## Safety invariants

- A destination is replaced only after a complete same-directory temporary copy
  has been flushed and its SHA-256 hash verified.
- A completed source file is never opened for writing.
- Independently changed contents are never used to overwrite one another; both
  are retained at their original paths and as deterministic conflict copies.
- Every accessed path is relative to and revalidated beneath an explicitly
  selected root. Symlink traversal is refused.
- Recovery operations are content-addressed and journaled. Repeating recovery
  converges without creating additional files.
- Missing files that were previously recorded are treated as unsupported
  deletions and stop propagation for that path.
- Ambiguous or inconsistent journal, source, or destination content stops the
  operation instead of guessing.

## Classification limits

A path absent from prior state and present on one side is a new file. A path
recorded as present and now missing is a deletion, which is reported and not
propagated. Renames are intentionally not inferred: without stable filesystem
identity or rename history, a rename is represented as one unsupported deletion
plus one creation. Modifications are changes to the content hash at the same
relative path.

A true conflict means both sides' current hashes independently differ from their
last successful hashes and differ from each other. A repeated recovery has the
same deterministic operation ID, expected hash, and destination; the journal or
already-matching destination makes it a no-op.

## Crash injection

Tests can pause a worker by setting `SAFESYNC_PAUSE_POINT` and passing a localhost
signal port in `SAFESYNC_PAUSE_PORT`. After the worker reaches the named point it
signals the parent and waits. The parent verifies that the worker is still alive,
forcibly terminates it, and verifies the nonzero process result. Named points are
`after_journal_prepared`, `after_temp_fsync`, `after_atomic_replace`, and
`after_journal_commit`.
