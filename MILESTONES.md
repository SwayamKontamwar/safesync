# Milestones

## Milestone 6: Journal and process-crash recovery - Complete

- Persistent prepared, temp-written, and committed operation states
- Parent-forced process termination at every named transition
- Recovery after partial temp writes and post-replacement/pre-commit termination
- Byte-for-byte second-recovery idempotence checks
- State update followed by bounded committed-journal compaction

## Milestone 7: Windows filesystem hardening - Complete

- Strict state, journal, configuration, hash, operation-ID, and root-pair validation
- Stable scans and source revalidation after copy
- Journaled destination preconditions checked immediately before replacement
- Exclusive writer lock and locked-destination recovery
- Rejection of overlap, traversal, symlinks, junctions, reparse points, reserved
  names, alternate data streams, trailing dots/spaces, and case collisions
- Refusal of unsupported deletion without changing prior state

## Milestone 8: Usable alpha release - Complete

- `init`, `dry-run`, `sync`, `inspect`, and `recover` commands
- Standard `pyproject.toml` wheel/editable installation and console entry point
- MIT license, Windows CI, workflow and limitation documentation
- Deterministic randomized real-filesystem convergence test
- Clean-environment install and full-suite verification

"Complete" means the acceptance items above are implemented and tested. It does
not expand the deliberately excluded feature scope or claim power-loss durability.
