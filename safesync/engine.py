from __future__ import annotations

import hashlib
import logging
import os
import socket
import time
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from .filesystem import (
    CONTROL_DIRECTORY,
    SafetyError,
    atomic_write_json,
    exclusive_lock,
    guarded_path,
    is_reparse_point,
    load_json,
    scan_tree,
    sha256_file,
    validate_roots,
)
from .model import (
    ConflictCase,
    ConflictVersion,
    JournalOperation,
    DeletionIntent,
    OperationKind,
    OperationStatus,
    PlannedOperation,
    Roots,
    ResolutionResult,
    SyncRecord,
)

LOGGER = logging.getLogger("safesync")
STATE_VERSION = 3
CRASH_POINTS = (
    "after_journal_prepared",
    "during_temp_copy",
    "after_temp_fsync",
    "after_atomic_replace",
    "after_journal_commit",
    "after_state_commit",
    "after_delete_backup",
    "after_delete_unlink",
    "after_move_destination",
    "after_move_unlink",
    "during_move_tree",
    "after_resolution_intent",
    "after_resolution_journal_prepared",
    "after_resolution_operation",
    "after_resolution_state_commit",
    "after_resolution_commit",
)


@dataclass(frozen=True)
class SyncResult:
    planned: int
    committed: int
    conflicts: int
    skipped: int
    changed: bool


@dataclass(frozen=True)
class Inspection:
    initialized: bool
    state_files: int
    pending_operations: int
    committed_operations: int
    conflict_files: tuple[str, ...]
    temporary_files: tuple[str, ...]
    deletion_conflicts: tuple[str, ...]
    deletion_intents: tuple[str, ...]
    unconfirmed_deletions: tuple[str, ...]


class SyncEngine:
    def __init__(self, left: Path, right: Path, *, dry_run: bool = False) -> None:
        left_root, right_root = validate_roots(left, right)
        self.roots = Roots(left_root, right_root)
        self.dry_run = dry_run
        self.control = left_root / CONTROL_DIRECTORY
        if self.control.exists() and is_reparse_point(self.control):
            raise SafetyError("tool control directory may not be a reparse point")
        self.config_path = self.control / "config.json"
        self.state_path = self.control / "state.json"
        self.journal_path = self.control / "journal.json"
        self.intents_path = self.control / "deletions.json"
        self.resolutions_path = self.control / "resolutions.json"
        self.operations_path = self.control / "operations.json"
        self.lock_path = self.control / "lock"

    def initialize(self) -> bool:
        with exclusive_lock(self.lock_path):
            if self.config_path.exists():
                self._verify_config()
                if not self.state_path.exists():
                    atomic_write_json(self.state_path, {"version": STATE_VERSION, "files": {}})
                if not self.journal_path.exists():
                    atomic_write_json(self.journal_path, {"version": STATE_VERSION, "operations": {}})
                if not self.intents_path.exists():
                    atomic_write_json(self.intents_path, {"version": STATE_VERSION, "intents": {}})
                if not self.resolutions_path.exists():
                    atomic_write_json(self.resolutions_path, {"version": STATE_VERSION, "transactions": {}})
                if not self.operations_path.exists():
                    atomic_write_json(self.operations_path, {"version": STATE_VERSION, "events": []})
                return False
            if self.state_path.exists() or self.journal_path.exists():
                raise SafetyError("state or journal exists without root-pair configuration")
            atomic_write_json(self.config_path, self._config_payload())
            atomic_write_json(self.state_path, {"version": STATE_VERSION, "files": {}})
            atomic_write_json(self.journal_path, {"version": STATE_VERSION, "operations": {}})
            atomic_write_json(self.intents_path, {"version": STATE_VERSION, "intents": {}})
            atomic_write_json(self.resolutions_path, {"version": STATE_VERSION, "transactions": {}})
            atomic_write_json(self.operations_path, {"version": STATE_VERSION, "events": []})
            return True

    def confirm_deletion(self, side: str, relative: str, *, evidence: str = "explicit") -> DeletionIntent:
        with exclusive_lock(self.lock_path):
            self._verify_config()
            records = self._load_state()
            if relative not in records:
                raise SafetyError(f"cannot confirm deletion without synchronized history: {relative}")
            record = records[relative]
            expected_hash = record.left_hash if side == "left" else record.right_hash if side == "right" else None
            if expected_hash is None:
                raise SafetyError(f"path was not present on {side} at the last successful sync: {relative}")
            path = guarded_path(self.roots.get(side), relative)
            if path.exists():
                raise SafetyError(f"cannot confirm deletion while path exists: {path}")
            identity = hashlib.sha256(f"{side}\0{relative}\0{expected_hash}".encode()).hexdigest()[:24]
            intent = DeletionIntent(identity, side, relative, expected_hash, evidence, time.time_ns())
            intents = self._load_intents()
            intents[identity] = intent
            self._save_intents(intents)
            return intent

    def inspect(self) -> Inspection:
        initialized = self.config_path.exists()
        if initialized:
            self._verify_config()
        elif self.state_path.exists() or self.journal_path.exists():
            raise SafetyError("state or journal exists without root-pair configuration")
        records = self._load_state() if self.state_path.exists() else {}
        journal = self._load_journal() if self.journal_path.exists() else {}
        intents = self._load_intents() if self.intents_path.exists() else {}
        left_files = scan_tree(self.roots.left)
        right_files = scan_tree(self.roots.right)
        conflicts_root = self.control / "conflicts"
        conflicts: tuple[str, ...] = ()
        if conflicts_root.exists():
            found_conflicts: list[str] = []
            for directory, names, filenames in os.walk(conflicts_root, topdown=True, followlinks=False):
                directory_path = Path(directory)
                for name in names:
                    if is_reparse_point(directory_path / name):
                        raise SafetyError("conflict storage contains a reparse point")
                for name in filenames:
                    path = directory_path / name
                    if is_reparse_point(path):
                        raise SafetyError("conflict storage contains a reparse point")
                    found_conflicts.append(path.relative_to(self.roots.left).as_posix())
            conflicts = tuple(sorted(found_conflicts))
        temporary = tuple(
            f"{side}:{path.relative_to(root).as_posix()}"
            for side, root in (("left", self.roots.left), ("right", self.roots.right))
            for path in sorted(root.rglob(".safesync-tmp-*"))
            if path.is_file()
        )
        return Inspection(
            initialized=initialized,
            state_files=len(records),
            pending_operations=sum(entry.status != OperationStatus.COMMITTED for entry in journal.values()),
            committed_operations=sum(entry.status == OperationStatus.COMMITTED for entry in journal.values()),
            conflict_files=conflicts,
            temporary_files=temporary,
            deletion_conflicts=tuple(
                sorted(path for path, record in records.items() if record.left_deleted or record.right_deleted)
            ),
            deletion_intents=tuple(sorted(f"{intent.side}:{intent.relative_path}" for intent in intents.values())),
            unconfirmed_deletions=tuple(sorted(
                f"{side}:{path}"
                for path, record in records.items()
                for side, expected, files in (
                    ("left", record.left_hash, left_files), ("right", record.right_hash, right_files)
                )
                if expected is not None
                and path not in files
                and (side, path) not in {(intent.side, intent.relative_path) for intent in intents.values()}
            )),
        )

    def list_conflicts(self) -> tuple[ConflictCase, ...]:
        with exclusive_lock(self.lock_path):
            self._verify_config()
            self._recover_journal()
            self._recover_resolutions_locked()
            return self._list_conflicts_locked()

    def _list_conflicts_locked(self) -> tuple[ConflictCase, ...]:
        records = self._load_state()
        root = self.control / "conflicts"
        if not root.exists():
            return ()
        cases: list[ConflictCase] = []
        for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
            current = Path(directory)
            if is_reparse_point(current):
                raise SafetyError("conflict storage contains a reparse point")
            if names or not filenames:
                continue
            files = [current / name for name in sorted(filenames)]
            if any(is_reparse_point(path) for path in files):
                raise SafetyError("conflict storage contains a reparse point")
            group_relative = current.relative_to(root).as_posix()
            parts = PurePosixPath(group_relative).parts
            is_move = bool(parts and parts[0] == "moves")
            target = None if is_move else "/".join(parts[:-1])
            deleted_side = None
            versions: list[ConflictVersion] = []
            for path in files:
                label = path.name
                content_hash = sha256_file(path)
                if label.startswith("edited-") and "-delete-" in label:
                    side = label[len("edited-"):].split("-delete-", 1)[0]
                else:
                    side = "left" if "left" in label else "right" if "right" in label else "unknown"
                preferred = target
                if "-delete-" in label:
                    deleted_side = label.rsplit("-delete-", 1)[1]
                if is_move:
                    candidates = []
                    for relative, record in records.items():
                        if not record.move_conflict:
                            continue
                        side_hash = record.left_hash if side == "left" else record.right_hash
                        if side_hash == content_hash:
                            candidates.append(relative)
                    preferred = candidates[0] if len(candidates) == 1 else None
                versions.append(ConflictVersion(
                    label=label,
                    side=side,
                    stored_relative=path.relative_to(self.roots.left).as_posix(),
                    content_hash=content_hash,
                    size=path.stat().st_size,
                    preferred_path=preferred,
                ))
            if is_move:
                matching = [version for version in versions if version.preferred_path is not None]
                if not matching:
                    continue
                paths = {item.preferred_path for item in matching if item.preferred_path}
                open_case = any(records[path].move_conflict for path in paths)
                resolvable = len(matching) >= 2 and all(item.side in {"left", "right"} for item in matching)
                kind = "move"
                display = " / ".join(sorted(paths))
                reason = None if resolvable else "move conflict paths cannot be mapped uniquely to stored versions"
            else:
                record = records.get(target or "")
                if record is None:
                    continue
                open_case = bool(
                    record.move_conflict or record.left_deleted or record.right_deleted
                    or record.left_hash != record.right_hash
                )
                kind = "delete" if deleted_side else "content"
                display = target or group_relative
                resolvable = (
                    len(versions) == 1 and versions[0].side in {"left", "right"}
                    if deleted_side else {item.side for item in versions} >= {"left", "right"}
                )
                reason = None if resolvable else "stored conflict versions are incomplete or ambiguous"
            if not open_case:
                continue
            cases.append(ConflictCase(
                conflict_id=hashlib.sha256(group_relative.encode()).hexdigest()[:16],
                kind=kind,
                display_path=display,
                versions=tuple(versions),
                deleted_side=deleted_side,
                resolvable=resolvable,
                reason=reason,
            ))
        return tuple(sorted(cases, key=lambda item: (item.display_path, item.conflict_id)))

    def resolve_conflict(self, conflict_id: str, choice: str) -> ResolutionResult:
        if choice not in {"left", "right", "keep_both"}:
            raise SafetyError(f"unsupported conflict resolution choice: {choice}")
        with exclusive_lock(self.lock_path):
            self._verify_config()
            recovered = self._recover_journal()
            recovered += self._recover_resolutions_locked()
            case = {item.conflict_id: item for item in self._list_conflicts_locked()}.get(conflict_id)
            if case is None:
                raise SafetyError(f"conflict is no longer open: {conflict_id}")
            if not case.resolvable:
                raise SafetyError(case.reason or f"conflict cannot be resolved safely: {conflict_id}")
            operations, expected, affected = self._plan_resolution(case, choice)
            transaction_id = hashlib.sha256(
                (f"resolve\0{case.conflict_id}\0{choice}\0" + "\0".join(
                    self._operation_id(operation) for operation in operations
                )).encode()
            ).hexdigest()[:24]
            transactions = self._load_resolutions()
            if transaction_id in transactions:
                raise SafetyError(f"resolution transaction already exists: {transaction_id}")
            transaction = {
                "transaction_id": transaction_id,
                "conflict_id": case.conflict_id,
                "choice": choice,
                "status": "prepared",
                "operations": [asdict(operation) for operation in operations],
                "expected": expected,
                "affected_paths": sorted(affected),
            }
            transactions[transaction_id] = transaction
            self._save_resolutions(transactions)
            self._pause_for_external_kill("after_resolution_intent")
            self._prepare_and_finish_batch(operations)
            self._finalize_resolution(transaction, transactions)
            return ResolutionResult(transaction_id, conflict_id, choice, len(operations), recovered)

    def _plan_resolution(self, case: ConflictCase, choice: str):
        current = {"left": scan_tree(self.roots.left), "right": scan_tree(self.roots.right)}
        operations: list[PlannedOperation] = []
        expected: dict[str, dict[str, str | None]] = {"left": {}, "right": {}}
        affected: set[str] = set()

        def copy(version: ConflictVersion, side: str, relative: str) -> None:
            prior = current[side].get(relative)
            operations.append(PlannedOperation(
                OperationKind.RESOLVE_COPY, "left", version.stored_relative, side, relative,
                version.content_hash, prior.content_hash if prior else None,
            ))
            expected[side][relative] = version.content_hash
            affected.add(relative)

        def delete(side: str, relative: str) -> None:
            prior = current[side].get(relative)
            if prior is not None:
                operations.append(PlannedOperation(
                    OperationKind.DELETE, side, relative, side, relative, prior.content_hash,
                    prior.content_hash,
                    backup_relative=f"{CONTROL_DIRECTORY}/trash/resolutions/{case.conflict_id}/{side}/{relative}",
                ))
            expected[side][relative] = None
            affected.add(relative)

        by_side = {version.side: version for version in case.versions if version.side in {"left", "right"}}
        if case.kind == "content":
            selected = by_side.get("left" if choice == "keep_both" else choice)
            if selected is None:
                raise SafetyError(f"selected conflict side is unavailable: {choice}")
            destination_order = ("right", "left") if selected.side == "left" else ("left", "right")
            for side in destination_order:
                copy(selected, side, case.display_path)
            if choice == "keep_both":
                for version in (by_side["left"], by_side["right"]):
                    alternate = self._conflict_alternate(case.display_path, version.side, case.conflict_id)
                    for side in ("left", "right"):
                        copy(version, side, alternate)
        elif case.kind == "delete":
            survivor = case.versions[0]
            if choice == survivor.side:
                destination_order = ("right", "left") if survivor.side == "left" else ("left", "right")
                for side in destination_order:
                    copy(survivor, side, case.display_path)
            elif choice == case.deleted_side:
                for side in ("left", "right"):
                    delete(side, case.display_path)
            elif choice == "keep_both":
                alternate = self._conflict_alternate(case.display_path, survivor.side, case.conflict_id)
                for side in ("left", "right"):
                    copy(survivor, side, alternate)
                    delete(side, case.display_path)
            else:
                raise SafetyError(f"selected conflict side is unavailable: {choice}")
        else:
            selected = by_side.get("left" if choice == "keep_both" else choice)
            if selected is None or selected.preferred_path is None:
                raise SafetyError(f"selected move version is unavailable: {choice}")
            if choice == "keep_both":
                used_paths: set[str] = set()
                for version in (by_side["left"], by_side["right"]):
                    target = version.preferred_path
                    if target is None:
                        raise SafetyError("move conflict path is ambiguous")
                    if target in used_paths:
                        target = self._conflict_alternate(target, version.side, case.conflict_id)
                    used_paths.add(target)
                    for side in ("left", "right"):
                        copy(version, side, target)
            else:
                target = selected.preferred_path
                for side in ("left", "right"):
                    copy(selected, side, target)
                for other in {item.preferred_path for item in case.versions if item.preferred_path != target}:
                    if other:
                        for side in ("left", "right"):
                            delete(side, other)
        for relative in affected:
            for side in ("left", "right"):
                observation = current[side].get(relative)
                expected[side].setdefault(relative, observation.content_hash if observation else None)
        return operations, expected, affected

    @staticmethod
    def _conflict_alternate(relative: str, side: str, conflict_id: str) -> str:
        path = PurePosixPath(relative)
        suffix = path.suffix
        stem = path.name[:-len(suffix)] if suffix else path.name
        return str(path.with_name(f"{stem}.safesync-{side}-{conflict_id[:8]}{suffix}"))

    def recover(self) -> SyncResult:
        return self.sync()

    def abandon_stale_prepared_copies(self) -> int:
        with exclusive_lock(self.lock_path):
            self._verify_config()
            journal = self._load_journal()
            abandoned = 0
            for operation_id, entry in list(journal.items()):
                if entry.status != OperationStatus.PREPARED or entry.kind not in {
                    OperationKind.COPY,
                    OperationKind.PRESERVE_CONFLICT,
                }:
                    continue
                source = guarded_path(self.roots.get(entry.source_side), entry.source_relative)
                if source.exists() and sha256_file(source) == entry.expected_hash:
                    continue
                destination = guarded_path(
                    self.roots.get(entry.destination_side), entry.destination_relative, allow_control=True
                )
                self._verify_destination_precondition(destination, entry.destination_prior_hash)
                temp = destination.parent / entry.temp_name
                if temp.exists():
                    temp.unlink()
                del journal[operation_id]
                abandoned += 1
            if abandoned:
                self._save_journal(journal)
            return abandoned

    def sync(self) -> SyncResult:
        if self.dry_run:
            if self.config_path.exists():
                self._verify_config()
            return self._sync_locked()
        with exclusive_lock(self.lock_path):
            if not self.config_path.exists():
                if self.state_path.exists() or self.journal_path.exists():
                    raise SafetyError("state or journal exists without root-pair configuration")
                atomic_write_json(self.config_path, self._config_payload())
            self._verify_config()
            return self._sync_locked()

    def _sync_locked(self) -> SyncResult:
        recovered = 0 if self.dry_run else self._recover_journal()
        if not self.dry_run:
            recovered += self._recover_resolutions_locked()
        left_files = scan_tree(self.roots.left)
        right_files = scan_tree(self.roots.right)
        folded_paths: dict[str, str] = {}
        for relative in sorted(set(left_files) | set(right_files)):
            folded = relative.casefold()
            if folded in folded_paths and folded_paths[folded] != relative:
                raise SafetyError(
                    f"cross-root case-insensitive collision: {folded_paths[folded]!r} and {relative!r}"
                )
            folded_paths[folded] = relative
        records = self._load_state()
        intents = self._load_intents()
        intents_by_path = {(intent.side, intent.relative_path): intent for intent in intents.values()}
        operations: list[PlannedOperation] = []
        committed = recovered
        conflicts = 0
        skipped = 0
        preserve_previous_state: set[str] = set()
        tombstones: set[str] = set()
        state_overrides: dict[str, SyncRecord] = {}
        consumed_intents: set[str] = set()
        handled_paths: set[str] = set()

        left_moves = self._detect_moves("left", records, left_files)
        right_moves = self._detect_moves("right", records, right_files)
        for moved_side, moves, other_files in (
            ("left", left_moves, right_files), ("right", right_moves, left_files)
        ):
            other_side = "right" if moved_side == "left" else "left"
            for old_dir, new_dir, members in self._tree_move_groups(moves, records):
                if any(path in (right_moves if moved_side == "left" else left_moves) for path in members):
                    continue
                if not all(path in other_files for path in members):
                    continue
                if any((new_dir + path[len(old_dir):]) in other_files for path in members):
                    continue
                expected = self._tree_manifest_hash_from_observations(other_files, old_dir, members)
                operations.append(self._move_tree_operation(other_side, old_dir, new_dir, expected))
                for old_path in members:
                    handled_paths.add(old_path)
                    handled_paths.add(moves[old_path])
                    tombstones.add(old_path)
                    moves.pop(old_path)
        for old_path in sorted(set(left_moves) | set(right_moves)):
            left_new = left_moves.get(old_path)
            right_new = right_moves.get(old_path)
            previous = records[old_path]
            if left_new and right_new:
                if left_new == right_new:
                    handled_paths.update((old_path, left_new))
                    tombstones.add(old_path)
                else:
                    operations.extend(self._move_conflict_operations(old_path, left_new, right_new, left_files, right_files))
                    conflicts += 1
                    handled_paths.update((old_path, left_new, right_new))
                    tombstones.add(old_path)
                    state_overrides[left_new] = SyncRecord(
                        left_files[left_new].content_hash, None, left_files[left_new].identity, None,
                        move_conflict=True,
                    )
                    state_overrides[right_new] = SyncRecord(
                        None, right_files[right_new].content_hash, None, right_files[right_new].identity,
                        move_conflict=True,
                    )
                continue
            moved_side = "left" if left_new else "right"
            new_path = left_new or right_new
            other_side = "right" if moved_side == "left" else "left"
            other_files = right_files if other_side == "right" else left_files
            other_old = other_files.get(old_path)
            other_previous_hash = previous.right_hash if other_side == "right" else previous.left_hash
            if other_old and other_old.content_hash == other_previous_hash and new_path not in other_files:
                operations.append(self._move_operation(other_side, old_path, new_path, other_old.content_hash))
                handled_paths.update((old_path, new_path))
                tombstones.add(old_path)
            else:
                moved_files = left_files if moved_side == "left" else right_files
                operations.extend(self._move_edit_conflict_operations(
                    old_path, new_path, moved_side, moved_files[new_path], other_side, other_old
                ))
                conflicts += 1
                handled_paths.update((old_path, new_path))
                tombstones.add(old_path)
                moved = moved_files[new_path]
                if moved_side == "left":
                    state_overrides[new_path] = SyncRecord(
                        moved.content_hash, None, moved.identity, None, move_conflict=True
                    )
                else:
                    state_overrides[new_path] = SyncRecord(
                        None, moved.content_hash, None, moved.identity, move_conflict=True
                    )
                if other_old:
                    if other_side == "left":
                        state_overrides[old_path] = SyncRecord(
                            other_old.content_hash, None, other_old.identity, None, move_conflict=True
                        )
                    else:
                        state_overrides[old_path] = SyncRecord(
                            None, other_old.content_hash, None, other_old.identity, move_conflict=True
                        )

        for relative in sorted(set(left_files) | set(right_files) | set(records)):
            if relative in handled_paths:
                continue
            left = left_files.get(relative)
            right = right_files.get(relative)
            previous = records.get(relative)

            if previous and previous.move_conflict:
                left_stable = left is None or left.content_hash == previous.left_hash
                right_stable = right is None or right.content_hash == previous.right_hash
                if left_stable and right_stable:
                    state_overrides[relative] = previous
                    continue
                if (left is None) != (right is None):
                    survivor = left or right
                    survivor_side = "left" if left else "right"
                    conflict_id = hashlib.sha256(
                        f"move-conflict-update\0{relative}\0{survivor.content_hash}".encode()
                    ).hexdigest()[:16]
                    operations.append(PlannedOperation(
                        OperationKind.PRESERVE_CONFLICT, survivor_side, relative, "left",
                        f"{CONTROL_DIRECTORY}/conflicts/moves/{conflict_id}/{survivor_side}",
                        survivor.content_hash, None,
                    ))
                    conflicts += 1
                    state_overrides[relative] = SyncRecord(
                        survivor.content_hash if left else None,
                        survivor.content_hash if right else None,
                        survivor.identity if left else None,
                        survivor.identity if right else None,
                        move_conflict=True,
                    )
                    continue

            if previous and previous.tombstone and left is None and right is None:
                tombstones.add(relative)
                continue

            if previous and previous.left_deleted and left is None and right is not None:
                if right.content_hash == previous.right_hash:
                    state_overrides[relative] = previous
                    continue
                synthetic = DeletionIntent(
                    hashlib.sha256(f"left\0{relative}\0{previous.right_hash}".encode()).hexdigest()[:24],
                    "left", relative, previous.right_hash or right.content_hash,
                    "existing-conflict", time.time_ns(),
                )
                operations.append(self._deletion_conflict_operation(synthetic, right.content_hash))
                conflicts += 1
                state_overrides[relative] = SyncRecord(
                    None, right.content_hash, None, right.identity, False, True, False
                )
                continue
            if previous and previous.right_deleted and right is None and left is not None:
                if left.content_hash == previous.left_hash:
                    state_overrides[relative] = previous
                    continue
                synthetic = DeletionIntent(
                    hashlib.sha256(f"right\0{relative}\0{previous.left_hash}".encode()).hexdigest()[:24],
                    "right", relative, previous.left_hash or left.content_hash,
                    "existing-conflict", time.time_ns(),
                )
                operations.append(self._deletion_conflict_operation(synthetic, left.content_hash))
                conflicts += 1
                state_overrides[relative] = SyncRecord(
                    left.content_hash, None, left.identity, None, False, False, True
                )
                continue

            if previous and ((left is None and previous.left_hash) or (right is None and previous.right_hash)):
                missing_side = "left" if left is None and previous.left_hash else "right"
                intent = intents_by_path.get((missing_side, relative))
                expected = previous.left_hash if missing_side == "left" else previous.right_hash
                if intent is None or intent.expected_hash != expected:
                    LOGGER.warning("skip unconfirmed deletion path=%s side=%s", relative, missing_side)
                    skipped += 1
                    preserve_previous_state.add(relative)
                    continue
                survivor = right if missing_side == "left" else left
                survivor_previous = previous.right_hash if missing_side == "left" else previous.left_hash
                consumed_intents.add(intent.intent_id)
                if survivor is None:
                    opposite = intents_by_path.get(("right" if missing_side == "left" else "left", relative))
                    if opposite:
                        consumed_intents.add(opposite.intent_id)
                    tombstones.add(relative)
                elif survivor.content_hash == survivor_previous:
                    operations.append(self._delete_operation(
                        intent, "right" if missing_side == "left" else "left", survivor_previous
                    ))
                    tombstones.add(relative)
                else:
                    operations.append(self._deletion_conflict_operation(intent, survivor.content_hash))
                    conflicts += 1
                    if missing_side == "left":
                        state_overrides[relative] = SyncRecord(
                            None, survivor.content_hash, None, survivor.identity, False, True, False
                        )
                    else:
                        state_overrides[relative] = SyncRecord(
                            survivor.content_hash, None, survivor.identity, None, False, False, True
                        )
                continue

            if left is None and right is not None:
                operations.append(self._copy("right", "left", relative, right.content_hash, None))
            elif right is None and left is not None:
                operations.append(self._copy("left", "right", relative, left.content_hash, None))
            elif left is None or right is None:
                continue
            elif left.content_hash == right.content_hash:
                continue
            elif previous is None:
                operations.extend(self._conflict_operations(relative, left.content_hash, right.content_hash))
                conflicts += 1
            else:
                left_changed = left.content_hash != previous.left_hash
                right_changed = right.content_hash != previous.right_hash
                if left_changed and not right_changed:
                    operations.append(self._copy("left", "right", relative, left.content_hash, right.content_hash))
                elif right_changed and not left_changed:
                    operations.append(self._copy("right", "left", relative, right.content_hash, left.content_hash))
                elif left_changed and right_changed:
                    operations.extend(self._conflict_operations(relative, left.content_hash, right.content_hash))
                    conflicts += 1
                else:
                    LOGGER.info("stable preserved conflict path=%s", relative)

        for operation in operations:
            LOGGER.info(
                "%s kind=%s source=%s:%s destination=%s:%s",
                "would-write" if self.dry_run else "write",
                operation.kind,
                operation.source_side,
                operation.source_relative,
                operation.destination_side,
                operation.destination_relative,
            )
            if not self.dry_run:
                committed += int(self._execute(operation))

        if not self.dry_run:
            final_left = scan_tree(self.roots.left)
            final_right = scan_tree(self.roots.right)
            self._verify_final_tree(left_files, right_files, operations, final_left, final_right)
            next_records = {
                relative: SyncRecord(
                    final_left[relative].content_hash if relative in final_left else None,
                    final_right[relative].content_hash if relative in final_right else None,
                    final_left[relative].identity if relative in final_left else None,
                    final_right[relative].identity if relative in final_right else None,
                )
                for relative in sorted(set(final_left) | set(final_right))
            }
            for relative in preserve_previous_state:
                next_records[relative] = records[relative]
            for relative in tombstones:
                next_records[relative] = SyncRecord(None, None, tombstone=True)
            next_records.update(state_overrides)
            if next_records != records or not self.state_path.exists():
                self._save_state(next_records)
                self._pause_for_external_kill("after_state_commit")
            if consumed_intents:
                remaining = {key: value for key, value in intents.items() if key not in consumed_intents}
                self._save_intents(remaining)
            self._compact_journal()

        return SyncResult(
            planned=len(operations),
            committed=0 if self.dry_run else committed,
            conflicts=conflicts,
            skipped=skipped,
            changed=bool(operations or recovered),
        )

    def _verify_final_tree(self, initial_left, initial_right, operations, final_left, final_right) -> None:
        expected = {
            "left": {path: item.content_hash for path, item in initial_left.items()},
            "right": {path: item.content_hash for path, item in initial_right.items()},
        }
        for operation in operations:
            destination = expected[operation.destination_side]
            if operation.kind in {OperationKind.COPY, OperationKind.RESOLVE_COPY}:
                destination[operation.destination_relative] = operation.expected_hash
            elif operation.kind == OperationKind.DELETE:
                destination.pop(operation.destination_relative, None)
            elif operation.kind == OperationKind.MOVE:
                destination.pop(operation.move_source_relative or operation.source_relative, None)
                destination[operation.destination_relative] = operation.expected_hash
            elif operation.kind == OperationKind.MOVE_TREE:
                old_prefix = (operation.move_source_relative or operation.source_relative).rstrip("/")
                new_prefix = operation.destination_relative.rstrip("/")
                moved = {
                    path: content_hash
                    for path, content_hash in destination.items()
                    if path == old_prefix or path.startswith(old_prefix + "/")
                }
                for path, content_hash in moved.items():
                    del destination[path]
                    suffix = path[len(old_prefix):].lstrip("/")
                    destination[f"{new_prefix}/{suffix}" if suffix else new_prefix] = content_hash

        actual = {
            "left": {path: item.content_hash for path, item in final_left.items()},
            "right": {path: item.content_hash for path, item in final_right.items()},
        }
        if actual != expected:
            raise SafetyError("filesystem changed during synchronization; refusing state commit")

    def _copy(
        self, source: str, destination: str, relative: str, content_hash: str, destination_prior_hash: str | None
    ) -> PlannedOperation:
        return PlannedOperation(
            OperationKind.COPY, source, relative, destination, relative, content_hash, destination_prior_hash
        )

    def _conflict_operations(self, relative: str, left_hash: str, right_hash: str) -> list[PlannedOperation]:
        conflict_id = hashlib.sha256(f"{relative}\0{left_hash}\0{right_hash}".encode()).hexdigest()[:16]
        safe_path = "/".join(PurePosixPath(relative).parts)
        base = f"{CONTROL_DIRECTORY}/conflicts/{safe_path}/{conflict_id}"
        return [
            PlannedOperation(
                OperationKind.PRESERVE_CONFLICT, "left", relative, "left", f"{base}/left", left_hash, None
            ),
            PlannedOperation(
                OperationKind.PRESERVE_CONFLICT, "right", relative, "left", f"{base}/right", right_hash, None
            ),
        ]

    def _delete_operation(
        self, intent: DeletionIntent, destination_side: str, destination_prior_hash: str
    ) -> PlannedOperation:
        backup = f"{CONTROL_DIRECTORY}/trash/{intent.intent_id}/{destination_side}"
        return PlannedOperation(
            OperationKind.DELETE, intent.side, intent.relative_path, destination_side, intent.relative_path,
            destination_prior_hash, destination_prior_hash, backup,
        )

    def _deletion_conflict_operation(self, intent: DeletionIntent, survivor_hash: str) -> PlannedOperation:
        survivor_side = "right" if intent.side == "left" else "left"
        conflict_id = hashlib.sha256(
            f"delete\0{intent.side}\0{intent.relative_path}\0{intent.expected_hash}\0{survivor_hash}".encode()
        ).hexdigest()[:16]
        destination = (
            f"{CONTROL_DIRECTORY}/conflicts/{intent.relative_path}/{conflict_id}/"
            f"edited-{survivor_side}-delete-{intent.side}"
        )
        return PlannedOperation(
            OperationKind.PRESERVE_CONFLICT, survivor_side, intent.relative_path,
            "left", destination, survivor_hash, None,
        )

    def _detect_moves(self, side: str, records, current) -> dict[str, str]:
        previous_by_identity: dict[str, list[str]] = {}
        current_by_identity: dict[str, list[str]] = {}
        for path, record in records.items():
            identity = record.left_identity if side == "left" else record.right_identity
            if identity:
                previous_by_identity.setdefault(identity, []).append(path)
        for path, observation in current.items():
            current_by_identity.setdefault(observation.identity, []).append(path)
        moves: dict[str, str] = {}
        for identity in set(previous_by_identity) & set(current_by_identity):
            old_paths = previous_by_identity[identity]
            new_paths = current_by_identity[identity]
            if len(old_paths) == len(new_paths) == 1 and old_paths[0] != new_paths[0]:
                moves[old_paths[0]] = new_paths[0]
        return moves

    def _move_operation(self, side: str, old_path: str, new_path: str, content_hash: str) -> PlannedOperation:
        return PlannedOperation(
            OperationKind.MOVE, side, old_path, side, new_path, content_hash, None,
            move_source_relative=old_path,
        )

    def _tree_move_groups(self, moves, records):
        grouped: dict[tuple[str, str], list[str]] = {}
        for old_path, new_path in moves.items():
            old_parts = PurePosixPath(old_path).parts
            new_parts = PurePosixPath(new_path).parts
            common_suffix = 0
            while (
                common_suffix < min(len(old_parts), len(new_parts))
                and old_parts[-1 - common_suffix] == new_parts[-1 - common_suffix]
            ):
                common_suffix += 1
            if common_suffix == 0 or common_suffix >= min(len(old_parts), len(new_parts)):
                continue
            old_dir = "/".join(old_parts[:-common_suffix])
            new_dir = "/".join(new_parts[:-common_suffix])
            if not old_dir or not new_dir:
                continue
            grouped.setdefault((old_dir, new_dir), []).append(old_path)
        results = []
        for (old_dir, new_dir), members in grouped.items():
            historical = [path for path in records if path == old_dir or path.startswith(old_dir + "/")]
            if len(members) >= 2 and set(members) == set(historical):
                results.append((old_dir, new_dir, sorted(members)))
        return results

    @staticmethod
    def _tree_manifest_hash_from_observations(files, root_relative: str, members) -> str:
        digest = hashlib.sha256()
        for path in sorted(members):
            suffix = path[len(root_relative):].lstrip("/")
            digest.update(f"{suffix}\0{files[path].content_hash}\0".encode())
        return digest.hexdigest()

    def _tree_manifest_hash(self, root: Path) -> str:
        files = scan_tree(root)
        digest = hashlib.sha256()
        for relative, observation in sorted(files.items()):
            digest.update(f"{relative}\0{observation.content_hash}\0".encode())
        return digest.hexdigest()

    def _move_tree_operation(self, side: str, old_dir: str, new_dir: str, manifest_hash: str) -> PlannedOperation:
        return PlannedOperation(
            OperationKind.MOVE_TREE, side, old_dir, side, new_dir, manifest_hash, None,
            move_source_relative=old_dir,
        )

    def _move_conflict_operations(self, old_path, left_new, right_new, left_files, right_files):
        conflict_id = hashlib.sha256(f"move\0{old_path}\0{left_new}\0{right_new}".encode()).hexdigest()[:16]
        base = f"{CONTROL_DIRECTORY}/conflicts/moves/{conflict_id}"
        return [
            PlannedOperation(OperationKind.PRESERVE_CONFLICT, "left", left_new, "left", f"{base}/left", left_files[left_new].content_hash, None),
            PlannedOperation(OperationKind.PRESERVE_CONFLICT, "right", right_new, "left", f"{base}/right", right_files[right_new].content_hash, None),
        ]

    def _move_edit_conflict_operations(self, old_path, new_path, moved_side, moved, other_side, other_old):
        identity = hashlib.sha256(f"move-edit\0{old_path}\0{new_path}\0{moved.content_hash}".encode()).hexdigest()[:16]
        base = f"{CONTROL_DIRECTORY}/conflicts/moves/{identity}"
        operations = [
            PlannedOperation(OperationKind.PRESERVE_CONFLICT, moved_side, new_path, "left", f"{base}/moved-{moved_side}", moved.content_hash, None)
        ]
        if other_old:
            operations.append(PlannedOperation(
                OperationKind.PRESERVE_CONFLICT, other_side, old_path, "left", f"{base}/edited-{other_side}", other_old.content_hash, None
            ))
        return operations

    def _operation_id(self, operation: PlannedOperation) -> str:
        identity = "\0".join(
            (operation.kind, operation.source_side, operation.source_relative,
             operation.destination_side, operation.destination_relative, operation.expected_hash,
             operation.destination_prior_hash or "", operation.backup_relative or "",
             operation.move_source_relative or "")
        )
        return hashlib.sha256(identity.encode()).hexdigest()[:24]

    def _execute(self, operation: PlannedOperation) -> bool:
        operation_id = self._operation_id(operation)
        destination = guarded_path(
            self.roots.get(operation.destination_side), operation.destination_relative, allow_control=True
        )
        if operation.kind not in {OperationKind.DELETE, OperationKind.MOVE, OperationKind.MOVE_TREE} and destination.exists() and sha256_file(destination) == operation.expected_hash:
            LOGGER.info("already-committed operation=%s", operation_id)
            return False
        if operation.kind not in {OperationKind.DELETE, OperationKind.MOVE, OperationKind.MOVE_TREE}:
            self._verify_destination_precondition(destination, operation.destination_prior_hash)

        journal = self._load_journal()
        existing = journal.get(operation_id)
        if existing and existing.status == OperationStatus.COMMITTED:
            if operation.kind == OperationKind.DELETE:
                backup = guarded_path(
                    self.roots.get(operation.destination_side), operation.backup_relative or "", allow_control=True
                )
                if not destination.exists() and backup.exists() and sha256_file(backup) == operation.expected_hash:
                    return False
            if operation.kind == OperationKind.MOVE_TREE:
                if destination.is_dir() and self._tree_manifest_hash(destination) == operation.expected_hash:
                    source = guarded_path(
                        self.roots.get(operation.source_side), operation.move_source_relative or operation.source_relative
                    )
                    if not source.exists():
                        return False
            if destination.exists() and sha256_file(destination) == operation.expected_hash:
                return False
            raise SafetyError(f"committed journal destination does not match: {destination}")

        if existing is None and operation.kind in {OperationKind.MOVE, OperationKind.MOVE_TREE}:
            self._verify_destination_precondition(destination, None)

        entry = existing or JournalOperation(
            operation_id=operation_id,
            kind=operation.kind,
            source_side=operation.source_side,
            source_relative=operation.source_relative,
            destination_side=operation.destination_side,
            destination_relative=operation.destination_relative,
            expected_hash=operation.expected_hash,
            destination_prior_hash=operation.destination_prior_hash,
            temp_name=f".safesync-tmp-{operation_id}",
            backup_relative=operation.backup_relative,
            move_source_relative=operation.move_source_relative,
        )
        journal[operation_id] = entry
        self._save_journal(journal)
        self._pause_for_external_kill("after_journal_prepared")
        self._finish_entry(entry, journal)
        return True

    def _finish_entry(self, entry: JournalOperation, journal: dict[str, JournalOperation]) -> None:
        if entry.kind == OperationKind.DELETE:
            self._finish_delete(entry, journal)
            return
        if entry.kind == OperationKind.MOVE:
            self._finish_move(entry, journal)
            return
        if entry.kind == OperationKind.MOVE_TREE:
            self._finish_move_tree(entry, journal)
            return
        source = guarded_path(
            self.roots.get(entry.source_side), entry.source_relative,
            allow_control=entry.kind == OperationKind.RESOLVE_COPY,
        )
        destination = guarded_path(
            self.roots.get(entry.destination_side), entry.destination_relative, allow_control=True
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.parent / entry.temp_name

        if entry.status == OperationStatus.PREPARED:
            self._verify_destination_precondition(destination, entry.destination_prior_hash)
            if not source.exists() or sha256_file(source) != entry.expected_hash:
                raise SafetyError(f"source changed while operation was pending: {source}")
            with source.open("rb") as source_stream, temp.open("wb") as temp_stream:
                while block := source_stream.read(1024 * 1024):
                    temp_stream.write(block)
                    self._pause_for_external_kill("during_temp_copy")
                temp_stream.flush()
                os.fsync(temp_stream.fileno())
            if sha256_file(temp) != entry.expected_hash:
                raise SafetyError(f"temporary copy verification failed: {temp}")
            if sha256_file(source) != entry.expected_hash:
                raise SafetyError(f"source changed while it was being copied: {source}")
            entry.status = OperationStatus.TEMP_WRITTEN
            self._save_journal(journal)
            self._pause_for_external_kill("after_temp_fsync")

        if entry.status == OperationStatus.TEMP_WRITTEN:
            if destination.exists() and sha256_file(destination) == entry.expected_hash:
                LOGGER.info("replacement already visible operation=%s", entry.operation_id)
                if temp.exists():
                    if sha256_file(temp) != entry.expected_hash:
                        raise SafetyError(f"pending temporary file is corrupt: {temp}")
                    temp.unlink()
            else:
                self._verify_destination_precondition(destination, entry.destination_prior_hash)
                if not temp.exists() or sha256_file(temp) != entry.expected_hash:
                    raise SafetyError(f"pending temporary file is missing or corrupt: {temp}")
                os.replace(temp, destination)
                self._pause_for_external_kill("after_atomic_replace")
            if sha256_file(destination) != entry.expected_hash:
                raise SafetyError(f"atomic replacement verification failed: {destination}")
            entry.status = OperationStatus.COMMITTED
            self._save_journal(journal)
            self._record_operation("operation_committed", entry)
            self._pause_for_external_kill("after_journal_commit")

    def _finish_delete(self, entry: JournalOperation, journal: dict[str, JournalOperation]) -> None:
        if entry.backup_relative is None:
            raise SafetyError(f"delete operation lacks backup path: {entry.operation_id}")
        root = self.roots.get(entry.destination_side)
        destination = guarded_path(root, entry.destination_relative)
        backup = guarded_path(root, entry.backup_relative, allow_control=True)
        backup.parent.mkdir(parents=True, exist_ok=True)
        temp = backup.parent / entry.temp_name

        if entry.status == OperationStatus.PREPARED:
            self._verify_destination_precondition(destination, entry.destination_prior_hash)
            with destination.open("rb") as source, temp.open("wb") as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
                target.flush()
                os.fsync(target.fileno())
            if sha256_file(temp) != entry.expected_hash or sha256_file(destination) != entry.expected_hash:
                raise SafetyError(f"delete backup verification failed: {destination}")
            os.replace(temp, backup)
            entry.status = OperationStatus.BACKUP_WRITTEN
            self._save_journal(journal)
            self._pause_for_external_kill("after_delete_backup")

        if entry.status == OperationStatus.BACKUP_WRITTEN:
            if not backup.exists() or sha256_file(backup) != entry.expected_hash:
                raise SafetyError(f"delete backup is missing or corrupt: {backup}")
            if destination.exists():
                if sha256_file(destination) != entry.expected_hash:
                    raise SafetyError(f"delete destination changed after backup: {destination}")
                destination.unlink()
                self._pause_for_external_kill("after_delete_unlink")
            entry.status = OperationStatus.COMMITTED
            self._save_journal(journal)
            self._record_operation("operation_committed", entry)
            self._pause_for_external_kill("after_journal_commit")

    def _finish_move(self, entry: JournalOperation, journal: dict[str, JournalOperation]) -> None:
        root = self.roots.get(entry.destination_side)
        source = guarded_path(root, entry.move_source_relative or entry.source_relative)
        destination = guarded_path(root, entry.destination_relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if entry.status == OperationStatus.PREPARED:
            self._verify_destination_precondition(destination, None)
            if not source.exists() or sha256_file(source) != entry.expected_hash:
                raise SafetyError(f"move source changed or disappeared: {source}")
            try:
                os.link(source, destination)
            except OSError:
                temp = destination.parent / entry.temp_name
                with source.open("rb") as input_stream, temp.open("wb") as output_stream:
                    while block := input_stream.read(1024 * 1024):
                        output_stream.write(block)
                    output_stream.flush()
                    os.fsync(output_stream.fileno())
                if sha256_file(temp) != entry.expected_hash:
                    raise SafetyError(f"move destination temp verification failed: {temp}")
                os.replace(temp, destination)
            if sha256_file(destination) != entry.expected_hash or sha256_file(source) != entry.expected_hash:
                raise SafetyError(f"move destination verification failed: {destination}")
            entry.status = OperationStatus.DESTINATION_READY
            self._save_journal(journal)
            self._pause_for_external_kill("after_move_destination")
        if entry.status == OperationStatus.DESTINATION_READY:
            if not destination.exists() or sha256_file(destination) != entry.expected_hash:
                raise SafetyError(f"verified move destination is missing or changed: {destination}")
            if source.exists():
                if sha256_file(source) != entry.expected_hash:
                    raise SafetyError(f"move source changed before unlink: {source}")
                source.unlink()
                self._pause_for_external_kill("after_move_unlink")
            entry.status = OperationStatus.COMMITTED
            self._save_journal(journal)
            self._record_operation("operation_committed", entry)
            self._pause_for_external_kill("after_journal_commit")

    def _finish_move_tree(self, entry: JournalOperation, journal: dict[str, JournalOperation]) -> None:
        root = self.roots.get(entry.destination_side)
        source = guarded_path(root, entry.move_source_relative or entry.source_relative)
        destination = guarded_path(root, entry.destination_relative)
        if entry.status == OperationStatus.PREPARED:
            if not source.is_dir() or self._tree_manifest_hash(source) != entry.expected_hash:
                raise SafetyError(f"move-tree source changed or disappeared: {source}")
            destination.mkdir(parents=True, exist_ok=True)
            for path in sorted(source.rglob("*")):
                relative = path.relative_to(source)
                target = destination / relative
                if path.is_dir():
                    target.mkdir(exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if sha256_file(target) != sha256_file(path):
                        raise SafetyError(f"partial move-tree destination conflicts: {target}")
                else:
                    os.link(path, target)
                self._pause_for_external_kill("during_move_tree")
            if self._tree_manifest_hash(destination) != entry.expected_hash:
                raise SafetyError(f"move-tree destination verification failed: {destination}")
            entry.status = OperationStatus.DESTINATION_READY
            self._save_journal(journal)
            self._pause_for_external_kill("after_move_destination")
        if entry.status == OperationStatus.DESTINATION_READY:
            if not destination.is_dir() or self._tree_manifest_hash(destination) != entry.expected_hash:
                raise SafetyError(f"verified move-tree destination changed: {destination}")
            if source.exists():
                if self._tree_manifest_hash(source) != entry.expected_hash:
                    raise SafetyError(f"move-tree source changed before removal: {source}")
                for path in sorted(source.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                    path.unlink() if path.is_file() else path.rmdir()
                source.rmdir()
                self._pause_for_external_kill("after_move_unlink")
            entry.status = OperationStatus.COMMITTED
            self._save_journal(journal)
            self._record_operation("operation_committed", entry)
            self._pause_for_external_kill("after_journal_commit")

    def _recover_journal(self) -> int:
        journal = self._load_journal()
        recovered = 0
        for entry in sorted(journal.values(), key=lambda item: item.operation_id):
            if entry.status == OperationStatus.COMMITTED:
                continue
            LOGGER.info("recover operation=%s status=%s", entry.operation_id, entry.status)
            self._finish_entry(entry, journal)
            recovered += 1
        return recovered

    def _prepare_and_finish_batch(self, operations: list[PlannedOperation]) -> None:
        journal = self._load_journal()
        added = False
        entries: list[JournalOperation] = []
        for operation in operations:
            operation_id = self._operation_id(operation)
            entry = journal.get(operation_id)
            if entry is None:
                destination = guarded_path(
                    self.roots.get(operation.destination_side), operation.destination_relative,
                    allow_control=True,
                )
                self._verify_destination_precondition(destination, operation.destination_prior_hash)
                entry = JournalOperation(
                    operation_id=operation_id,
                    kind=operation.kind,
                    source_side=operation.source_side,
                    source_relative=operation.source_relative,
                    destination_side=operation.destination_side,
                    destination_relative=operation.destination_relative,
                    expected_hash=operation.expected_hash,
                    destination_prior_hash=operation.destination_prior_hash,
                    temp_name=f".safesync-tmp-{operation_id}",
                    backup_relative=operation.backup_relative,
                    move_source_relative=operation.move_source_relative,
                )
                journal[operation_id] = entry
                added = True
            entries.append(entry)
        if added:
            self._save_journal(journal)
            self._pause_for_external_kill("after_resolution_journal_prepared")
        for entry in entries:
            if entry.status != OperationStatus.COMMITTED:
                self._finish_entry(entry, journal)
                self._pause_for_external_kill("after_resolution_operation")

    def _recover_resolutions_locked(self) -> int:
        transactions = self._load_resolutions()
        recovered = 0
        for transaction in transactions.values():
            if transaction["status"] == "committed":
                continue
            operations = [PlannedOperation(**value) for value in transaction["operations"]]
            self._prepare_and_finish_batch(operations)
            self._finalize_resolution(transaction, transactions)
            recovered += 1
        return recovered

    def _finalize_resolution(self, transaction, transactions) -> None:
        observations = {"left": scan_tree(self.roots.left), "right": scan_tree(self.roots.right)}
        for side in ("left", "right"):
            for relative, expected_hash in transaction["expected"][side].items():
                current = observations[side].get(relative)
                current_hash = current.content_hash if current else None
                if current_hash != expected_hash:
                    raise SafetyError(
                        f"resolution destination changed before state commit: {side}:{relative}"
                    )
        records = self._load_state()
        for relative in transaction["affected_paths"]:
            left = observations["left"].get(relative)
            right = observations["right"].get(relative)
            if left is None and right is None:
                records[relative] = SyncRecord(None, None, tombstone=True)
            else:
                records[relative] = SyncRecord(
                    left.content_hash if left else None,
                    right.content_hash if right else None,
                    left.identity if left else None,
                    right.identity if right else None,
                )
        self._save_state(records)
        self._pause_for_external_kill("after_resolution_state_commit")
        transaction["status"] = "committed"
        transactions[transaction["transaction_id"]] = transaction
        self._save_resolutions(transactions)
        self._record_event("resolution_committed", {
            "transaction_id": transaction["transaction_id"],
            "conflict_id": transaction["conflict_id"],
            "choice": transaction["choice"],
        })
        self._pause_for_external_kill("after_resolution_commit")
        self._compact_journal()

    def _load_state(self) -> dict[str, SyncRecord]:
        payload = load_json(self.state_path, {"version": STATE_VERSION, "files": {}})
        if payload.get("version") != STATE_VERSION:
            raise SafetyError("unsupported state file version")
        files = payload.get("files")
        if set(payload) != {"version", "files"} or not isinstance(files, dict):
            raise SafetyError("invalid state schema")
        try:
            records = {path: SyncRecord(**record) for path, record in files.items()}
        except (TypeError, AttributeError) as exc:
            raise SafetyError("invalid state record") from exc
        for path, record in records.items():
            guarded_path(self.roots.left, path)
            for value in (record.left_hash, record.right_hash):
                if value is not None and (not isinstance(value, str) or not self._valid_hash(value)):
                    raise SafetyError(f"invalid state hash for {path}")
        return records

    def _save_state(self, records: dict[str, SyncRecord]) -> None:
        atomic_write_json(self.state_path, {
            "version": STATE_VERSION,
            "files": {path: asdict(record) for path, record in records.items()},
        })

    def _load_journal(self) -> dict[str, JournalOperation]:
        payload = load_json(self.journal_path, {"version": STATE_VERSION, "operations": {}})
        if payload.get("version") != STATE_VERSION:
            raise SafetyError("unsupported journal version")
        operations = payload.get("operations")
        if set(payload) != {"version", "operations"} or not isinstance(operations, dict):
            raise SafetyError("invalid journal schema")
        try:
            journal = {
                operation_id: JournalOperation.from_dict(value)
                for operation_id, value in operations.items()
            }
        except (TypeError, AttributeError) as exc:
            raise SafetyError("invalid journal operation") from exc
        valid_statuses = {status.value for status in OperationStatus}
        valid_kinds = {kind.value for kind in OperationKind}
        for operation_id, entry in journal.items():
            if operation_id != entry.operation_id or entry.status not in valid_statuses or entry.kind not in valid_kinds:
                raise SafetyError(f"invalid journal operation: {operation_id}")
            hashes = (entry.expected_hash, entry.destination_prior_hash)
            if any(value is not None and not self._valid_hash(value) for value in hashes):
                raise SafetyError(f"invalid journal hash: {operation_id}")
            if entry.temp_name != f".safesync-tmp-{operation_id}":
                raise SafetyError(f"invalid journal operation identity: {operation_id}")
            guarded_path(
                self.roots.get(entry.source_side), entry.source_relative,
                allow_control=entry.kind == OperationKind.RESOLVE_COPY,
            )
            guarded_path(self.roots.get(entry.destination_side), entry.destination_relative, allow_control=True)
            planned = PlannedOperation(
                OperationKind(entry.kind), entry.source_side, entry.source_relative,
                entry.destination_side, entry.destination_relative, entry.expected_hash, entry.destination_prior_hash,
                entry.backup_relative, entry.move_source_relative,
            )
            if self._operation_id(planned) != operation_id:
                raise SafetyError(f"journal operation ID does not match its contents: {operation_id}")
        return journal

    def _save_journal(self, journal: dict[str, JournalOperation]) -> None:
        atomic_write_json(self.journal_path, {
            "version": STATE_VERSION,
            "operations": {key: value.to_dict() for key, value in sorted(journal.items())},
        })

    def _load_intents(self) -> dict[str, DeletionIntent]:
        payload = load_json(self.intents_path, {"version": STATE_VERSION, "intents": {}})
        values = payload.get("intents")
        if payload.get("version") != STATE_VERSION or set(payload) != {"version", "intents"} or not isinstance(values, dict):
            raise SafetyError("invalid deletion-intent schema")
        try:
            intents = {key: DeletionIntent.from_dict(value) for key, value in values.items()}
        except (TypeError, AttributeError) as exc:
            raise SafetyError("invalid deletion intent") from exc
        for key, intent in intents.items():
            if key != intent.intent_id or intent.side not in {"left", "right"} or not self._valid_hash(intent.expected_hash):
                raise SafetyError(f"invalid deletion intent: {key}")
            guarded_path(self.roots.get(intent.side), intent.relative_path)
        return intents

    def _save_intents(self, intents: dict[str, DeletionIntent]) -> None:
        atomic_write_json(self.intents_path, {
            "version": STATE_VERSION,
            "intents": {key: value.to_dict() for key, value in sorted(intents.items())},
        })

    def _load_resolutions(self) -> dict[str, dict]:
        payload = load_json(self.resolutions_path, {"version": STATE_VERSION, "transactions": {}})
        transactions = payload.get("transactions")
        if (
            payload.get("version") != STATE_VERSION
            or set(payload) != {"version", "transactions"}
            or not isinstance(transactions, dict)
        ):
            raise SafetyError("invalid resolution-transaction schema")
        required = {
            "transaction_id", "conflict_id", "choice", "status", "operations",
            "expected", "affected_paths",
        }
        for key, transaction in transactions.items():
            if not isinstance(transaction, dict) or set(transaction) != required:
                raise SafetyError(f"invalid resolution transaction: {key}")
            if (
                key != transaction["transaction_id"]
                or transaction["status"] not in {"prepared", "committed"}
                or transaction["choice"] not in {"left", "right", "keep_both"}
                or not isinstance(transaction["operations"], list)
                or not isinstance(transaction["affected_paths"], list)
                or set(transaction["expected"] if isinstance(transaction["expected"], dict) else ())
                != {"left", "right"}
            ):
                raise SafetyError(f"invalid resolution transaction: {key}")
            try:
                operations = [PlannedOperation(**value) for value in transaction["operations"]]
            except (TypeError, AttributeError) as exc:
                raise SafetyError(f"invalid resolution operations: {key}") from exc
            expected_id = hashlib.sha256(
                (f"resolve\0{transaction['conflict_id']}\0{transaction['choice']}\0" + "\0".join(
                    self._operation_id(operation) for operation in operations
                )).encode()
            ).hexdigest()[:24]
            if expected_id != key:
                raise SafetyError(f"resolution transaction ID does not match contents: {key}")
            affected = set(transaction["affected_paths"])
            if not affected:
                raise SafetyError(f"resolution transaction has no affected paths: {key}")
            for relative in affected:
                guarded_path(self.roots.left, relative)
            for side in ("left", "right"):
                values = transaction["expected"][side]
                if not isinstance(values, dict) or set(values) != affected:
                    raise SafetyError(f"resolution expected-path set is invalid: {key}")
                for relative, content_hash in values.items():
                    if content_hash is not None and not self._valid_hash(content_hash):
                        raise SafetyError(f"resolution expected hash is invalid: {key}:{relative}")
        return transactions

    def _save_resolutions(self, transactions: dict[str, dict]) -> None:
        atomic_write_json(self.resolutions_path, {
            "version": STATE_VERSION,
            "transactions": {key: value for key, value in sorted(transactions.items())},
        })

    def _record_operation(self, event: str, entry: JournalOperation) -> None:
        self._record_event(event, {
            "operation_id": entry.operation_id,
            "kind": str(entry.kind),
            "source": f"{entry.source_side}:{entry.source_relative}",
            "destination": f"{entry.destination_side}:{entry.destination_relative}",
            "expected_hash": entry.expected_hash,
        })

    def _record_event(self, event: str, details: dict) -> None:
        payload = load_json(self.operations_path, {"version": STATE_VERSION, "events": []})
        events = payload.get("events")
        if payload.get("version") != STATE_VERSION or set(payload) != {"version", "events"} or not isinstance(events, list):
            raise SafetyError("invalid operation-log schema")
        events.append({"timestamp_ns": time.time_ns(), "event": event, **details})
        atomic_write_json(self.operations_path, {"version": STATE_VERSION, "events": events[-1000:]})

    def operation_events(self) -> tuple[dict, ...]:
        with exclusive_lock(self.lock_path):
            self._verify_config()
            payload = load_json(self.operations_path, {"version": STATE_VERSION, "events": []})
            events = payload.get("events")
            if payload.get("version") != STATE_VERSION or set(payload) != {"version", "events"} or not isinstance(events, list):
                raise SafetyError("invalid operation-log schema")
            return tuple(events)

    def dashboard_snapshot(self) -> dict:
        # Metadata files are atomically replaced. A read-only live view must not
        # wait behind the writer lock or it could never display mid-operation state.
        with nullcontext():
            self._verify_config()
            left_files = scan_tree(self.roots.left)
            right_files = scan_tree(self.roots.right)
            records = self._load_state()
            journal = self._load_journal()
            conflicts = self._list_conflicts_locked()
            conflict_paths = {
                path
                for conflict in conflicts
                for path in (
                    [conflict.display_path]
                    if conflict.kind != "move"
                    else [version.preferred_path for version in conflict.versions if version.preferred_path]
                )
            }
            pending_paths = {
                relative
                for entry in journal.values()
                if entry.status != OperationStatus.COMMITTED
                for relative in (entry.source_relative, entry.destination_relative, entry.move_source_relative)
                if relative and not relative.startswith(CONTROL_DIRECTORY + "/")
            }
            files = []
            for relative in sorted(set(left_files) | set(right_files) | set(records)):
                left = left_files.get(relative)
                right = right_files.get(relative)
                record = records.get(relative)
                if relative in pending_paths:
                    status = "mid_operation"
                elif relative in conflict_paths or (
                    record and (record.move_conflict or record.left_deleted or record.right_deleted)
                ):
                    status = "conflict"
                elif left and right and left.content_hash == right.content_hash:
                    status = "in_sync"
                elif left and right:
                    status = "different"
                elif left:
                    status = "left_only"
                elif right:
                    status = "right_only"
                else:
                    status = "deleted"

                def view(observation):
                    if observation is None:
                        return None
                    return {
                        "sha256": observation.content_hash,
                        "size": observation.size,
                        "modified_ns": observation.modified_ns,
                        "identity": observation.identity,
                    }

                files.append({"path": relative, "status": status, "left": view(left), "right": view(right)})
            operations_payload = load_json(
                self.operations_path, {"version": STATE_VERSION, "events": []}
            )
            return {
                "roots": {"left": str(self.roots.left), "right": str(self.roots.right)},
                "files": files,
                "conflicts": [asdict(conflict) for conflict in conflicts],
                "journal": {
                    "version": STATE_VERSION,
                    "operations": {key: value.to_dict() for key, value in sorted(journal.items())},
                },
                "state": {
                    "version": STATE_VERSION,
                    "files": {key: asdict(value) for key, value in sorted(records.items())},
                },
                "operation_log": operations_payload.get("events", [])[-200:],
                "temporary_files": [
                    f"{side}:{path.relative_to(root).as_posix()}"
                    for side, root in (("left", self.roots.left), ("right", self.roots.right))
                    for path in sorted(root.rglob(".safesync-tmp-*"))
                    if path.is_file()
                ],
            }

    def _compact_journal(self) -> None:
        journal = self._load_journal()
        pending = {key: entry for key, entry in journal.items() if entry.status != OperationStatus.COMMITTED}
        if len(pending) != len(journal):
            self._save_journal(pending)

    def _config_payload(self) -> dict[str, object]:
        return {
            "version": STATE_VERSION,
            "left": str(self.roots.left),
            "right": str(self.roots.right),
        }

    def _verify_config(self) -> None:
        payload = load_json(self.config_path, {})
        if payload != self._config_payload():
            raise SafetyError("selected roots do not match the initialized root pair")

    @staticmethod
    def _valid_hash(value: str) -> bool:
        return len(value) == 64 and all(character in "0123456789abcdef" for character in value)

    @staticmethod
    def _verify_destination_precondition(destination: Path, prior_hash: str | None) -> None:
        if prior_hash is None:
            if destination.exists():
                raise SafetyError(f"destination appeared after planning: {destination}")
            return
        if not destination.exists() or sha256_file(destination) != prior_hash:
            raise SafetyError(f"destination changed after planning: {destination}")

    @staticmethod
    def _pause_for_external_kill(point: str) -> None:
        if os.environ.get("SAFESYNC_PAUSE_POINT") != point:
            return
        os.environ.pop("SAFESYNC_PAUSE_POINT", None)
        port = int(os.environ["SAFESYNC_PAUSE_PORT"])
        message = f"{os.getpid()} {point}\n".encode("ascii")
        with socket.create_connection(("127.0.0.1", port), timeout=10) as signal:
            signal.sendall(message)
            if os.environ.get("SAFESYNC_RESUME_AFTER_SIGNAL") == "1":
                signal.settimeout(None)
                if signal.recv(1) != b"1":
                    raise SafetyError("test checkpoint was not resumed")
                return
        while True:
            time.sleep(60)
