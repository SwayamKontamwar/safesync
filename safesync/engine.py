from __future__ import annotations

import hashlib
import logging
import os
import socket
import time
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
    JournalOperation,
    OperationKind,
    OperationStatus,
    PlannedOperation,
    Roots,
    SyncRecord,
)

LOGGER = logging.getLogger("safesync")
STATE_VERSION = 2
CRASH_POINTS = (
    "after_journal_prepared",
    "during_temp_copy",
    "after_temp_fsync",
    "after_atomic_replace",
    "after_journal_commit",
    "after_state_commit",
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
        self.lock_path = self.control / "lock"

    def initialize(self) -> bool:
        with exclusive_lock(self.lock_path):
            if self.config_path.exists():
                self._verify_config()
                if not self.state_path.exists():
                    atomic_write_json(self.state_path, {"version": STATE_VERSION, "files": {}})
                if not self.journal_path.exists():
                    atomic_write_json(self.journal_path, {"version": STATE_VERSION, "operations": {}})
                return False
            if self.state_path.exists() or self.journal_path.exists():
                raise SafetyError("state or journal exists without root-pair configuration")
            atomic_write_json(self.config_path, self._config_payload())
            atomic_write_json(self.state_path, {"version": STATE_VERSION, "files": {}})
            atomic_write_json(self.journal_path, {"version": STATE_VERSION, "operations": {}})
            return True

    def inspect(self) -> Inspection:
        initialized = self.config_path.exists()
        if initialized:
            self._verify_config()
        elif self.state_path.exists() or self.journal_path.exists():
            raise SafetyError("state or journal exists without root-pair configuration")
        records = self._load_state() if self.state_path.exists() else {}
        journal = self._load_journal() if self.journal_path.exists() else {}
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
        )

    def recover(self) -> SyncResult:
        return self.sync()

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
        operations: list[PlannedOperation] = []
        committed = recovered
        conflicts = 0
        skipped = 0
        preserve_previous_state: set[str] = set()

        for relative in sorted(set(left_files) | set(right_files) | set(records)):
            left = left_files.get(relative)
            right = right_files.get(relative)
            previous = records.get(relative)

            if previous and ((left is None and previous.left_hash) or (right is None and previous.right_hash)):
                LOGGER.warning("skip ambiguous deletion path=%s", relative)
                skipped += 1
                preserve_previous_state.add(relative)
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
            next_records = {
                relative: SyncRecord(
                    final_left[relative].content_hash if relative in final_left else None,
                    final_right[relative].content_hash if relative in final_right else None,
                )
                for relative in sorted(set(final_left) | set(final_right))
            }
            for relative in preserve_previous_state:
                next_records[relative] = records[relative]
            self._save_state(next_records)
            self._pause_for_external_kill("after_state_commit")
            self._compact_journal()

        return SyncResult(
            planned=len(operations),
            committed=0 if self.dry_run else committed,
            conflicts=conflicts,
            skipped=skipped,
            changed=bool(operations or recovered),
        )

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

    def _operation_id(self, operation: PlannedOperation) -> str:
        identity = "\0".join(
            (operation.kind, operation.source_side, operation.source_relative,
             operation.destination_side, operation.destination_relative, operation.expected_hash,
             operation.destination_prior_hash or "")
        )
        return hashlib.sha256(identity.encode()).hexdigest()[:24]

    def _execute(self, operation: PlannedOperation) -> bool:
        operation_id = self._operation_id(operation)
        destination = guarded_path(
            self.roots.get(operation.destination_side), operation.destination_relative, allow_control=True
        )
        if destination.exists() and sha256_file(destination) == operation.expected_hash:
            LOGGER.info("already-committed operation=%s", operation_id)
            return False
        self._verify_destination_precondition(destination, operation.destination_prior_hash)

        journal = self._load_journal()
        existing = journal.get(operation_id)
        if existing and existing.status == OperationStatus.COMMITTED:
            if destination.exists() and sha256_file(destination) == operation.expected_hash:
                return False
            raise SafetyError(f"committed journal destination does not match: {destination}")

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
        )
        journal[operation_id] = entry
        self._save_journal(journal)
        self._pause_for_external_kill("after_journal_prepared")
        self._finish_entry(entry, journal)
        return True

    def _finish_entry(self, entry: JournalOperation, journal: dict[str, JournalOperation]) -> None:
        source = guarded_path(self.roots.get(entry.source_side), entry.source_relative)
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
            guarded_path(self.roots.get(entry.source_side), entry.source_relative)
            guarded_path(self.roots.get(entry.destination_side), entry.destination_relative, allow_control=True)
            planned = PlannedOperation(
                OperationKind(entry.kind), entry.source_side, entry.source_relative,
                entry.destination_side, entry.destination_relative, entry.expected_hash, entry.destination_prior_hash,
            )
            if self._operation_id(planned) != operation_id:
                raise SafetyError(f"journal operation ID does not match its contents: {operation_id}")
        return journal

    def _save_journal(self, journal: dict[str, JournalOperation]) -> None:
        atomic_write_json(self.journal_path, {
            "version": STATE_VERSION,
            "operations": {key: value.to_dict() for key, value in sorted(journal.items())},
        })

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
