from __future__ import annotations

import hashlib
import logging
import os
import socket
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from .filesystem import (
    CONTROL_DIRECTORY,
    SafetyError,
    atomic_write_json,
    guarded_path,
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
STATE_VERSION = 1
CRASH_POINTS = (
    "after_journal_prepared",
    "after_temp_fsync",
    "after_atomic_replace",
    "after_journal_commit",
)


@dataclass(frozen=True)
class SyncResult:
    planned: int
    committed: int
    conflicts: int
    skipped: int
    changed: bool


class SyncEngine:
    def __init__(self, left: Path, right: Path, *, dry_run: bool = False) -> None:
        left_root, right_root = validate_roots(left, right)
        self.roots = Roots(left_root, right_root)
        self.dry_run = dry_run
        self.control = left_root / CONTROL_DIRECTORY
        self.state_path = self.control / "state.json"
        self.journal_path = self.control / "journal.json"

    def sync(self) -> SyncResult:
        recovered = 0 if self.dry_run else self._recover_journal()
        left_files = scan_tree(self.roots.left)
        right_files = scan_tree(self.roots.right)
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
                operations.append(self._copy("right", "left", relative, right.content_hash))
            elif right is None and left is not None:
                operations.append(self._copy("left", "right", relative, left.content_hash))
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
                    operations.append(self._copy("left", "right", relative, left.content_hash))
                elif right_changed and not left_changed:
                    operations.append(self._copy("right", "left", relative, right.content_hash))
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

        return SyncResult(
            planned=len(operations),
            committed=0 if self.dry_run else committed,
            conflicts=conflicts,
            skipped=skipped,
            changed=bool(operations or recovered),
        )

    def _copy(self, source: str, destination: str, relative: str, content_hash: str) -> PlannedOperation:
        return PlannedOperation(OperationKind.COPY, source, relative, destination, relative, content_hash)

    def _conflict_operations(self, relative: str, left_hash: str, right_hash: str) -> list[PlannedOperation]:
        conflict_id = hashlib.sha256(f"{relative}\0{left_hash}\0{right_hash}".encode()).hexdigest()[:16]
        safe_path = "/".join(PurePosixPath(relative).parts)
        base = f"{CONTROL_DIRECTORY}/conflicts/{safe_path}/{conflict_id}"
        return [
            PlannedOperation(OperationKind.PRESERVE_CONFLICT, "left", relative, "left", f"{base}/left", left_hash),
            PlannedOperation(OperationKind.PRESERVE_CONFLICT, "right", relative, "left", f"{base}/right", right_hash),
        ]

    def _operation_id(self, operation: PlannedOperation) -> str:
        identity = "\0".join(
            (operation.kind, operation.source_side, operation.source_relative,
             operation.destination_side, operation.destination_relative, operation.expected_hash)
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
            if not source.exists() or sha256_file(source) != entry.expected_hash:
                raise SafetyError(f"source changed while operation was pending: {source}")
            with source.open("rb") as source_stream, temp.open("wb") as temp_stream:
                shutil.copyfileobj(source_stream, temp_stream, length=1024 * 1024)
                temp_stream.flush()
                os.fsync(temp_stream.fileno())
            if sha256_file(temp) != entry.expected_hash:
                raise SafetyError(f"temporary copy verification failed: {temp}")
            entry.status = OperationStatus.TEMP_WRITTEN
            self._save_journal(journal)
            self._pause_for_external_kill("after_temp_fsync")

        if entry.status == OperationStatus.TEMP_WRITTEN:
            if destination.exists() and sha256_file(destination) == entry.expected_hash:
                LOGGER.info("replacement already visible operation=%s", entry.operation_id)
            else:
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
        return {path: SyncRecord(**record) for path, record in payload.get("files", {}).items()}

    def _save_state(self, records: dict[str, SyncRecord]) -> None:
        atomic_write_json(self.state_path, {
            "version": STATE_VERSION,
            "files": {path: asdict(record) for path, record in records.items()},
        })

    def _load_journal(self) -> dict[str, JournalOperation]:
        payload = load_json(self.journal_path, {"version": STATE_VERSION, "operations": {}})
        if payload.get("version") != STATE_VERSION:
            raise SafetyError("unsupported journal version")
        return {
            operation_id: JournalOperation.from_dict(value)
            for operation_id, value in payload.get("operations", {}).items()
        }

    def _save_journal(self, journal: dict[str, JournalOperation]) -> None:
        atomic_write_json(self.journal_path, {
            "version": STATE_VERSION,
            "operations": {key: value.to_dict() for key, value in sorted(journal.items())},
        })

    @staticmethod
    def _pause_for_external_kill(point: str) -> None:
        if os.environ.get("SAFESYNC_PAUSE_POINT") != point:
            return
        port = int(os.environ["SAFESYNC_PAUSE_PORT"])
        message = f"{os.getpid()} {point}\n".encode("ascii")
        with socket.create_connection(("127.0.0.1", port), timeout=10) as signal:
            signal.sendall(message)
        while True:
            time.sleep(60)
