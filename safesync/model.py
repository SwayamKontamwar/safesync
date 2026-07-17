from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class OperationKind(StrEnum):
    COPY = "copy"
    PRESERVE_CONFLICT = "preserve_conflict"
    DELETE = "delete"
    MOVE = "move"
    MOVE_TREE = "move_tree"


class OperationStatus(StrEnum):
    PREPARED = "prepared"
    TEMP_WRITTEN = "temp_written"
    BACKUP_WRITTEN = "backup_written"
    DESTINATION_READY = "destination_ready"
    COMMITTED = "committed"


@dataclass(frozen=True)
class FileObservation:
    relative_path: str
    content_hash: str
    size: int
    modified_ns: int
    identity: str


@dataclass(frozen=True)
class SyncRecord:
    left_hash: str | None
    right_hash: str | None
    left_identity: str | None = None
    right_identity: str | None = None
    tombstone: bool = False
    left_deleted: bool = False
    right_deleted: bool = False
    move_conflict: bool = False


@dataclass
class JournalOperation:
    operation_id: str
    kind: str
    source_side: str
    source_relative: str
    destination_side: str
    destination_relative: str
    expected_hash: str
    destination_prior_hash: str | None
    temp_name: str
    backup_relative: str | None = None
    move_source_relative: str | None = None
    status: str = OperationStatus.PREPARED

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "JournalOperation":
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PlannedOperation:
    kind: OperationKind
    source_side: str
    source_relative: str
    destination_side: str
    destination_relative: str
    expected_hash: str
    destination_prior_hash: str | None
    backup_relative: str | None = None
    move_source_relative: str | None = None


@dataclass(frozen=True)
class DeletionIntent:
    intent_id: str
    side: str
    relative_path: str
    expected_hash: str
    evidence: str
    observed_at_ns: int

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DeletionIntent":
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Roots:
    left: Path
    right: Path

    def get(self, side: str) -> Path:
        if side == "left":
            return self.left
        if side == "right":
            return self.right
        raise ValueError(f"invalid side: {side}")
