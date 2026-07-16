from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from .model import FileObservation

CONTROL_DIRECTORY = ".safesync"


class SafetyError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_roots(left: Path, right: Path) -> tuple[Path, Path]:
    roots = []
    for candidate in (left, right):
        if not candidate.exists() or not candidate.is_dir():
            raise SafetyError(f"selected root is not a directory: {candidate}")
        if candidate.is_symlink():
            raise SafetyError(f"selected root may not be a symlink: {candidate}")
        roots.append(candidate.resolve(strict=True))
    left_root, right_root = roots
    if left_root == right_root or left_root in right_root.parents or right_root in left_root.parents:
        raise SafetyError("selected roots must be distinct and non-overlapping")
    return left_root, right_root


def guarded_path(root: Path, relative: str, *, allow_control: bool = False) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise SafetyError(f"unsafe relative path: {relative!r}")
    if not allow_control and pure.parts[0] == CONTROL_DIRECTORY:
        raise SafetyError("tool control paths are not user file paths")

    current = root
    for part in pure.parts[:-1]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise SafetyError(f"symlink traversal refused: {current}")
    candidate = current / pure.parts[-1]
    if candidate.exists() and candidate.is_symlink():
        raise SafetyError(f"symlink target refused: {candidate}")
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise SafetyError(f"path escapes selected root: {relative}") from exc
    return candidate


def scan_tree(root: Path) -> dict[str, FileObservation]:
    observations: dict[str, FileObservation] = {}
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        names[:] = sorted(name for name in names if name != CONTROL_DIRECTORY)
        for name in list(names):
            path = directory_path / name
            if path.is_symlink():
                raise SafetyError(f"symbolic links are unsupported: {path}")
        for name in sorted(filenames):
            path = directory_path / name
            file_stat = path.lstat()
            if stat.S_ISLNK(file_stat.st_mode):
                raise SafetyError(f"symbolic links are unsupported: {path}")
            if not stat.S_ISREG(file_stat.st_mode):
                raise SafetyError(f"non-regular files are unsupported: {path}")
            relative = path.relative_to(root).as_posix()
            observations[relative] = FileObservation(
                relative_path=relative,
                content_hash=sha256_file(path),
                size=file_stat.st_size,
                modified_ns=file_stat.st_mtime_ns,
            )
    return observations


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    with temp.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)

