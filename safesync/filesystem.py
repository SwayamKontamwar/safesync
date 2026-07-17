from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .model import FileObservation

CONTROL_DIRECTORY = ".safesync"


class SafetyError(RuntimeError):
    pass


WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL", *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    if hasattr(os.path, "isjunction") and os.path.isjunction(path):
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, FileNotFoundError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def validate_windows_component(component: str) -> None:
    if component.endswith((" ", ".")) or ":" in component:
        raise SafetyError(f"unsupported Windows path component: {component!r}")
    stem = component.split(".", 1)[0].upper()
    if stem in WINDOWS_RESERVED_NAMES:
        raise SafetyError(f"reserved Windows path component: {component!r}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_file_observation(path: Path, relative: str) -> FileObservation:
    before = path.stat()
    content_hash = sha256_file(path)
    after = path.stat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise SafetyError(f"file changed while being observed: {path}")
    identity = f"{after.st_dev:x}:{after.st_ino:x}"
    return FileObservation(relative, content_hash, after.st_size, after.st_mtime_ns, identity)


def validate_roots(left: Path, right: Path) -> tuple[Path, Path]:
    roots = []
    for candidate in (left, right):
        if not candidate.exists() or not candidate.is_dir():
            raise SafetyError(f"selected root is not a directory: {candidate}")
        if is_reparse_point(candidate):
            raise SafetyError(f"selected root may not be a reparse point: {candidate}")
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
    for part in pure.parts:
        validate_windows_component(part)

    current = root
    for part in pure.parts[:-1]:
        current = current / part
        if current.exists() and is_reparse_point(current):
            raise SafetyError(f"reparse-point traversal refused: {current}")
    candidate = current / pure.parts[-1]
    if candidate.exists() and is_reparse_point(candidate):
        raise SafetyError(f"reparse-point target refused: {candidate}")
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise SafetyError(f"path escapes selected root: {relative}") from exc
    return candidate


def scan_tree(root: Path) -> dict[str, FileObservation]:
    observations: dict[str, FileObservation] = {}
    casefolded: dict[str, str] = {}
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        names[:] = sorted(name for name in names if name != CONTROL_DIRECTORY)
        for name in list(names):
            path = directory_path / name
            if is_reparse_point(path):
                raise SafetyError(f"reparse points are unsupported: {path}")
        for name in sorted(filenames):
            path = directory_path / name
            file_stat = path.lstat()
            if stat.S_ISLNK(file_stat.st_mode):
                raise SafetyError(f"symbolic links are unsupported: {path}")
            if not stat.S_ISREG(file_stat.st_mode):
                raise SafetyError(f"non-regular files are unsupported: {path}")
            relative = path.relative_to(root).as_posix()
            for part in PurePosixPath(relative).parts:
                validate_windows_component(part)
            folded = relative.casefold()
            if folded in casefolded and casefolded[folded] != relative:
                raise SafetyError(f"case-insensitive path collision: {casefolded[folded]!r} and {relative!r}")
            casefolded[folded] = relative
            observations[relative] = stable_file_observation(path, relative)
    return observations


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    if is_reparse_point(path.parent) or (temp.exists() and is_reparse_point(temp)):
        raise SafetyError(f"metadata path contains a reparse point: {path}")
    data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    with temp.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SafetyError(f"invalid metadata file: {path}") from exc
    if not isinstance(value, dict):
        raise SafetyError(f"metadata root must be an object: {path}")
    return value


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if is_reparse_point(path.parent) or (path.exists() and is_reparse_point(path)):
        raise SafetyError(f"lock path contains a reparse point: {path}")
    stream = path.open("a+b")
    locked = False
    try:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise SafetyError("another SafeSync process holds the selected roots") from exc
        yield
    finally:
        try:
            if locked:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()
