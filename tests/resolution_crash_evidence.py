from __future__ import annotations

import hashlib
import json
import multiprocessing
import socket
from pathlib import Path

from safesync import SyncEngine
from tests.test_interface import _resolution_worker
from tests.test_sync import SyncTestCase


def manifest(snapshot: dict[str, bytes]) -> dict[str, dict[str, object]]:
    result = {}
    for path, content in sorted(snapshot.items()):
        if "/conflicts/" in path:
            kind = "conflict"
        elif Path(path).name.startswith(".safesync-tmp-") or Path(path).name.startswith(".") and path.endswith(".tmp"):
            kind = "temp"
        elif path.endswith("journal.json"):
            kind = "journal"
        elif path.endswith("state.json"):
            kind = "state"
        elif path.endswith("resolutions.json"):
            kind = "resolutions"
        elif path.endswith("operations.json"):
            kind = "operation_log"
        else:
            kind = "normal"
        result[path] = {"kind": kind, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
    return result


def metadata(snapshot: dict[str, bytes], filename: str):
    matches = [content for path, content in snapshot.items() if path.endswith(filename)]
    return json.loads(matches[0]) if matches else None


def stage(snapshot: dict[str, bytes]) -> dict:
    return {
        "files": manifest(snapshot),
        "temp_files": sorted(path for path in snapshot if Path(path).name.startswith(".safesync-tmp-")),
        "journal": metadata(snapshot, "journal.json"),
        "state": metadata(snapshot, "state.json"),
        "resolutions": metadata(snapshot, "resolutions.json"),
        "operation_log": metadata(snapshot, "operations.json"),
    }


def main() -> None:
    case = SyncTestCase("test_one_way_creation_uses_verified_atomic_copy")
    case.setUp()
    try:
        baseline = b"baseline" * 2048
        left_version = b"LEFT-RESOLUTION\x00" + bytes(range(256)) * 4096
        right_version = b"RIGHT-RESOLUTION\x00" + bytes(range(255, -1, -1)) * 4096
        case.write(case.left, "resolve.bin", baseline)
        engine = SyncEngine(case.left, case.right)
        engine.sync()
        (case.left / "resolve.bin").write_bytes(left_version)
        (case.right / "resolve.bin").write_bytes(right_version)
        engine.sync()
        conflict = engine.list_conflicts()[0]
        before = case._tree_snapshot()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            process = multiprocessing.get_context("spawn").Process(
                target=_resolution_worker,
                args=(str(case.left), str(case.right), conflict.conflict_id, "left",
                      "after_resolution_operation", listener.getsockname()[1]),
            )
            process.start()
            connection, _ = listener.accept()
            with connection:
                signal = connection.makefile("r", encoding="ascii").readline().strip()
            alive = process.is_alive()
            process.kill()
            process.join(timeout=15)
            exit_code = process.exitcode

        after_kill = case._tree_snapshot()
        engine.recover()
        after_one = case._tree_snapshot()
        engine.recover()
        after_two = case._tree_snapshot()
        conflicts = case._conflict_files(after_two)
        diff_kill = case._snapshot_diff(before, after_kill)
        diff_one = case._snapshot_diff(after_kill, after_one)
        diff_two = case._snapshot_diff(after_one, after_two)
        report = {
            "process": {
                "pause_signal": signal,
                "worker_pid": process.pid,
                "alive_before_parent_kill": alive,
                "worker_exit_code_after_parent_kill": exit_code,
            },
            "stages": {
                "before_resolution": stage(before),
                "directly_after_kill": stage(after_kill),
                "after_recovery_one": stage(after_one),
                "after_recovery_two": stage(after_two),
            },
            "changes": {
                "resolution_before_to_kill": {"count": sum(map(len, diff_kill.values())), "paths": diff_kill},
                "recovery_one": {"count": sum(map(len, diff_one.values())), "paths": diff_one},
                "recovery_two": {"count": sum(map(len, diff_two.values())), "paths": diff_two},
            },
            "proof_checks": {
                "left_normal_sha256": hashlib.sha256((case.left / "resolve.bin").read_bytes()).hexdigest(),
                "right_normal_sha256": hashlib.sha256((case.right / "resolve.bin").read_bytes()).hexdigest(),
                "left_stored_copy_count": list(conflicts.values()).count(left_version),
                "right_stored_copy_count": list(conflicts.values()).count(right_version),
                "remaining_temp_count": len(list(case.base.rglob(".safesync-tmp-*"))),
                "recovery_two_snapshot_byte_equal": after_one == after_two,
                "open_conflict_count": len(engine.list_conflicts()),
            },
        }
        assert alive and exit_code is not None and exit_code < 0
        assert after_one == after_two
        assert list(conflicts.values()).count(left_version) == 1
        assert list(conflicts.values()).count(right_version) == 1
        assert not list(case.base.rglob(".safesync-tmp-*"))
        assert not engine.list_conflicts()
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        case.tearDown()


if __name__ == "__main__":
    main()
