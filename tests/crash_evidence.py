from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from tests.test_sync import SyncTestCase


def manifest(snapshot: dict[str, bytes]) -> dict[str, dict[str, object]]:
    result = {}
    for path, content in sorted(snapshot.items()):
        if "/conflicts/" in path:
            kind = "conflict"
        elif Path(path).name.startswith(".safesync-tmp-"):
            kind = "temp"
        elif path.endswith("state.json"):
            kind = "state"
        elif path.endswith("journal.json"):
            kind = "journal"
        else:
            kind = "normal"
        result[path] = {
            "kind": kind,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    return result


def metadata(snapshot: dict[str, bytes], filename: str) -> object | None:
    matching = [content for path, content in snapshot.items() if path.endswith(filename)]
    return json.loads(matching[0]) if matching else None


def stage(snapshot: dict[str, bytes]) -> dict[str, object]:
    return {
        "files": manifest(snapshot),
        "temp_files": sorted(path for path in snapshot if Path(path).name.startswith(".safesync-tmp-")),
        "journal": metadata(snapshot, "journal.json"),
        "state": metadata(snapshot, "state.json"),
    }


def main() -> None:
    case = SyncTestCase(methodName="test_external_kill_after_first_conflict_copy_recovers_other_binary_version")
    case.setUp()
    try:
        baseline = bytes(range(256)) * 64
        left_version = b"LEFT\x00" + bytes(range(255, -1, -1)) * 64
        right_version = b"RIGHT\x00" + bytes(range(256)) * 64
        case.write(case.left, "payload.bin", baseline)
        initial = case.run_worker()
        assert initial.returncode == 0, initial.stderr
        left_file = case.left / "payload.bin"
        right_file = case.right / "payload.bin"
        left_file.write_bytes(left_version)
        right_file.write_bytes(right_version)
        os.utime(left_file, (946684800, 946684800))
        os.utime(right_file, (1893456000, 1893456000))
        before = case._tree_snapshot()

        killed, signal, was_running, worker_pid, killed_exit = case.kill_worker_at("after_journal_commit")
        after_kill = case._tree_snapshot()
        assert was_running
        assert int(signal.split()[0]) == worker_pid
        assert killed_exit < 0
        assert killed.returncode != 0

        recovery_one = case.run_worker()
        assert recovery_one.returncode == 0, recovery_one.stderr
        after_one = case._tree_snapshot()
        recovery_two = case.run_worker()
        assert recovery_two.returncode == 0, recovery_two.stderr
        after_two = case._tree_snapshot()

        conflicts = case._conflict_files(after_two)
        assert list(conflicts.values()).count(left_version) == 1
        assert list(conflicts.values()).count(right_version) == 1
        assert not list(case.base.rglob(".safesync-tmp-*"))
        assert after_one == after_two
        case._assert_journal_state_disk_agree("payload.bin")

        diff_kill = case._snapshot_diff(before, after_kill)
        diff_one = case._snapshot_diff(after_kill, after_one)
        diff_two = case._snapshot_diff(after_one, after_two)
        report = {
            "process": {
                "pause_signal": signal,
                "worker_pid": worker_pid,
                "alive_before_parent_kill": was_running,
                "worker_exit_code_after_parent_kill": killed_exit,
                "launcher_result": killed.returncode,
            },
            "operation_logs": {
                "initial_sync_stderr": initial.stderr,
                "killed_worker_stderr": killed.stderr,
                "recovery_one_stderr": recovery_one.stderr,
                "recovery_two_stderr": recovery_two.stderr,
            },
            "stages": {
                "before_crash": stage(before),
                "directly_after_kill": stage(after_kill),
                "after_recovery_one": stage(after_one),
                "after_recovery_two": stage(after_two),
            },
            "changes": {
                "crash_worker_before_to_kill": {"count": sum(map(len, diff_kill.values())), "paths": diff_kill},
                "recovery_one": {"count": sum(map(len, diff_one.values())), "paths": diff_one},
                "recovery_two": {"count": sum(map(len, diff_two.values())), "paths": diff_two},
            },
            "proof_checks": {
                "left_normal_sha256": hashlib.sha256(left_file.read_bytes()).hexdigest(),
                "right_normal_sha256": hashlib.sha256(right_file.read_bytes()).hexdigest(),
                "left_conflict_copy_count": list(conflicts.values()).count(left_version),
                "right_conflict_copy_count": list(conflicts.values()).count(right_version),
                "remaining_temp_count": len(list(case.base.rglob(".safesync-tmp-*"))),
                "recovery_two_snapshot_byte_equal": after_one == after_two,
                "journal_state_disk_consistency_assertions": "passed",
            },
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        case.tearDown()


if __name__ == "__main__":
    main()
