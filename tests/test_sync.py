from __future__ import annotations

import json
import hashlib
import logging
import multiprocessing
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from dataclasses import asdict

from safesync import SyncEngine
from safesync.filesystem import SafetyError, sha256_file


def _spawned_worker(
    left: str, right: str, point: str, port: int, stdout_path: str, stderr_path: str, resume: bool = False
) -> None:
    os.environ["SAFESYNC_PAUSE_POINT"] = point
    os.environ["SAFESYNC_PAUSE_PORT"] = str(port)
    if resume:
        os.environ["SAFESYNC_RESUME_AFTER_SIGNAL"] = "1"
    with open(stdout_path, "w", encoding="utf-8") as stdout, open(stderr_path, "w", encoding="utf-8") as stderr:
        logging.basicConfig(stream=stderr, level=logging.INFO, format="%(levelname)s %(message)s", force=True)
        try:
            result = SyncEngine(Path(left), Path(right)).sync()
            print(json.dumps(asdict(result), sort_keys=True), file=stdout, flush=True)
        except Exception:
            logging.exception("worker failed")
            raise SystemExit(2)


class SyncTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.left = self.base / "left"
        self.right = self.base / "right"
        self.left.mkdir()
        self.right.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, side: Path, relative: str, content: bytes) -> Path:
        path = side / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def run_worker(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("SAFESYNC_PAUSE_POINT", None)
        environment.pop("SAFESYNC_PAUSE_PORT", None)
        return subprocess.run(
            [sys.executable, "-m", "safesync", "--verbose", "sync", str(self.left), str(self.right)],
            cwd=Path(__file__).parents[1], env=environment, text=True,
            capture_output=True, timeout=15, check=False,
        )

    def kill_worker_at(self, point: str, action=None) -> tuple[subprocess.CompletedProcess[str], str, bool, int, int]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            stdout_path = self.base / "worker.stdout.log"
            stderr_path = self.base / "worker.stderr.log"
            process = multiprocessing.get_context("spawn").Process(
                target=_spawned_worker,
                args=(str(self.left), str(self.right), point, listener.getsockname()[1],
                      str(stdout_path), str(stderr_path)),
            )
            process.start()
            try:
                connection, _ = listener.accept()
                with connection:
                    signal = connection.makefile("r", encoding="ascii").readline().strip()
                worker_pid = int(signal.split()[0])
                was_running = process.is_alive()
                if action is not None:
                    action()
                process.kill()
                process.join(timeout=15)
                if process.is_alive():
                    raise RuntimeError("killed worker did not terminate")
                killed_exit_code = process.exitcode
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(timeout=15)
        stdout = stdout_path.read_text(encoding="utf-8") if stdout_path.exists() else ""
        stderr = stderr_path.read_text(encoding="utf-8") if stderr_path.exists() else ""
        completed = subprocess.CompletedProcess(["multiprocessing", point], process.exitcode, stdout, stderr)
        return completed, signal, was_running, worker_pid, killed_exit_code

    def run_worker_through_gate(self, point: str, action) -> subprocess.CompletedProcess[str]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            stdout_path = self.base / "gate.stdout.log"
            stderr_path = self.base / "gate.stderr.log"
            process = multiprocessing.get_context("spawn").Process(
                target=_spawned_worker,
                args=(str(self.left), str(self.right), point, listener.getsockname()[1],
                      str(stdout_path), str(stderr_path), True),
            )
            process.start()
            try:
                connection, _ = listener.accept()
                with connection:
                    signal = connection.makefile("r", encoding="ascii").readline().strip()
                    self.assertEqual(int(signal.split()[0]), process.pid)
                    self.assertEqual(signal.split()[1], point)
                    self.assertTrue(process.is_alive())
                    action()
                    connection.sendall(b"1")
                process.join(timeout=15)
                if process.is_alive():
                    raise RuntimeError("resumed worker did not terminate")
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(timeout=15)
        stdout = stdout_path.read_text(encoding="utf-8") if stdout_path.exists() else ""
        stderr = stderr_path.read_text(encoding="utf-8") if stderr_path.exists() else ""
        return subprocess.CompletedProcess(["multiprocessing", point], process.exitcode, stdout, stderr)

    def test_one_way_creation_uses_verified_atomic_copy(self) -> None:
        source = self.write(self.left, "folder/data.bin", b"complete payload" * 1000)
        result = SyncEngine(self.left, self.right).sync()
        destination = self.right / "folder/data.bin"
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(sha256_file(destination), sha256_file(source))
        self.assertEqual(result.committed, 1)
        self.assertFalse(list(self.right.rglob(".safesync-tmp-*")))

    def test_dry_run_logs_plan_and_changes_nothing(self) -> None:
        self.write(self.left, "new.txt", b"new")
        with self.assertLogs("safesync", level="INFO") as captured:
            result = SyncEngine(self.left, self.right, dry_run=True).sync()
        self.assertFalse((self.right / "new.txt").exists())
        self.assertFalse((self.left / ".safesync").exists())
        self.assertIn("would-write", "\n".join(captured.output))
        self.assertEqual(result.planned, 1)
        self.assertEqual(result.committed, 0)

    def test_rejects_overlapping_roots(self) -> None:
        nested = self.left / "nested"
        nested.mkdir()
        before = self._tree_snapshot()
        with self.assertRaises(SafetyError):
            SyncEngine(self.left, nested)
        self.assertEqual(before, self._tree_snapshot())
        self.assertFalse((self.left / ".safesync").exists())

    def test_tracks_state_and_ignores_misleading_timestamps(self) -> None:
        left_file = self.write(self.left, "notes.txt", b"baseline")
        SyncEngine(self.left, self.right).sync()
        right_file = self.right / "notes.txt"
        timestamp = 946684800
        left_file.write_bytes(b"left changed")
        os.utime(left_file, (timestamp, timestamp))
        os.utime(right_file, (timestamp + 100000, timestamp + 100000))
        result = SyncEngine(self.left, self.right).sync()
        self.assertEqual(right_file.read_bytes(), b"left changed")
        self.assertEqual(result.conflicts, 0)

    def test_unchanged_sync_does_not_replace_state_file(self) -> None:
        self.write(self.left, "stable.txt", b"stable")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        before = engine.state_path.stat()
        self.assertFalse(engine.sync().changed)
        after = engine.state_path.stat()
        self.assertEqual(before.st_ino, after.st_ino)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
        self.assertFalse((engine.control / ".state.json.tmp").exists())

    def test_independent_changes_preserve_both_and_retry_is_idempotent(self) -> None:
        left_file = self.write(self.left, "shared.txt", b"baseline")
        SyncEngine(self.left, self.right).sync()
        right_file = self.right / "shared.txt"
        left_file.write_bytes(b"left version")
        right_file.write_bytes(b"right version")
        os.utime(left_file, (2000000000, 2000000000))
        os.utime(right_file, (1000000000, 1000000000))
        first = SyncEngine(self.left, self.right).sync()
        first_snapshot = self._tree_snapshot()
        conflict_before = self._conflict_files(first_snapshot)
        second = SyncEngine(self.left, self.right).sync()
        second_snapshot = self._tree_snapshot()
        conflict_after = self._conflict_files(second_snapshot)
        self.assertEqual(2, len(conflict_before))
        self.assertCountEqual([b"left version", b"right version"], conflict_before.values())
        self.assertEqual(b"left version", (self.left / "shared.txt").read_bytes())
        self.assertEqual(b"right version", (self.right / "shared.txt").read_bytes())
        self.assertEqual(first_snapshot, second_snapshot)
        self.assertEqual(conflict_before, conflict_after)
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))
        self._assert_journal_state_disk_agree("shared.txt")
        self.assertEqual(first.conflicts, 1)
        self.assertFalse(second.changed)
        self.assertEqual(second.skipped, 0)

    def test_recovers_when_killed_after_replace_before_journal_commit(self) -> None:
        self.write(self.left, "replace.txt", b"replacement")
        before = self._tree_snapshot()
        killed, signal, was_running, worker_pid, killed_exit = self.kill_worker_at("after_atomic_replace")
        after_kill = self._tree_snapshot()
        self.assertTrue(was_running)
        self.assertEqual(signal, f"{signal.split()[0]} after_atomic_replace")
        self.assertEqual(int(signal.split()[0]), worker_pid)
        self.assertLess(killed_exit, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertNotEqual(before, after_kill)
        self.assertEqual((self.right / "replace.txt").read_bytes(), b"replacement")
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))
        journal_after_kill = self._journal()
        self.assertEqual({"temp_written"}, {entry["status"] for entry in journal_after_kill["operations"].values()})

        recovered = self.run_worker()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        after_recovery_one = self._tree_snapshot()
        self.assertEqual((self.right / "replace.txt").read_bytes(), b"replacement")
        unchanged = self.run_worker()
        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
        after_recovery_two = self._tree_snapshot()
        self.assertNotEqual(after_kill, after_recovery_one)
        self.assertEqual(after_recovery_one, after_recovery_two)
        self.assertEqual({}, self._snapshot_diff(after_recovery_one, after_recovery_two))
        self.assertEqual({}, self._journal()["operations"])
        self.assertFalse(json.loads(unchanged.stdout)["changed"])

    def test_previous_presence_distinguishes_deletion_and_stops(self) -> None:
        self.write(self.left, "kept.txt", b"content")
        SyncEngine(self.left, self.right).sync()
        original_hash = sha256_file(self.right / "kept.txt")
        (self.left / "kept.txt").unlink()
        after_user_deletion = self._tree_snapshot()
        state_before_refusal = (self.left / ".safesync/state.json").read_bytes()
        with self.assertLogs("safesync", level="WARNING") as captured:
            result = SyncEngine(self.left, self.right).sync()
        after_refusal = self._tree_snapshot()
        self.assertIn("skip unconfirmed deletion path=kept.txt side=left", "\n".join(captured.output))
        self.assertFalse((self.left / "kept.txt").exists())
        self.assertEqual((self.right / "kept.txt").read_bytes(), b"content")
        self.assertEqual(sha256_file(self.right / "kept.txt"), original_hash)
        self.assertEqual(state_before_refusal, (self.left / ".safesync/state.json").read_bytes())
        state = json.loads(state_before_refusal)
        self.assertEqual(state["files"]["kept.txt"]["left_hash"], original_hash)
        self.assertEqual(state["files"]["kept.txt"]["right_hash"], original_hash)
        self.assertEqual(after_user_deletion, after_refusal)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.committed, 0)

    def test_forced_termination_recovery_twice_preserves_versions(self) -> None:
        self.write(self.left, "shared.txt", b"baseline")
        self.assertEqual(self.run_worker().returncode, 0)
        (self.left / "shared.txt").write_bytes(b"left original")
        (self.right / "shared.txt").write_bytes(b"right original")

        before_crash = self._tree_snapshot()
        killed, signal, was_running, worker_pid, killed_exit = self.kill_worker_at("after_temp_fsync")
        directly_after_kill = self._tree_snapshot()
        self.assertTrue(was_running)
        self.assertEqual(signal.split()[1], "after_temp_fsync")
        self.assertEqual(int(signal.split()[0]), worker_pid)
        self.assertLess(killed_exit, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertEqual((self.left / "shared.txt").read_bytes(), b"left original")
        self.assertEqual((self.right / "shared.txt").read_bytes(), b"right original")
        temp_files = list(self.base.rglob(".safesync-tmp-*"))
        self.assertEqual(1, len(temp_files))
        self.assertEqual(temp_files[0].read_bytes(), b"left original")
        journal = self._journal()
        self.assertIn("temp_written", {item["status"] for item in journal["operations"].values()})
        self.assertNotEqual(before_crash, directly_after_kill)

        first_recovery = self.run_worker()
        self.assertEqual(first_recovery.returncode, 0, first_recovery.stderr)
        after_recovery_one = self._tree_snapshot()
        second_recovery = self.run_worker()
        self.assertEqual(second_recovery.returncode, 0, second_recovery.stderr)
        after_recovery_two = self._tree_snapshot()

        conflicts = self._conflict_files(after_recovery_two)
        self.assertEqual(2, len(conflicts))
        self.assertCountEqual([b"left original", b"right original"], conflicts.values())
        self.assertEqual((self.left / "shared.txt").read_bytes(), b"left original")
        self.assertEqual((self.right / "shared.txt").read_bytes(), b"right original")
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))
        self.assertNotEqual(directly_after_kill, after_recovery_one)
        self.assertEqual(after_recovery_one, after_recovery_two)
        self.assertEqual({}, self._snapshot_diff(after_recovery_one, after_recovery_two))
        self._assert_journal_state_disk_agree("shared.txt")
        second_result = json.loads(second_recovery.stdout.strip())
        self.assertFalse(second_result["changed"])
        self.assertEqual(second_result["committed"], 0)

    def test_external_kill_after_first_conflict_copy_recovers_other_binary_version(self) -> None:
        baseline = bytes(range(256)) * 64
        self.write(self.left, "payload.bin", baseline)
        self.assertEqual(self.run_worker().returncode, 0)
        left_version = b"LEFT\x00" + bytes(range(255, -1, -1)) * 64
        right_version = b"RIGHT\x00" + bytes(range(256)) * 64
        left_file = self.left / "payload.bin"
        right_file = self.right / "payload.bin"
        left_file.write_bytes(left_version)
        right_file.write_bytes(right_version)
        os.utime(left_file, (946684800, 946684800))
        os.utime(right_file, (1893456000, 1893456000))
        left_hash = hashlib.sha256(left_version).hexdigest()
        right_hash = hashlib.sha256(right_version).hexdigest()
        before_crash = self._tree_snapshot()

        killed, signal, was_running, worker_pid, killed_exit = self.kill_worker_at("after_journal_commit")
        after_kill = self._tree_snapshot()
        self.assertTrue(was_running)
        self.assertEqual(signal.split()[1], "after_journal_commit")
        self.assertEqual(int(signal.split()[0]), worker_pid)
        self.assertLess(killed_exit, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertEqual(1, len(self._conflict_files(after_kill)))
        self.assertCountEqual([left_version], self._conflict_files(after_kill).values())
        self.assertEqual(left_hash, sha256_file(left_file))
        self.assertEqual(right_hash, sha256_file(right_file))
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))
        self.assertNotEqual(before_crash, after_kill)

        first_recovery = self.run_worker()
        self.assertEqual(first_recovery.returncode, 0, first_recovery.stderr)
        after_recovery_one = self._tree_snapshot()
        second_recovery = self.run_worker()
        self.assertEqual(second_recovery.returncode, 0, second_recovery.stderr)
        after_recovery_two = self._tree_snapshot()

        conflict_files = self._conflict_files(after_recovery_two)
        self.assertEqual(2, len(conflict_files))
        self.assertEqual(1, list(conflict_files.values()).count(left_version))
        self.assertEqual(1, list(conflict_files.values()).count(right_version))
        self.assertEqual(left_hash, sha256_file(left_file))
        self.assertEqual(right_hash, sha256_file(right_file))
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))
        self.assertNotEqual(after_kill, after_recovery_one)
        self.assertEqual(after_recovery_one, after_recovery_two)
        self.assertEqual({}, self._snapshot_diff(after_recovery_one, after_recovery_two))
        self._assert_journal_state_disk_agree("payload.bin")

    def _tree_snapshot(self, *, exclude_live_lock: bool = False) -> dict[str, bytes]:
        result = {}
        for side_name, root in (("left", self.left), ("right", self.right)):
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    if exclude_live_lock and path == self.left / ".safesync" / "lock":
                        continue
                    result[f"{side_name}/{path.relative_to(root).as_posix()}"] = path.read_bytes()
        return result

    @staticmethod
    def _conflict_files(snapshot: dict[str, bytes]) -> dict[str, bytes]:
        return {path: content for path, content in snapshot.items() if "/conflicts/" in path}

    @staticmethod
    def _snapshot_diff(before: dict[str, bytes], after: dict[str, bytes]) -> dict[str, list[str]]:
        added = sorted(after.keys() - before.keys())
        removed = sorted(before.keys() - after.keys())
        modified = sorted(path for path in before.keys() & after.keys() if before[path] != after[path])
        return {key: value for key, value in (("added", added), ("removed", removed), ("modified", modified)) if value}

    def _journal(self) -> dict:
        return json.loads((self.left / ".safesync/journal.json").read_text(encoding="utf-8"))

    def _assert_journal_state_disk_agree(self, relative: str) -> None:
        state = json.loads((self.left / ".safesync/state.json").read_text(encoding="utf-8"))
        record = state["files"][relative]
        self.assertEqual(record["left_hash"], sha256_file(self.left / relative))
        self.assertEqual(record["right_hash"], sha256_file(self.right / relative))
        self.assertEqual({}, self._journal()["operations"])
        conflict_files = self._conflict_files(self._tree_snapshot())
        self.assertEqual(2, len(conflict_files))
        self.assertCountEqual(
            [record["left_hash"], record["right_hash"]],
            [hashlib.sha256(content).hexdigest() for content in conflict_files.values()],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
