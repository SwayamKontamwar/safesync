from __future__ import annotations

import ctypes
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from safesync import SyncEngine
from safesync.filesystem import SafetyError, exclusive_lock, guarded_path, sha256_file
from tests.test_sync import SyncTestCase


class MetadataAndRecoveryTests(SyncTestCase):
    def test_external_kill_after_journal_prepared_recovers_idempotently(self) -> None:
        self.write(self.left, "prepared.bin", b"prepared payload")
        killed, signal, alive, worker_pid, exit_code = self.kill_worker_at("after_journal_prepared")
        self.assertTrue(alive)
        self.assertEqual(int(signal.split()[0]), worker_pid)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertFalse((self.right / "prepared.bin").exists())
        self.assertEqual({"prepared"}, {item["status"] for item in self._journal()["operations"].values()})
        first = self.run_worker()
        self.assertEqual(first.returncode, 0, first.stderr)
        snapshot = self._tree_snapshot()
        second = self.run_worker()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(snapshot, self._tree_snapshot())
        self.assertEqual((self.right / "prepared.bin").read_bytes(), b"prepared payload")
        self.assertEqual({}, self._journal()["operations"])

    def test_external_kill_after_journal_commit_recovers_state_and_compacts(self) -> None:
        self.write(self.left, "committed.bin", b"committed payload")
        killed, _, alive, _, exit_code = self.kill_worker_at("after_journal_commit")
        self.assertTrue(alive)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertEqual((self.right / "committed.bin").read_bytes(), b"committed payload")
        self.assertEqual({"committed"}, {item["status"] for item in self._journal()["operations"].values()})
        self.assertFalse((self.left / ".safesync/state.json").exists())
        self.assertEqual(self.run_worker().returncode, 0)
        snapshot = self._tree_snapshot()
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(snapshot, self._tree_snapshot())
        self.assertEqual({}, self._journal()["operations"])

    def test_external_kill_after_state_commit_only_compacts_on_recovery(self) -> None:
        content = b"state committed"
        self.write(self.left, "state.bin", content)
        killed, _, alive, _, exit_code = self.kill_worker_at("after_state_commit")
        self.assertTrue(alive)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertEqual((self.right / "state.bin").read_bytes(), content)
        state_before = (self.left / ".safesync/state.json").read_bytes()
        self.assertEqual({"committed"}, {item["status"] for item in self._journal()["operations"].values()})
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(state_before, (self.left / ".safesync/state.json").read_bytes())
        self.assertEqual({}, self._journal()["operations"])
        snapshot = self._tree_snapshot()
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(snapshot, self._tree_snapshot())

    def test_source_changed_during_real_copy_stops_without_destination(self) -> None:
        source = self.write(self.left, "changing.bin", b"A" * (3 * 1024 * 1024))
        result = self.run_worker_through_gate("during_temp_copy", lambda: source.write_bytes(b"B" * (3 * 1024 * 1024)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("temporary copy verification failed", result.stderr)
        self.assertEqual(source.read_bytes(), b"B" * (3 * 1024 * 1024))
        self.assertFalse((self.right / "changing.bin").exists())
        self.assertEqual({"prepared"}, {item["status"] for item in self._journal()["operations"].values()})

    def test_destination_appearing_during_copy_is_not_overwritten(self) -> None:
        self.write(self.left, "appeared.bin", b"source" * (512 * 1024))
        destination = self.right / "appeared.bin"
        result = self.run_worker_through_gate(
            "during_temp_copy", lambda: destination.write_bytes(b"independent destination")
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("destination appeared after planning", result.stderr)
        self.assertEqual(destination.read_bytes(), b"independent destination")
        self.assertEqual(1, len(list(self.base.rglob(".safesync-tmp-*"))))
        self.assertEqual({"temp_written"}, {item["status"] for item in self._journal()["operations"].values()})

    def test_external_kill_during_partial_temp_copy_recovers_idempotently(self) -> None:
        content = b"partial-crash" * (256 * 1024)
        self.write(self.left, "partial.bin", content)
        killed, _, alive, _, exit_code = self.kill_worker_at("during_temp_copy")
        self.assertTrue(alive)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        temp_files = list(self.base.rglob(".safesync-tmp-*"))
        self.assertEqual(1, len(temp_files))
        self.assertLess(temp_files[0].stat().st_size, len(content))
        self.assertEqual({"prepared"}, {item["status"] for item in self._journal()["operations"].values()})
        self.assertEqual(self.run_worker().returncode, 0)
        snapshot = self._tree_snapshot()
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(snapshot, self._tree_snapshot())
        self.assertEqual((self.right / "partial.bin").read_bytes(), content)
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))

    def test_invalid_state_json_stops_without_filesystem_change(self) -> None:
        self.write(self.left, "safe.txt", b"safe")
        SyncEngine(self.left, self.right).sync()
        (self.left / ".safesync/state.json").write_bytes(b"{not-json")
        before = self._tree_snapshot()
        with self.assertRaisesRegex(SafetyError, "invalid metadata"):
            SyncEngine(self.left, self.right).sync()
        self.assertEqual(before, self._tree_snapshot())

    def test_invalid_journal_schema_stops_without_copying(self) -> None:
        SyncEngine(self.left, self.right).initialize()
        self.write(self.left, "safe.txt", b"safe")
        (self.left / ".safesync/journal.json").write_text(
            json.dumps({"version": 3, "operations": {"bad": {"status": "mystery"}}}), encoding="utf-8"
        )
        before = self._tree_snapshot()
        with self.assertRaisesRegex(SafetyError, "invalid journal operation"):
            SyncEngine(self.left, self.right).sync()
        self.assertEqual(before, self._tree_snapshot())
        self.assertFalse((self.right / "safe.txt").exists())

    def test_truncated_journal_and_tampered_config_stop_safely(self) -> None:
        engine = SyncEngine(self.left, self.right)
        engine.initialize()
        engine.journal_path.write_bytes(b'{"version": 3, "operations":')
        before = self._tree_snapshot()
        with self.assertRaisesRegex(SafetyError, "invalid metadata"):
            engine.sync()
        self.assertEqual(before, self._tree_snapshot())
        engine.journal_path.write_text('{"operations": {}, "version": 3}\n', encoding="utf-8")
        engine.config_path.write_text(
            json.dumps({"version": 3, "left": str(self.left), "right": str(self.base / "elsewhere")}),
            encoding="utf-8",
        )
        before_config_check = self._tree_snapshot()
        with self.assertRaisesRegex(SafetyError, "root pair"):
            engine.sync()
        self.assertEqual(before_config_check, self._tree_snapshot())

    def test_initialized_state_cannot_be_reused_with_different_right_root(self) -> None:
        SyncEngine(self.left, self.right).initialize()
        other = self.base / "other"
        other.mkdir()
        before = self._tree_snapshot()
        with self.assertRaisesRegex(SafetyError, "root pair"):
            SyncEngine(self.left, other).sync()
        self.assertEqual(before, self._tree_snapshot())

    def test_exclusive_lock_rejects_concurrent_writer(self) -> None:
        engine = SyncEngine(self.left, self.right)
        with exclusive_lock(engine.lock_path):
            with self.assertRaisesRegex(SafetyError, "another SafeSync process"):
                engine.sync()

    def test_completed_journal_is_compacted_after_many_updates(self) -> None:
        path = self.write(self.left, "bounded.txt", b"0")
        engine = SyncEngine(self.left, self.right)
        for number in range(25):
            path.write_bytes(str(number).encode("ascii"))
            engine.sync()
        journal = json.loads(engine.journal_path.read_text(encoding="utf-8"))
        self.assertEqual({}, journal["operations"])
        self.assertLess(engine.journal_path.stat().st_size, 100)


@unittest.skipUnless(os.name == "nt", "Windows filesystem boundary test")
class WindowsBoundaryTests(SyncTestCase):
    def test_cross_root_case_collision_stops_before_copy(self) -> None:
        self.write(self.left, "Report.txt", b"left")
        self.write(self.right, "report.txt", b"right")
        before = self._tree_snapshot()
        with self.assertRaisesRegex(SafetyError, "case-insensitive collision"):
            SyncEngine(self.left, self.right).sync()
        after = self._tree_snapshot()
        self.assertEqual(before["left/Report.txt"], after["left/Report.txt"])
        self.assertEqual(before["right/report.txt"], after["right/report.txt"])
        self.assertFalse(list((self.left / ".safesync").glob("conflicts/**/*")))

    def test_reserved_and_trailing_windows_names_are_rejected(self) -> None:
        for relative in ("NUL.txt", "folder/bad. ", "stream:name"):
            with self.subTest(relative=relative):
                with self.assertRaises(SafetyError):
                    guarded_path(self.left, relative)

    def test_directory_junction_is_rejected_without_traversal(self) -> None:
        target = self.base / "junction-target"
        target.mkdir()
        (target / "outside.txt").write_bytes(b"outside")
        junction = self.left / "junction"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaisesRegex(SafetyError, "reparse points"):
            SyncEngine(self.left, self.right).sync()
        self.assertFalse((self.right / "junction/outside.txt").exists())

    def test_locked_destination_stops_and_recovers_after_unlock(self) -> None:
        source = self.write(self.left, "locked.bin", b"baseline")
        SyncEngine(self.left, self.right).sync()
        destination = self.right / "locked.bin"
        source.write_bytes(b"replacement")
        handle = self._open_without_sharing(destination)
        try:
            with self.assertRaises(PermissionError):
                SyncEngine(self.left, self.right).sync()
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
        self.assertEqual(destination.read_bytes(), b"baseline")
        SyncEngine(self.left, self.right).recover()
        self.assertEqual(destination.read_bytes(), b"replacement")
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))

    @staticmethod
    def _open_without_sharing(path: Path) -> int:
        generic_read = 0x80000000
        open_existing = 3
        handle = ctypes.windll.kernel32.CreateFileW(
            str(path), generic_read, 0, None, open_existing, 0, None
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError()
        return handle


class CliAndStressTests(SyncTestCase):
    def cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "safesync", *arguments],
            cwd=Path(__file__).parents[1], capture_output=True, text=True, timeout=30, check=False,
        )

    def test_complete_cli_workflow(self) -> None:
        before_inspect = self._tree_snapshot()
        uninitialized = self.cli("inspect", str(self.left), str(self.right))
        self.assertEqual(uninitialized.returncode, 0, uninitialized.stderr)
        self.assertFalse(json.loads(uninitialized.stdout)["initialized"])
        self.assertEqual(before_inspect, self._tree_snapshot())
        initialized = self.cli("init", str(self.left), str(self.right))
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        self.assertTrue(json.loads(initialized.stdout)["initialized"])
        repeated_init = self.cli("init", str(self.left), str(self.right))
        self.assertEqual(repeated_init.returncode, 0, repeated_init.stderr)
        self.assertFalse(json.loads(repeated_init.stdout)["initialized"])
        self.write(self.left, "cli.txt", b"cli")
        before = self._tree_snapshot()
        dry_run = self.cli("dry-run", str(self.left), str(self.right))
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertEqual(before, self._tree_snapshot())
        self.assertEqual(json.loads(dry_run.stdout)["planned"], 1)
        synced = self.cli("sync", str(self.left), str(self.right))
        self.assertEqual(synced.returncode, 0, synced.stderr)
        self.assertEqual((self.right / "cli.txt").read_bytes(), b"cli")
        inspected = self.cli("inspect", str(self.left), str(self.right))
        status = json.loads(inspected.stdout)
        self.assertTrue(status["initialized"])
        self.assertEqual(status["pending_operations"], 0)
        self.assertEqual(status["temporary_files"], [])
        recovered = self.cli("recover", str(self.left), str(self.right))
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertFalse(json.loads(recovered.stdout)["changed"])

    def test_deterministic_randomized_real_filesystem_rounds_converge(self) -> None:
        rng = random.Random(20260716)
        expected_left: dict[str, bytes] = {}
        for number in range(40):
            relative = f"group-{number % 5}/file-{number:02}.bin"
            content = rng.randbytes(rng.randint(0, 8192))
            expected_left[relative] = content
            self.write(self.left, relative, content)
        SyncEngine(self.left, self.right).sync()
        for relative, content in expected_left.items():
            self.assertEqual((self.right / relative).read_bytes(), content)

        conflicts: dict[str, tuple[bytes, bytes]] = {}
        for relative in sorted(expected_left):
            choice = rng.randrange(3)
            if choice == 0:
                self.write(self.left, relative, b"L" + rng.randbytes(1024))
            elif choice == 1:
                self.write(self.right, relative, b"R" + rng.randbytes(1024))
            else:
                left_content = b"CL" + rng.randbytes(1024)
                right_content = b"CR" + rng.randbytes(1024)
                self.write(self.left, relative, left_content)
                self.write(self.right, relative, right_content)
                conflicts[relative] = (left_content, right_content)
        SyncEngine(self.left, self.right).sync()
        snapshot = self._tree_snapshot()
        SyncEngine(self.left, self.right).sync()
        self.assertEqual(snapshot, self._tree_snapshot())
        conflict_contents = self._conflict_files(snapshot).values()
        for left_content, right_content in conflicts.values():
            self.assertIn(left_content, conflict_contents)
            self.assertIn(right_content, conflict_contents)
        self.assertFalse(list(self.base.rglob(".safesync-tmp-*")))


if __name__ == "__main__":
    unittest.main(verbosity=2)


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for test_class in (MetadataAndRecoveryTests, WindowsBoundaryTests, CliAndStressTests):
        for name in sorted(test_class.__dict__):
            if name.startswith("test_"):
                suite.addTest(test_class(name))
    return suite
