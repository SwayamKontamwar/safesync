from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import socket
import threading
import time
import unittest
from pathlib import Path

from safesync import SyncEngine
from tests.test_sync import SyncTestCase
from safesync.watcher import WatchService


def _watch_worker(left: str, right: str, point: str, port: int, ready) -> None:
    os.environ["SAFESYNC_PAUSE_POINT"] = point
    os.environ["SAFESYNC_PAUSE_PORT"] = str(port)
    service = WatchService(Path(left), Path(right), settle_seconds=0.1, full_scan_seconds=1.0)
    service.run(ready_event=ready)


class DeletionTests(SyncTestCase):
    def prepare_deleted_left(self, content: bytes = b"delete me") -> SyncEngine:
        self.write(self.left, "gone.bin", content)
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "gone.bin").unlink()
        engine.confirm_deletion("left", "gone.bin")
        return engine

    def test_explicit_deletion_is_backed_up_tombstoned_and_idempotent(self) -> None:
        engine = self.prepare_deleted_left()
        result = engine.sync()
        self.assertEqual(result.committed, 1)
        self.assertFalse((self.right / "gone.bin").exists())
        backups = list((self.right / ".safesync/trash").rglob("right"))
        self.assertEqual(1, len(backups))
        self.assertEqual(backups[0].read_bytes(), b"delete me")
        state = json.loads(engine.state_path.read_text(encoding="utf-8"))["files"]["gone.bin"]
        self.assertTrue(state["tombstone"])
        self.assertIsNone(state["left_hash"])
        self.assertIsNone(state["right_hash"])
        first = self._tree_snapshot()
        self.assertFalse(engine.sync().changed)
        self.assertEqual(first, self._tree_snapshot())

    def test_delete_versus_independent_edit_preserves_edit_as_conflict(self) -> None:
        self.write(self.left, "gone.bin", b"baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "gone.bin").unlink()
        (self.right / "gone.bin").write_bytes(b"independent edit")
        engine.confirm_deletion("left", "gone.bin")
        result = engine.sync()
        self.assertEqual(result.conflicts, 1)
        self.assertEqual((self.right / "gone.bin").read_bytes(), b"independent edit")
        self.assertEqual([b"independent edit"], list(self._conflict_files(self._tree_snapshot()).values()))
        state = json.loads(engine.state_path.read_text(encoding="utf-8"))["files"]["gone.bin"]
        self.assertTrue(state["left_deleted"])
        self.assertEqual(state["right_hash"], hashlib.sha256(b"independent edit").hexdigest())
        first = self._tree_snapshot()
        self.assertFalse(engine.sync().changed)
        self.assertEqual(first, self._tree_snapshot())

    def test_kill_after_delete_backup_recovers_once(self) -> None:
        self.prepare_deleted_left(b"backup boundary")
        killed, _, alive, _, exit_code = self.kill_worker_at("after_delete_backup")
        self.assertTrue(alive)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertEqual((self.right / "gone.bin").read_bytes(), b"backup boundary")
        self.assertEqual(1, len(list((self.right / ".safesync/trash").rglob("right"))))
        self.assertEqual(self.run_worker().returncode, 0)
        snapshot = self._tree_snapshot()
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(snapshot, self._tree_snapshot())
        self.assertFalse((self.right / "gone.bin").exists())

    def test_kill_after_delete_unlink_does_not_resurrect(self) -> None:
        self.prepare_deleted_left(b"unlink boundary")
        killed, _, alive, _, exit_code = self.kill_worker_at("after_delete_unlink")
        self.assertTrue(alive)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertFalse((self.right / "gone.bin").exists())
        self.assertEqual(self.run_worker().returncode, 0)
        snapshot = self._tree_snapshot()
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(snapshot, self._tree_snapshot())


class MoveTests(SyncTestCase):
    def prepare_left_move(self, content: bytes = b"move me") -> SyncEngine:
        self.write(self.left, "old/file.bin", content)
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "new").mkdir()
        os.replace(self.left / "old/file.bin", self.left / "new/file.bin")
        return engine

    def test_identity_backed_move_creates_verified_name_before_removing_old(self) -> None:
        engine = self.prepare_left_move()
        old_identity = (self.right / "old/file.bin").stat().st_ino
        result = engine.sync()
        self.assertEqual(result.committed, 1)
        self.assertFalse((self.right / "old/file.bin").exists())
        self.assertEqual((self.right / "new/file.bin").read_bytes(), b"move me")
        self.assertEqual(old_identity, (self.right / "new/file.bin").stat().st_ino)
        snapshot = self._tree_snapshot()
        self.assertFalse(engine.sync().changed)
        self.assertEqual(snapshot, self._tree_snapshot())

    def test_folder_rename_with_one_thousand_images_uses_one_tree_operation(self) -> None:
        for number in range(1000):
            relative = f"photos/image-{number:04}.jpg"
            content = b"JPEG" + number.to_bytes(4, "little")
            self.write(self.left, relative, content)
            self.write(self.right, relative, content)
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        os.replace(self.left / "photos", self.left / "archive")
        result = engine.sync()
        self.assertEqual(result.planned, 1)
        self.assertEqual(result.committed, 1)
        self.assertFalse((self.right / "photos").exists())
        files = sorted((self.right / "archive").glob("*.jpg"))
        self.assertEqual(1000, len(files))
        self.assertEqual(b"JPEG" + (777).to_bytes(4, "little"), files[777].read_bytes())
        snapshot = self._tree_snapshot()
        self.assertFalse(engine.sync().changed)
        self.assertEqual(snapshot, self._tree_snapshot())


class WatchTests(SyncTestCase):
    def prepare_left_move(self, content: bytes = b"move me") -> SyncEngine:
        self.write(self.left, "old/file.bin", content)
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "new").mkdir()
        os.replace(self.left / "old/file.bin", self.left / "new/file.bin")
        return engine

    def start_watch(self, settle: float = 0.2, full_scan: float = 0.5):
        service = WatchService(self.left, self.right, settle_seconds=settle, full_scan_seconds=full_scan)
        stop = threading.Event()
        thread = threading.Thread(target=service.run, args=(stop,), daemon=True)
        thread.start()
        self.assertTrue(self.wait_until(lambda: service.engine.config_path.exists()))
        time.sleep(0.2)
        return service, stop, thread

    def stop_watch(self, stop, thread) -> None:
        stop.set()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())

    def kill_watch_at(self, point: str, action):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            context = multiprocessing.get_context("spawn")
            ready = context.Event()
            process = context.Process(
                target=_watch_worker,
                args=(str(self.left), str(self.right), point, listener.getsockname()[1], ready),
            )
            process.start()
            try:
                self.assertTrue(ready.wait(timeout=10))
                time.sleep(0.2)
                action()
                connection, _ = listener.accept()
                with connection:
                    signal = connection.makefile("r", encoding="ascii").readline().strip()
                self.assertEqual(int(signal.split()[0]), process.pid)
                self.assertTrue(process.is_alive())
                process.kill()
                process.join(timeout=15)
                self.assertFalse(process.is_alive())
                self.assertLess(process.exitcode, 0)
                return signal, process.exitcode
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(timeout=15)

    @staticmethod
    def wait_until(predicate, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def test_editor_temp_flush_and_rename_syncs_only_settled_final_file(self) -> None:
        self.write(self.left, "note.txt", b"old")
        SyncEngine(self.left, self.right).sync()
        service, stop, thread = self.start_watch()
        try:
            temporary = self.left / ".note.txt.editor-tmp"
            with temporary.open("wb") as stream:
                stream.write(b"new ")
                stream.flush()
                os.fsync(stream.fileno())
                time.sleep(0.1)
                stream.write(b"complete")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.left / "note.txt")
            self.assertTrue(self.wait_until(lambda: (self.right / "note.txt").read_bytes() == b"new complete"))
            self.assertFalse((self.right / ".note.txt.editor-tmp").exists())
            self.assertTrue(self.wait_until(lambda: not json.loads(
                (self.left / ".safesync/journal.json").read_text(encoding="utf-8")
            )["operations"]))
            snapshot = self._tree_snapshot(exclude_live_lock=True)
            time.sleep(0.8)
            self.assertEqual(snapshot, self._tree_snapshot(exclude_live_lock=True))
        finally:
            self.stop_watch(stop, thread)

    def test_active_writer_is_not_synced_until_quiet(self) -> None:
        self.write(self.left, "active.bin", b"baseline")
        SyncEngine(self.left, self.right).sync()
        service, stop, thread = self.start_watch(settle=0.35)
        try:
            path = self.left / "active.bin"
            for number in range(6):
                path.write_bytes(f"partial-{number}".encode())
                time.sleep(0.1)
            self.assertEqual((self.right / "active.bin").read_bytes(), b"baseline")
            path.write_bytes(b"settled-final")
            self.assertTrue(self.wait_until(lambda: (self.right / "active.bin").read_bytes() == b"settled-final"))
        finally:
            self.stop_watch(stop, thread)

    def test_direct_delete_event_propagates_but_prestart_absence_does_not(self) -> None:
        self.write(self.left, "observed.txt", b"observed")
        self.write(self.left, "unobserved.txt", b"unobserved")
        SyncEngine(self.left, self.right).sync()
        (self.left / "unobserved.txt").unlink()
        service, stop, thread = self.start_watch()
        try:
            time.sleep(0.8)
            self.assertTrue((self.right / "unobserved.txt").exists())
            (self.left / "observed.txt").unlink()
            self.assertTrue(self.wait_until(lambda: not (self.right / "observed.txt").exists()))
            self.assertTrue((self.right / "unobserved.txt").exists())
        finally:
            self.stop_watch(stop, thread)

    def test_forced_full_scan_reconciles_even_without_trusting_event_queue(self) -> None:
        self.write(self.left, "overflow.txt", b"before")
        SyncEngine(self.left, self.right).sync()
        service, stop, thread = self.start_watch(full_scan=60)
        try:
            (self.left / "overflow.txt").write_bytes(b"after overflow")
            while not service.events.empty():
                service.events.get_nowait()
            service.notify_overflow()
            self.assertTrue(self.wait_until(lambda: (self.right / "overflow.txt").read_bytes() == b"after overflow"))
        finally:
            self.stop_watch(stop, thread)

    def test_watch_killed_during_copy_recovers_without_duplicate(self) -> None:
        self.kill_watch_at(
            "after_temp_fsync", lambda: self.write(self.left, "watched-crash.bin", b"watch crash" * 200000)
        )
        engine = SyncEngine(self.left, self.right)
        engine.recover()
        self.assertEqual((self.right / "watched-crash.bin").read_bytes(), b"watch crash" * 200000)
        snapshot = self._tree_snapshot()
        self.assertFalse(engine.recover().changed)
        self.assertEqual(snapshot, self._tree_snapshot())

    def test_watch_killed_after_delete_backup_recovers_tombstone(self) -> None:
        self.write(self.left, "watch-delete.bin", b"watch delete")
        SyncEngine(self.left, self.right).sync()
        self.kill_watch_at("after_delete_backup", lambda: (self.left / "watch-delete.bin").unlink())
        engine = SyncEngine(self.left, self.right)
        engine.recover()
        self.assertFalse((self.left / "watch-delete.bin").exists())
        self.assertFalse((self.right / "watch-delete.bin").exists())
        snapshot = self._tree_snapshot()
        self.assertFalse(engine.recover().changed)
        self.assertEqual(snapshot, self._tree_snapshot())

    def test_equal_hashes_do_not_confuse_identity_move(self) -> None:
        self.write(self.left, "a.txt", b"same")
        self.write(self.left, "b.txt", b"same")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        os.replace(self.left / "a.txt", self.left / "c.txt")
        engine.sync()
        self.assertFalse((self.right / "a.txt").exists())
        self.assertEqual((self.right / "b.txt").read_bytes(), b"same")
        self.assertEqual((self.right / "c.txt").read_bytes(), b"same")

    def test_kill_after_move_destination_keeps_both_names_until_recovery(self) -> None:
        self.prepare_left_move(b"move destination boundary")
        killed, _, alive, _, exit_code = self.kill_worker_at("after_move_destination")
        self.assertTrue(alive)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertEqual((self.right / "old/file.bin").read_bytes(), b"move destination boundary")
        self.assertEqual((self.right / "new/file.bin").read_bytes(), b"move destination boundary")
        self.assertEqual(self.run_worker().returncode, 0)
        snapshot = self._tree_snapshot()
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(snapshot, self._tree_snapshot())
        self.assertFalse((self.right / "old/file.bin").exists())

    def test_kill_after_move_unlink_does_not_restore_old_name(self) -> None:
        self.prepare_left_move(b"move unlink boundary")
        killed, _, alive, _, exit_code = self.kill_worker_at("after_move_unlink")
        self.assertTrue(alive)
        self.assertLess(exit_code, 0)
        self.assertNotEqual(killed.returncode, 0)
        self.assertFalse((self.right / "old/file.bin").exists())
        self.assertEqual((self.right / "new/file.bin").read_bytes(), b"move unlink boundary")
        self.assertEqual(self.run_worker().returncode, 0)
        snapshot = self._tree_snapshot()
        self.assertEqual(self.run_worker().returncode, 0)
        self.assertEqual(snapshot, self._tree_snapshot())


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for test_class in (DeletionTests, MoveTests, WatchTests):
        for name in sorted(test_class.__dict__):
            if name.startswith("test_"):
                suite.addTest(test_class(name))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
