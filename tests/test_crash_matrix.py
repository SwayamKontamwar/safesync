from __future__ import annotations

import os
import unittest
from pathlib import Path

from safesync import SyncEngine
from tests.test_sync import SyncTestCase


COPY_POINTS = (
    "after_journal_prepared",
    "during_temp_copy",
    "after_temp_fsync",
    "after_atomic_replace",
    "after_journal_commit",
    "after_state_commit",
)
DELETE_POINTS = (
    "after_journal_prepared",
    "after_delete_backup",
    "after_delete_unlink",
    "after_journal_commit",
    "after_state_commit",
)
MOVE_POINTS = (
    "after_journal_prepared",
    "after_move_destination",
    "after_move_unlink",
    "after_journal_commit",
    "after_state_commit",
)
TREE_MOVE_POINTS = (
    "after_journal_prepared",
    "during_move_tree",
    "after_move_destination",
    "after_move_unlink",
    "after_journal_commit",
    "after_state_commit",
)


class CrashCrossProductTests(unittest.TestCase):
    def new_case(self) -> SyncTestCase:
        case = SyncTestCase("test_one_way_creation_uses_verified_atomic_copy")
        case.setUp()
        self.addCleanup(case.tearDown)
        return case

    def test_create_change_delete_move_each_side_at_every_reachable_crash_point(self) -> None:
        matrix = {
            "create": COPY_POINTS,
            "change": COPY_POINTS,
            "delete": DELETE_POINTS,
            "move": MOVE_POINTS,
        }
        for operation, points in matrix.items():
            for side in ("left", "right"):
                for point in points:
                    with self.subTest(operation=operation, side=side, point=point):
                        case = self.new_case()
                        content = f"{operation}-{side}-{point}".encode() * 40000
                        engine = SyncEngine(case.left, case.right)
                        if operation != "create":
                            case.write(case.left, "old.bin", b"baseline")
                            engine.sync()
                        if operation == "create":
                            case.write(case.left if side == "left" else case.right, "new.bin", content)
                        elif operation == "change":
                            (case.left / "old.bin" if side == "left" else case.right / "old.bin").write_bytes(content)
                        elif operation == "delete":
                            target = case.left / "old.bin" if side == "left" else case.right / "old.bin"
                            target.unlink()
                            engine.confirm_deletion(side, "old.bin")
                        else:
                            root = case.left if side == "left" else case.right
                            os.replace(root / "old.bin", root / "moved.bin")

                        killed, signal, alive, worker_pid, exit_code = case.kill_worker_at(point)
                        self.assertTrue(alive)
                        self.assertEqual(int(signal.split()[0]), worker_pid)
                        self.assertLess(exit_code, 0)
                        self.assertNotEqual(killed.returncode, 0)
                        first = case.run_worker()
                        self.assertEqual(first.returncode, 0, first.stderr)
                        snapshot = case._tree_snapshot()
                        second = case.run_worker()
                        self.assertEqual(second.returncode, 0, second.stderr)
                        self.assertEqual(snapshot, case._tree_snapshot())
                        if operation == "create":
                            self.assertEqual((case.left / "new.bin").read_bytes(), content)
                            self.assertEqual((case.right / "new.bin").read_bytes(), content)
                        elif operation == "change":
                            self.assertEqual((case.left / "old.bin").read_bytes(), content)
                            self.assertEqual((case.right / "old.bin").read_bytes(), content)
                        elif operation == "delete":
                            self.assertFalse((case.left / "old.bin").exists())
                            self.assertFalse((case.right / "old.bin").exists())
                        else:
                            self.assertFalse((case.left / "old.bin").exists())
                            self.assertFalse((case.right / "old.bin").exists())
                            self.assertEqual((case.left / "moved.bin").read_bytes(), b"baseline")
                            self.assertEqual((case.right / "moved.bin").read_bytes(), b"baseline")

    def test_both_sides_conflicts_at_every_copy_crash_point(self) -> None:
        for scenario in ("create", "change", "move-different"):
            for point in COPY_POINTS:
                with self.subTest(scenario=scenario, point=point):
                    case = self.new_case()
                    engine = SyncEngine(case.left, case.right)
                    if scenario != "create":
                        case.write(case.left, "shared.bin", b"baseline")
                        engine.sync()
                    if scenario == "create":
                        case.write(case.left, "shared.bin", b"left-new")
                        case.write(case.right, "shared.bin", b"right-new")
                    elif scenario == "change":
                        (case.left / "shared.bin").write_bytes(b"left-change")
                        (case.right / "shared.bin").write_bytes(b"right-change")
                    else:
                        os.replace(case.left / "shared.bin", case.left / "left-name.bin")
                        os.replace(case.right / "shared.bin", case.right / "right-name.bin")
                    killed, _, alive, _, exit_code = case.kill_worker_at(point)
                    self.assertTrue(alive)
                    self.assertLess(exit_code, 0)
                    self.assertNotEqual(killed.returncode, 0)
                    self.assertEqual(case.run_worker().returncode, 0)
                    snapshot = case._tree_snapshot()
                    self.assertEqual(case.run_worker().returncode, 0)
                    self.assertEqual(snapshot, case._tree_snapshot())
                    conflicts = case._conflict_files(snapshot)
                    self.assertGreaterEqual(len(conflicts), 2)

    def test_both_sides_confirmed_delete_becomes_one_tombstone(self) -> None:
        case = self.new_case()
        case.write(case.left, "both.bin", b"both")
        engine = SyncEngine(case.left, case.right)
        engine.sync()
        (case.left / "both.bin").unlink()
        (case.right / "both.bin").unlink()
        engine.confirm_deletion("left", "both.bin")
        engine.confirm_deletion("right", "both.bin")
        result = engine.sync()
        self.assertFalse((case.left / "both.bin").exists())
        self.assertFalse((case.right / "both.bin").exists())
        self.assertEqual(0, result.committed)
        self.assertEqual((), engine.inspect().deletion_intents)
        snapshot = case._tree_snapshot()
        self.assertFalse(engine.sync().changed)
        self.assertEqual(snapshot, case._tree_snapshot())

    def test_directory_move_each_side_at_every_reachable_crash_point(self) -> None:
        for side in ("left", "right"):
            for point in TREE_MOVE_POINTS:
                with self.subTest(side=side, point=point):
                    case = self.new_case()
                    expected = {}
                    for number in range(4):
                        content = f"image-{side}-{point}-{number}".encode()
                        relative = f"photos/image-{number}.jpg"
                        expected[relative] = content
                        case.write(case.left, relative, content)
                        case.write(case.right, relative, content)
                    engine = SyncEngine(case.left, case.right)
                    engine.sync()
                    root = case.left if side == "left" else case.right
                    os.replace(root / "photos", root / "archive")

                    killed, signal, alive, worker_pid, exit_code = case.kill_worker_at(point)
                    self.assertTrue(alive)
                    self.assertEqual(int(signal.split()[0]), worker_pid)
                    self.assertLess(exit_code, 0)
                    self.assertNotEqual(killed.returncode, 0)
                    self.assertEqual(case.run_worker().returncode, 0)
                    after_first = case._tree_snapshot()
                    self.assertEqual(case.run_worker().returncode, 0)
                    self.assertEqual(after_first, case._tree_snapshot())
                    for current_root in (case.left, case.right):
                        self.assertFalse((current_root / "photos").exists())
                        for relative, content in expected.items():
                            filename = Path(relative).name
                            self.assertEqual((current_root / "archive" / filename).read_bytes(), content)

    def test_delete_versus_edit_each_direction_at_every_copy_crash_point(self) -> None:
        for deleted_side in ("left", "right"):
            for point in COPY_POINTS:
                with self.subTest(deleted_side=deleted_side, point=point):
                    case = self.new_case()
                    case.write(case.left, "contested.bin", b"baseline")
                    engine = SyncEngine(case.left, case.right)
                    engine.sync()
                    deleted_root = case.left if deleted_side == "left" else case.right
                    edited_root = case.right if deleted_side == "left" else case.left
                    edited = f"independent-{deleted_side}-{point}".encode()
                    (deleted_root / "contested.bin").unlink()
                    (edited_root / "contested.bin").write_bytes(edited)
                    engine.confirm_deletion(deleted_side, "contested.bin")

                    killed, signal, alive, worker_pid, exit_code = case.kill_worker_at(point)
                    self.assertTrue(alive)
                    self.assertEqual(int(signal.split()[0]), worker_pid)
                    self.assertLess(exit_code, 0)
                    self.assertNotEqual(killed.returncode, 0)
                    self.assertEqual(case.run_worker().returncode, 0)
                    after_first = case._tree_snapshot()
                    self.assertEqual(case.run_worker().returncode, 0)
                    self.assertEqual(after_first, case._tree_snapshot())
                    self.assertFalse((deleted_root / "contested.bin").exists())
                    self.assertEqual((edited_root / "contested.bin").read_bytes(), edited)
                    conflicts = case._conflict_files(after_first)
                    self.assertEqual(1, list(conflicts.values()).count(edited))


class ConcurrencyCrossProductTests(unittest.TestCase):
    def new_case(self) -> SyncTestCase:
        case = SyncTestCase("test_one_way_creation_uses_verified_atomic_copy")
        case.setUp()
        self.addCleanup(case.tearDown)
        return case

    def test_real_second_writer_across_create_change_delete_move_both_directions(self) -> None:
        for operation in ("create", "change", "delete", "move"):
            for side in ("left", "right"):
                with self.subTest(operation=operation, side=side):
                    case = self.new_case()
                    engine = SyncEngine(case.left, case.right)
                    source_root = case.left if side == "left" else case.right
                    peer_root = case.right if side == "left" else case.left
                    if operation != "create":
                        case.write(case.left, "old.bin", b"baseline")
                        engine.sync()
                    if operation == "create":
                        case.write(source_root, "new.bin", b"source create" * 200000)
                        result = case.run_worker_through_gate(
                            "during_temp_copy", lambda: (peer_root / "new.bin").write_bytes(b"second writer create")
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual((source_root / "new.bin").read_bytes(), b"source create" * 200000)
                        self.assertEqual((peer_root / "new.bin").read_bytes(), b"second writer create")
                    elif operation == "change":
                        (source_root / "old.bin").write_bytes(b"first writer" * 200000)
                        result = case.run_worker_through_gate(
                            "during_temp_copy", lambda: (source_root / "old.bin").write_bytes(b"second writer change")
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual((source_root / "old.bin").read_bytes(), b"second writer change")
                        self.assertEqual((peer_root / "old.bin").read_bytes(), b"baseline")
                    elif operation == "delete":
                        (source_root / "old.bin").unlink()
                        engine.confirm_deletion(side, "old.bin")
                        result = case.run_worker_through_gate(
                            "after_delete_backup", lambda: (peer_root / "old.bin").write_bytes(b"second writer edit")
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual((peer_root / "old.bin").read_bytes(), b"second writer edit")
                        backups = list((peer_root / ".safesync/trash").rglob("*"))
                        self.assertIn(b"baseline", [path.read_bytes() for path in backups if path.is_file()])
                    else:
                        os.replace(source_root / "old.bin", source_root / "new.bin")
                        result = case.run_worker_through_gate(
                            "after_move_destination", lambda: (peer_root / "old.bin").write_bytes(b"second writer move edit")
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual((peer_root / "old.bin").read_bytes(), b"second writer move edit")
                        self.assertEqual((peer_root / "new.bin").read_bytes(), b"second writer move edit")
                        self.assertEqual((source_root / "new.bin").read_bytes(), b"baseline")

    def test_real_simultaneous_writers_on_both_sides_become_conflict(self) -> None:
        case = self.new_case()
        case.write(case.left, "both.bin", b"baseline")
        engine = SyncEngine(case.left, case.right)
        engine.sync()
        barrier = __import__("threading").Barrier(3)

        def write(path, content):
            barrier.wait()
            path.write_bytes(content)

        threads = [
            __import__("threading").Thread(target=write, args=(case.left / "both.bin", b"left concurrent")),
            __import__("threading").Thread(target=write, args=(case.right / "both.bin", b"right concurrent")),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        result = engine.sync()
        self.assertEqual(result.conflicts, 1)
        self.assertEqual((case.left / "both.bin").read_bytes(), b"left concurrent")
        self.assertEqual((case.right / "both.bin").read_bytes(), b"right concurrent")
        self.assertCountEqual(
            [b"left concurrent", b"right concurrent"], case._conflict_files(case._tree_snapshot()).values()
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for test_class in (CrashCrossProductTests, ConcurrencyCrossProductTests):
        for name in sorted(test_class.__dict__):
            if name.startswith("test_"):
                suite.addTest(test_class(name))
    return suite
