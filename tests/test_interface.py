from __future__ import annotations

import os
import multiprocessing
import socket
import json
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from safesync import SyncEngine
from safesync.web import create_server
from tests.test_sync import SyncTestCase


def _resolution_worker(
    left: str, right: str, conflict_id: str, choice: str, point: str, port: int, resume: bool = False
) -> None:
    os.environ["SAFESYNC_PAUSE_POINT"] = point
    os.environ["SAFESYNC_PAUSE_PORT"] = str(port)
    if resume:
        os.environ["SAFESYNC_RESUME_AFTER_SIGNAL"] = "1"
    SyncEngine(Path(left), Path(right)).resolve_conflict(conflict_id, choice)


class ResolutionEngineTests(SyncTestCase):
    def prepare_content_conflict(self) -> tuple[SyncEngine, bytes, bytes]:
        left_version = b"left interface version"
        right_version = b"right interface version"
        self.write(self.left, "notes/report.txt", b"baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "notes/report.txt").write_bytes(left_version)
        (self.right / "notes/report.txt").write_bytes(right_version)
        engine.sync()
        return engine, left_version, right_version

    def test_pick_left_resolves_content_conflict_through_journal(self) -> None:
        engine, left_version, _ = self.prepare_content_conflict()
        conflict = engine.list_conflicts()[0]
        result = engine.resolve_conflict(conflict.conflict_id, "left")
        self.assertGreaterEqual(result.operations, 2)
        self.assertEqual(left_version, (self.left / "notes/report.txt").read_bytes())
        self.assertEqual(left_version, (self.right / "notes/report.txt").read_bytes())
        self.assertEqual((), engine.list_conflicts())
        snapshot = self._tree_snapshot()
        self.assertFalse(engine.recover().changed)
        self.assertEqual(snapshot, self._tree_snapshot())

    def test_keep_both_creates_deterministic_versions_on_both_roots(self) -> None:
        engine, left_version, right_version = self.prepare_content_conflict()
        conflict = engine.list_conflicts()[0]
        engine.resolve_conflict(conflict.conflict_id, "keep_both")
        for root in (self.left, self.right):
            self.assertEqual(left_version, (root / "notes/report.txt").read_bytes())
            alternates = sorted((root / "notes").glob("report.safesync-*.txt"))
            self.assertEqual(2, len(alternates))
            self.assertCountEqual([left_version, right_version], [path.read_bytes() for path in alternates])
        snapshot = self._tree_snapshot()
        self.assertFalse(engine.recover().changed)
        self.assertEqual(snapshot, self._tree_snapshot())

    def test_delete_conflict_can_restore_survivor_or_honor_deletion(self) -> None:
        for choice in ("right", "left"):
            with self.subTest(choice=choice):
                case = SyncTestCase("test_one_way_creation_uses_verified_atomic_copy")
                case.setUp()
                self.addCleanup(case.tearDown)
                case.write(case.left, "deleted.txt", b"baseline")
                engine = SyncEngine(case.left, case.right)
                engine.sync()
                (case.left / "deleted.txt").unlink()
                edited = b"edited while deleted"
                (case.right / "deleted.txt").write_bytes(edited)
                engine.confirm_deletion("left", "deleted.txt")
                engine.sync()
                conflict = engine.list_conflicts()[0]
                self.assertEqual("delete", conflict.kind)
                engine.resolve_conflict(conflict.conflict_id, choice)
                if choice == "right":
                    self.assertEqual(edited, (case.left / "deleted.txt").read_bytes())
                    self.assertEqual(edited, (case.right / "deleted.txt").read_bytes())
                else:
                    self.assertFalse((case.left / "deleted.txt").exists())
                    self.assertFalse((case.right / "deleted.txt").exists())
                self.assertEqual((), engine.list_conflicts())

    def test_keep_both_resolves_divergent_move_paths(self) -> None:
        self.write(self.left, "old.bin", b"move baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        os.replace(self.left / "old.bin", self.left / "left-name.bin")
        os.replace(self.right / "old.bin", self.right / "right-name.bin")
        engine.sync()
        conflict = engine.list_conflicts()[0]
        self.assertEqual("move", conflict.kind)
        engine.resolve_conflict(conflict.conflict_id, "keep_both")
        for root in (self.left, self.right):
            self.assertEqual(b"move baseline", (root / "left-name.bin").read_bytes())
            self.assertEqual(b"move baseline", (root / "right-name.bin").read_bytes())
        self.assertEqual((), engine.list_conflicts())

    def test_parent_kill_at_every_resolution_point_recovers_once(self) -> None:
        points = (
            "after_resolution_intent",
            "after_resolution_journal_prepared",
            "during_temp_copy",
            "after_temp_fsync",
            "after_atomic_replace",
            "after_journal_commit",
            "after_resolution_operation",
            "after_resolution_state_commit",
            "after_resolution_commit",
        )
        for point in points:
            with self.subTest(point=point):
                case = SyncTestCase("test_one_way_creation_uses_verified_atomic_copy")
                case.setUp()
                self.addCleanup(case.tearDown)
                left_version = f"left-{point}".encode() * 100000
                right_version = f"right-{point}".encode() * 100000
                case.write(case.left, "crash.bin", b"baseline")
                engine = SyncEngine(case.left, case.right)
                engine.sync()
                (case.left / "crash.bin").write_bytes(left_version)
                (case.right / "crash.bin").write_bytes(right_version)
                engine.sync()
                conflict_id = engine.list_conflicts()[0].conflict_id
                before = case._tree_snapshot()

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    listener.settimeout(15)
                    process = multiprocessing.get_context("spawn").Process(
                        target=_resolution_worker,
                        args=(str(case.left), str(case.right), conflict_id, "left", point, listener.getsockname()[1]),
                    )
                    process.start()
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            signal = connection.makefile("r", encoding="ascii").readline().strip()
                        self.assertEqual(int(signal.split()[0]), process.pid)
                        self.assertEqual(point, signal.split()[1])
                        self.assertTrue(process.is_alive())
                        process.kill()
                        process.join(timeout=15)
                        self.assertFalse(process.is_alive())
                        self.assertLess(process.exitcode, 0)
                    finally:
                        if process.is_alive():
                            process.kill()
                            process.join(timeout=15)

                directly_after_kill = case._tree_snapshot()
                self.assertNotEqual(before, directly_after_kill)
                engine.recover()
                after_recovery_one = case._tree_snapshot()
                engine.recover()
                after_recovery_two = case._tree_snapshot()
                self.assertEqual(after_recovery_one, after_recovery_two)
                self.assertEqual(left_version, (case.left / "crash.bin").read_bytes())
                self.assertEqual(left_version, (case.right / "crash.bin").read_bytes())
                conflicts = case._conflict_files(after_recovery_two)
                self.assertEqual(1, list(conflicts.values()).count(left_version))
                self.assertEqual(1, list(conflicts.values()).count(right_version))
                self.assertFalse(list(case.base.rglob(".safesync-tmp-*")))


class InterfaceHTTPTests(SyncTestCase):
    def start_server(self):
        server = create_server(self.left, self.right)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def cleanup() -> None:
            server.watcher.stop()
            server.shutdown()
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
            server.server_close()

        self.addCleanup(cleanup)
        return server, f"http://127.0.0.1:{server.server_port}"

    @staticmethod
    def get(url: str) -> tuple[int, bytes]:
        with urlopen(url, timeout=10) as response:
            return response.status, response.read()

    @staticmethod
    def post(url: str, token: str, body: dict) -> tuple[int, dict]:
        request = Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "X-SafeSync-Token": token},
        )
        try:
            with urlopen(request, timeout=15) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise AssertionError(f"POST {url} returned {exc.code}: {detail}") from exc

    def wait_until(self, predicate, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def test_static_interface_status_and_token_protection(self) -> None:
        self.write(self.left, "visible.txt", b"visible")
        SyncEngine(self.left, self.right).sync()
        server, base = self.start_server()
        status, html = self.get(base + "/")
        self.assertEqual(200, status)
        self.assertIn(b"SafeSync", html)
        self.assertIn(server.token.encode("ascii"), html)
        status, body = self.get(base + "/api/status")
        self.assertEqual(200, status)
        payload = json.loads(body)
        self.assertEqual("in_sync", next(item for item in payload["files"] if item["path"] == "visible.txt")["status"])
        bad = Request(
            base + "/api/sync", data=b"{}", method="POST",
            headers={"Content-Type": "application/json", "X-SafeSync-Token": "wrong"},
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(bad, timeout=10)
        self.assertEqual(403, raised.exception.code)

    def test_http_resolve_and_live_watch_workflow(self) -> None:
        self.write(self.left, "web.txt", b"baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "web.txt").write_bytes(b"left web")
        (self.right / "web.txt").write_bytes(b"right web")
        engine.sync()
        server, base = self.start_server()
        _, body = self.get(base + "/api/status")
        conflict = json.loads(body)["conflicts"][0]
        status, resolved = self.post(
            f"{base}/api/conflicts/{conflict['conflict_id']}/resolve", server.token, {"choice": "right"}
        )
        self.assertEqual(200, status)
        self.assertEqual([], resolved["status"]["conflicts"])
        self.assertEqual(b"right web", (self.left / "web.txt").read_bytes())
        self.assertEqual(b"right web", (self.right / "web.txt").read_bytes())

        status, watched = self.post(base + "/api/watch/start", server.token, {"settle": 0.1, "full_scan": 1})
        self.assertEqual(200, status)
        self.assertTrue(watched["watch"]["running"])
        self.write(self.left, "live/new.txt", b"live update")

        def synchronized() -> bool:
            _, current = self.get(base + "/api/status")
            payload = json.loads(current)
            file = next((item for item in payload["files"] if item["path"] == "live/new.txt"), None)
            return bool(file and file["status"] == "in_sync" and payload["watch"]["events"])

        self.assertTrue(self.wait_until(synchronized))
        status, stopped = self.post(base + "/api/watch/stop", server.token, {})
        self.assertEqual(200, status)
        self.assertFalse(stopped["watch"]["running"])

    def test_watcher_dashboard_and_resolver_are_serialized_in_process(self) -> None:
        self.write(self.left, "serialized.txt", b"baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "serialized.txt").write_bytes(b"serialized left")
        (self.right / "serialized.txt").write_bytes(b"serialized right")
        engine.sync()
        server, base = self.start_server()
        self.post(base + "/api/watch/start", server.token, {"settle": 0.05, "full_scan": 0.2})
        conflict_id = engine.list_conflicts()[0].conflict_id
        errors: list[Exception] = []
        barrier = threading.Barrier(6)

        def read_dashboard() -> None:
            try:
                barrier.wait()
                for _ in range(20):
                    self.get(base + "/api/status")
            except HTTPError as exc:
                errors.append(RuntimeError(exc.read().decode("utf-8", errors="replace")))
            except Exception as exc:
                errors.append(exc)

        readers = [threading.Thread(target=read_dashboard) for _ in range(5)]
        for reader in readers:
            reader.start()
        barrier.wait()
        try:
            status, _ = self.post(
                f"{base}/api/conflicts/{conflict_id}/resolve", server.token, {"choice": "left"}
            )
        finally:
            for reader in readers:
                reader.join(timeout=15)
        self.assertEqual(200, status)
        self.assertEqual([], errors)
        self.assertEqual(b"serialized left", (self.left / "serialized.txt").read_bytes())
        self.assertEqual(b"serialized left", (self.right / "serialized.txt").read_bytes())
        self.post(base + "/api/watch/stop", server.token, {})

    def test_external_writer_during_resolution_stops_with_all_versions(self) -> None:
        left_version = b"resolver left"
        right_version = b"resolver right"
        third_version = b"external writer after plan"
        self.write(self.left, "contended.txt", b"baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "contended.txt").write_bytes(left_version)
        (self.right / "contended.txt").write_bytes(right_version)
        engine.sync()
        conflict_id = engine.list_conflicts()[0].conflict_id
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            process = multiprocessing.get_context("spawn").Process(
                target=_resolution_worker,
                args=(str(self.left), str(self.right), conflict_id, "left",
                      "after_resolution_journal_prepared", listener.getsockname()[1], True),
            )
            process.start()
            try:
                connection, _ = listener.accept()
                with connection:
                    signal = connection.makefile("r", encoding="ascii").readline().strip()
                    self.assertEqual(process.pid, int(signal.split()[0]))
                    self.assertTrue(process.is_alive())
                    (self.right / "contended.txt").write_bytes(third_version)
                    connection.sendall(b"1")
                process.join(timeout=15)
                self.assertFalse(process.is_alive())
                self.assertNotEqual(0, process.exitcode)
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(timeout=15)
        self.assertEqual(left_version, (self.left / "contended.txt").read_bytes())
        self.assertEqual(third_version, (self.right / "contended.txt").read_bytes())
        conflicts = self._conflict_files(self._tree_snapshot())
        self.assertEqual(1, list(conflicts.values()).count(left_version))
        self.assertEqual(1, list(conflicts.values()).count(right_version))
        with self.assertRaisesRegex(Exception, "destination changed after planning"):
            engine.recover()

    def test_dashboard_exposes_journal_and_temp_while_resolver_is_paused(self) -> None:
        self.write(self.left, "pending.bin", b"baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "pending.bin").write_bytes(b"pending left" * 200000)
        (self.right / "pending.bin").write_bytes(b"pending right" * 200000)
        engine.sync()
        conflict_id = engine.list_conflicts()[0].conflict_id
        server, base = self.start_server()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            process = multiprocessing.get_context("spawn").Process(
                target=_resolution_worker,
                args=(str(self.left), str(self.right), conflict_id, "left",
                      "during_temp_copy", listener.getsockname()[1], True),
            )
            process.start()
            try:
                connection, _ = listener.accept()
                with connection:
                    signal = connection.makefile("r", encoding="ascii").readline().strip()
                    self.assertEqual(process.pid, int(signal.split()[0]))
                    _, body = self.get(base + "/api/status")
                    payload = json.loads(body)
                    self.assertTrue(payload["journal"]["operations"])
                    self.assertTrue(payload["temporary_files"])
                    self.assertEqual(
                        "mid_operation",
                        next(item for item in payload["files"] if item["path"] == "pending.bin")["status"],
                    )
                    process.kill()
                    process.join(timeout=15)
                    self.assertLess(process.exitcode, 0)
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(timeout=15)
        engine.recover()


@unittest.skipUnless(os.name == "nt", "browser interface test requires Windows Edge")
class InterfaceBrowserTests(InterfaceHTTPTests):
    EDGE = Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")

    def test_real_browser_resolves_conflict_and_tracks_watch_event(self) -> None:
        if not self.EDGE.exists():
            self.skipTest("Microsoft Edge is not installed")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("install the pyproject test extra to run browser automation")

        self.write(self.left, "browser.txt", b"baseline")
        engine = SyncEngine(self.left, self.right)
        engine.sync()
        (self.left / "browser.txt").write_bytes(b"browser left")
        (self.right / "browser.txt").write_bytes(b"browser right")
        engine.sync()
        server, base = self.start_server()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(self.EDGE), headless=True)
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.goto(base, wait_until="networkidle")
                page.get_by_text("SafeSync", exact=True).wait_for()
                self.assertEqual("1", page.locator("#conflict-badge").inner_text())
                page.get_by_role("button", name="Conflicts 1").click()
                page.get_by_role("button", name="Use right").click()
                page.get_by_text("No open conflicts").wait_for()
                self.assertEqual(b"browser right", (self.left / "browser.txt").read_bytes())
                self.assertEqual(b"browser right", (self.right / "browser.txt").read_bytes())

                page.get_by_role("button", name="Start watch").click()
                page.get_by_role("button", name="Stop watch").wait_for()
                self.write(self.left, "browser-live.txt", b"browser live")
                page.get_by_role("button", name="Files").click()
                row = page.locator("tr", has_text="browser-live.txt")
                row.get_by_text("in sync").wait_for(timeout=10000)
                self.assertGreater(len(page.screenshot()), 10000)
                self.assertLessEqual(
                    page.evaluate("document.documentElement.scrollWidth"),
                    page.evaluate("document.documentElement.clientWidth"),
                )

                page.set_viewport_size({"width": 390, "height": 844})
                page.wait_for_timeout(250)
                self.assertGreater(len(page.screenshot()), 8000)
                self.assertLessEqual(
                    page.evaluate("document.documentElement.scrollWidth"),
                    page.evaluate("document.documentElement.clientWidth"),
                )
                page.get_by_role("button", name="Stop watch").click()
                page.get_by_role("button", name="Start watch").wait_for()
            finally:
                browser.close()


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for test_class in (ResolutionEngineTests, InterfaceHTTPTests, InterfaceBrowserTests):
        for name in sorted(test_class.__dict__):
            if name.startswith("test_"):
                suite.addTest(test_class(name))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
