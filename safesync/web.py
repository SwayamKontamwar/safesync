from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlparse

from .engine import SyncEngine
from .filesystem import SafetyError
from .watcher import WatchService


class WatchController:
    def __init__(self, left: Path, right: Path) -> None:
        self.left = left
        self.right = right
        self._lock = threading.Lock()
        self._service: WatchService | None = None
        self._thread: threading.Thread | None = None
        self._stop: threading.Event | None = None
        self._error: str | None = None

    def start(self, settle: float = 1.0, full_scan: float = 30.0) -> bool:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            service = WatchService(self.left, self.right, settle_seconds=settle, full_scan_seconds=full_scan)
            stop = threading.Event()
            ready = threading.Event()

            def run() -> None:
                try:
                    service.run(stop, ready)
                except Exception as exc:
                    self._error = str(exc)

            thread = threading.Thread(target=run, name="safesync-watch", daemon=True)
            self._service = service
            self._stop = stop
            self._thread = thread
            self._error = None
            thread.start()
        if not ready.wait(timeout=10):
            self.stop()
            raise SafetyError(self._error or "watch service did not become ready")
        return True

    def stop(self) -> bool:
        with self._lock:
            thread = self._thread
            stop = self._stop
            if not thread or not thread.is_alive():
                return False
            if stop:
                stop.set()
        thread.join(timeout=15)
        if thread.is_alive():
            raise SafetyError("watch service did not stop")
        return True

    def snapshot(self) -> dict:
        with self._lock:
            running = bool(self._thread and self._thread.is_alive())
            events = self._service.recent_events() if self._service else []
            return {"running": running, "error": self._error, "events": events[-200:]}


class SafeSyncHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, engine: SyncEngine, watcher: WatchController, token: str) -> None:
        super().__init__(address, SafeSyncHandler)
        self.engine = engine
        self.watcher = watcher
        self.token = token


class SafeSyncHandler(BaseHTTPRequestHandler):
    server: SafeSyncHTTPServer

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/status":
            self._api(self._status)
            return
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }
        asset = assets.get(path)
        if asset is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        name, content_type = asset
        data = files("safesync.static").joinpath(name).read_bytes()
        if name == "index.html":
            data = data.replace(b"__SAFESYNC_TOKEN__", self.server.token.encode("ascii"))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if self.headers.get("X-SafeSync-Token") != self.server.token:
            self._json(HTTPStatus.FORBIDDEN, {"error": "invalid interface token"})
            return
        path = urlparse(self.path).path
        routes = {
            "/api/sync": self._sync,
            "/api/watch/start": self._watch_start,
            "/api/watch/stop": self._watch_stop,
        }
        if path.startswith("/api/conflicts/") and path.endswith("/resolve"):
            conflict_id = path.split("/")[3]
            self._api(lambda: self._resolve(conflict_id))
            return
        action = routes.get(path)
        if action is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
            return
        self._api(action)

    def _api(self, action) -> None:
        try:
            self._json(HTTPStatus.OK, action())
        except (SafetyError, OSError, ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})

    def _status(self) -> dict:
        result = self.server.engine.dashboard_snapshot()
        result["watch"] = self.server.watcher.snapshot()
        return result

    def _sync(self) -> dict:
        return {"result": asdict(self.server.engine.sync()), "status": self._status()}

    def _resolve(self, conflict_id: str) -> dict:
        body = self._body()
        result = self.server.engine.resolve_conflict(conflict_id, body.get("choice", ""))
        return {"result": asdict(result), "status": self._status()}

    def _watch_start(self) -> dict:
        body = self._body()
        settle = float(body.get("settle", 1.0))
        full_scan = float(body.get("full_scan", 30.0))
        if settle <= 0 or full_scan <= 0:
            raise ValueError("watch intervals must be positive")
        self.server.watcher.start(settle, full_scan)
        return self._status()

    def _watch_stop(self) -> dict:
        self.server.watcher.stop()
        return self._status()

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 16384:
            raise ValueError("request body is too large")
        if length == 0:
            return {}
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _json(self, status: HTTPStatus, value: dict) -> None:
        data = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def create_server(left: Path, right: Path, port: int = 0) -> SafeSyncHTTPServer:
    engine = SyncEngine(left, right)
    engine.initialize()
    engine.recover()
    watcher = WatchController(engine.roots.left, engine.roots.right)
    return SafeSyncHTTPServer(("127.0.0.1", port), engine, watcher, secrets.token_urlsafe(32))


def serve_ui(left: Path, right: Path, port: int = 0, *, open_browser: bool = True) -> None:
    server = create_server(left, right, port)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(url, flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.watcher.stop()
        server.server_close()
