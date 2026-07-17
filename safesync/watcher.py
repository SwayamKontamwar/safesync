from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler, FileSystemMovedEvent
from watchdog.observers import Observer

from .engine import SyncEngine
from .filesystem import CONTROL_DIRECTORY, SafetyError

LOGGER = logging.getLogger("safesync")


@dataclass(frozen=True)
class WatchEvent:
    side: str
    kind: str
    source: str
    destination: str | None = None


class _Handler(FileSystemEventHandler):
    def __init__(self, side: str, root: Path, events: queue.Queue[WatchEvent]) -> None:
        self.side = side
        self.root = root
        self.events = events

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory and event.event_type not in {"moved", "deleted"}:
            return
        source = self._relative(event.src_path)
        if source is None:
            return
        destination = None
        if isinstance(event, FileSystemMovedEvent):
            destination = self._relative(event.dest_path)
        self.events.put(WatchEvent(self.side, event.event_type, source, destination))

    def _relative(self, raw_path: str) -> str | None:
        try:
            relative = Path(raw_path).resolve(strict=False).relative_to(self.root).as_posix()
        except ValueError:
            return None
        parts = Path(relative).parts
        if not parts or parts[0] == CONTROL_DIRECTORY or Path(relative).name.startswith(".safesync-tmp-"):
            return None
        return relative


class WatchService:
    def __init__(
        self, left: Path, right: Path, *, settle_seconds: float = 1.0, full_scan_seconds: float = 30.0
    ) -> None:
        self.engine = SyncEngine(left, right)
        self.settle_seconds = settle_seconds
        self.full_scan_seconds = full_scan_seconds
        self.events: queue.Queue[WatchEvent] = queue.Queue()
        self._force_full_scan = threading.Event()
        self._history: deque[dict] = deque(maxlen=500)
        self._history_lock = threading.Lock()

    def recent_events(self) -> list[dict]:
        with self._history_lock:
            return list(self._history)

    def notify_overflow(self) -> None:
        LOGGER.warning("filesystem event stream overflowed; scheduling full reconciliation")
        self._force_full_scan.set()

    def run(
        self,
        stop_event: threading.Event | None = None,
        ready_event: threading.Event | None = None,
    ) -> None:
        stop = stop_event or threading.Event()
        self.engine.initialize()
        self.engine.recover()
        observer = Observer()
        observer.schedule(_Handler("left", self.engine.roots.left, self.events), str(self.engine.roots.left), recursive=True)
        observer.schedule(_Handler("right", self.engine.roots.right, self.events), str(self.engine.roots.right), recursive=True)
        observer.start()
        if ready_event is not None:
            ready_event.set()
        deletion_candidates: dict[tuple[str, str], float] = {}
        dirty_at: float | None = None
        last_scan = time.monotonic()
        try:
            while not stop.wait(0.1):
                now = time.monotonic()
                while True:
                    try:
                        event = self.events.get_nowait()
                    except queue.Empty:
                        break
                    with self._history_lock:
                        self._history.append({
                            "timestamp_ns": time.time_ns(),
                            "side": event.side,
                            "kind": event.kind,
                            "source": event.source,
                            "destination": event.destination,
                        })
                    dirty_at = now
                    if event.kind == "deleted":
                        deletion_candidates[(event.side, event.source)] = now
                    elif event.kind == "moved":
                        deletion_candidates.pop((event.side, event.source), None)
                        if event.destination:
                            deletion_candidates.pop((event.side, event.destination), None)
                    else:
                        deletion_candidates.pop((event.side, event.source), None)

                settled = dirty_at is not None and now - dirty_at >= self.settle_seconds
                periodic = now - last_scan >= self.full_scan_seconds
                forced = self._force_full_scan.is_set()
                if dirty_at is not None and not settled:
                    continue
                if not (settled or periodic or forced):
                    continue

                for key, observed_at in list(deletion_candidates.items()):
                    if now - observed_at < self.settle_seconds:
                        continue
                    side, relative = key
                    path = self.engine.roots.get(side) / Path(relative)
                    if path.exists():
                        deletion_candidates.pop(key, None)
                        continue
                    try:
                        self.engine.confirm_deletion(side, relative, evidence="watch-delete-settled")
                    except SafetyError as exc:
                        LOGGER.info("deletion not confirmed path=%s reason=%s", relative, exc)
                    deletion_candidates.pop(key, None)
                try:
                    self.engine.sync()
                except (SafetyError, OSError) as exc:
                    LOGGER.warning("watch reconciliation deferred: %s", exc)
                    try:
                        self.engine.abandon_stale_prepared_copies()
                    except (SafetyError, OSError) as cleanup_exc:
                        LOGGER.warning("stale prepared operation retained: %s", cleanup_exc)
                    dirty_at = now
                else:
                    dirty_at = None
                last_scan = now
                self._force_full_scan.clear()
        finally:
            observer.stop()
            observer.join(timeout=10)
