from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict
from pathlib import Path

from .engine import CRASH_POINTS, SyncEngine
from .filesystem import SafetyError
from .watcher import WatchService


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="safesync")
    result.add_argument("--verbose", action="store_true", help="emit operation details")
    commands = result.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("init", "bind and initialize a root pair without copying files"),
        ("sync", "recover pending work and synchronize the root pair"),
        ("dry-run", "plan synchronization without changing either root"),
        ("inspect", "show state, journal, conflict, and temporary-file status"),
        ("recover", "recover pending work and finish the interrupted synchronization"),
        ("delete", "confirm an already-performed deletion and synchronize it"),
        ("watch", "watch both roots and reconcile settled changes continuously"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("left", type=Path)
        command.add_argument("right", type=Path)
        if name == "delete":
            command.add_argument("side", choices=("left", "right"))
            command.add_argument("path")
        if name == "watch":
            command.add_argument("--settle", type=float, default=1.0)
            command.add_argument("--full-scan", type=float, default=30.0)
    result.epilog = "named crash points: " + ", ".join(CRASH_POINTS)
    return result


def main() -> int:
    args = parser().parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )
    try:
        engine = SyncEngine(args.left, args.right, dry_run=args.command == "dry-run")
        if args.command == "watch":
            WatchService(args.left, args.right, settle_seconds=args.settle, full_scan_seconds=args.full_scan).run()
            return 0
        if args.command == "init":
            output = {"initialized": engine.initialize()}
        elif args.command == "inspect":
            output = asdict(engine.inspect())
        elif args.command == "recover":
            output = asdict(engine.recover())
        elif args.command == "delete":
            intent = engine.confirm_deletion(args.side, args.path)
            output = {"intent": intent.to_dict(), "result": asdict(engine.sync())}
        else:
            output = asdict(engine.sync())
    except (SafetyError, OSError, ValueError) as exc:
        logging.error("sync stopped safely: %s", exc)
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0
