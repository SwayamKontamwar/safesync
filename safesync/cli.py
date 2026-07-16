from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict
from pathlib import Path

from .engine import CRASH_POINTS, SyncEngine
from .filesystem import SafetyError


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
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("left", type=Path)
        command.add_argument("right", type=Path)
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
        if args.command == "init":
            output = {"initialized": engine.initialize()}
        elif args.command == "inspect":
            output = asdict(engine.inspect())
        elif args.command == "recover":
            output = asdict(engine.recover())
        else:
            output = asdict(engine.sync())
    except (SafetyError, OSError, ValueError) as exc:
        logging.error("sync stopped safely: %s", exc)
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0
