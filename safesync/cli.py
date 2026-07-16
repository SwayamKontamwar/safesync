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
    result.add_argument("left", type=Path)
    result.add_argument("right", type=Path)
    result.add_argument("--dry-run", action="store_true")
    result.add_argument("--verbose", action="store_true")
    result.epilog = "named crash points: " + ", ".join(CRASH_POINTS)
    return result


def main() -> int:
    args = parser().parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )
    try:
        result = SyncEngine(args.left, args.right, dry_run=args.dry_run).sync()
    except (SafetyError, OSError, ValueError) as exc:
        logging.error("sync stopped safely: %s", exc)
        return 2
    print(json.dumps(asdict(result), sort_keys=True))
    return 0

