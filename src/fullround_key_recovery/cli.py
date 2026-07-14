"""Command-line interface for retained-evidence verification."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .verify import VERIFY_FUNCTIONS, verify_all, verify_result


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Verify retained complete-domain and strict-subset full-round recoveries."
    )
    parser.add_argument(
        "result",
        nargs="?",
        choices=("all", *VERIFY_FUNCTIONS),
        default="all",
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    value = verify_all(args.root) if args.result == "all" else verify_result(args.result, args.root)
    print(json.dumps(value, indent=2 if args.pretty else None, sort_keys=True))


if __name__ == "__main__":
    main()
