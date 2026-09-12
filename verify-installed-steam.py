#!/usr/bin/env python3
"""Check file types and sizes from Steam's installed bootstrap manifest."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    failures: list[str] = []
    checked = 0

    with args.manifest.open("r", encoding="utf-8") as manifest:
        for line_number, raw_line in enumerate(manifest, 1):
            line = raw_line.rstrip("\n")
            if not line:
                continue
            # Valve appends key=value metadata after the path table.
            if "," not in line and "=" in line:
                continue
            try:
                relative, metadata = line.rsplit(",", 1)
                expected_size = int(metadata.split(";", 1)[0])
            except (ValueError, IndexError):
                failures.append(f"line {line_number}: malformed entry")
                continue

            target = args.root / relative
            checked += 1
            if expected_size == -1:
                if not target.is_dir():
                    failures.append(f"{relative}: directory missing")
                continue
            try:
                target_stat = os.lstat(target)
            except FileNotFoundError:
                failures.append(f"{relative}: file missing")
                continue
            if expected_size == -2:
                if not stat.S_ISLNK(target_stat.st_mode):
                    failures.append(f"{relative}: symlink missing")
                continue
            if not stat.S_ISREG(target_stat.st_mode):
                failures.append(f"{relative}: not a regular file")
            elif target_stat.st_size != expected_size:
                failures.append(
                    f"{relative}: size {target_stat.st_size}, expected {expected_size}"
                )

    if failures:
        print(f"FAILED: {len(failures)} of {checked} entries did not match")
        for failure in failures[:100]:
            print(f"  {failure}")
        if len(failures) > 100:
            print(f"  ... and {len(failures) - 100} more")
        return 1

    print(f"OK: all {checked} manifest entries match file types and sizes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
