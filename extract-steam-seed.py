#!/usr/bin/env python3

import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import zipfile


def safe_target(root: Path, archive_name: str) -> Path:
    normalized = archive_name.replace("\\", "/")
    relative = PurePosixPath(normalized)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe archive path: {archive_name!r}")

    target = root.joinpath(*relative.parts)
    target.resolve().relative_to(root.resolve())
    return target


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ARCHIVE DESTINATION", file=sys.stderr)
        return 2

    archive = Path(sys.argv[1]).resolve()
    destination = Path(sys.argv[2]).resolve()
    destination.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive) as source:
        for entry in source.infolist():
            target = safe_target(destination, entry.filename)
            normalized = entry.filename.replace("\\", "/")
            mode = (entry.external_attr >> 16) & 0xFFFF
            if entry.is_dir() or normalized.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            if stat.S_ISLNK(mode):
                link_value = source.read(entry).decode("utf-8")
                link_target = PurePosixPath(link_value)
                if link_target.is_absolute():
                    raise ValueError(f"unsafe absolute symlink: {entry.filename!r}")
                (target.parent / link_target).resolve().relative_to(destination.resolve())
                target.symlink_to(link_value)
                continue

            with source.open(entry) as input_file, target.open("wb") as output_file:
                shutil.copyfileobj(input_file, output_file)
            if mode:
                target.chmod(mode & 0o777)

    for path in destination.rglob("*"):
        if not path.is_file():
            continue
        result = subprocess.run(
            ["file", "-b", str(path)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
        )
        if "interpreter /lib/ld-linux" in result.stdout or result.stdout.startswith(
            ("POSIX shell script", "Python script")
        ):
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
