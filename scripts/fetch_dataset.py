#!/usr/bin/env python3
#
# Copyright (C) 2026 Ellis Huang
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. See the LICENSE file for the full text.
#
"""Fetch the OTRF detection-hackathon-apt29 dataset and unpack Day 1 host events.

Clones the repo shallowly (no git-lfs needed), extracts the Day 1 host JSONL and
verifies it byte-for-byte against the figures recorded in the build spec.
Verification is not cosmetic: every downstream count in scripts/verify.py is
derived from this exact file.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_URL = "https://github.com/OTRF/detection-hackathon-apt29"
REPO_DIR_NAME = "detection-hackathon-apt29"

DAY1_ZIP_REL = "datasets/day1/apt29_evals_day1_manual.zip"
DAY1_JSON_NAME = "apt29_evals_day1_manual_2020-05-01225525.json"
ZEEK_COMBINED_REL = "datasets/day1/zeek/combined_zeek.log"

EXPECTED_ZIP_BYTES = 13_944_972
EXPECTED_JSON_BYTES = 385_334_029
EXPECTED_JSON_LINES = 196_081
EXPECTED_ZEEK_BYTES = 1_243_861

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


def run(cmd: list[str]) -> None:
    print(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def clone_repo(repo_dir: Path, mirror_from: Path | None) -> None:
    if repo_dir.exists():
        print(f"[fetch] repo already present: {repo_dir}")
        return
    if mirror_from is not None:
        src = mirror_from.resolve()
        if not (src / DAY1_ZIP_REL).exists():
            sys.exit(f"[fetch] --mirror-from has no {DAY1_ZIP_REL}: {src}")
        print(f"[fetch] copying existing clone from {src}")
        shutil.copytree(src, repo_dir, ignore=shutil.ignore_patterns(".git"))
        return
    print(f"[fetch] cloning {REPO_URL} (shallow)")
    run(["git", "clone", "--depth", "1", REPO_URL, str(repo_dir)])


def check_size(path: Path, expected: int, label: str) -> bool:
    actual = path.stat().st_size
    ok = actual == expected
    mark = "OK " if ok else "BAD"
    print(f"  [{mark}] {label}: {actual:,} bytes (expected {expected:,})")
    return ok


def count_lines(path: Path) -> int:
    n = 0
    with path.open("rb") as fh:
        while chunk := fh.read(8 * 1024 * 1024):
            n += chunk.count(b"\n")
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--mirror-from",
        type=Path,
        default=None,
        help="path to an existing detection-hackathon-apt29 clone to copy instead of cloning",
    )
    ap.add_argument("--force", action="store_true", help="re-extract even if the JSON already exists")
    args = ap.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)
    repo_dir = DATA / REPO_DIR_NAME
    clone_repo(repo_dir, args.mirror_from)

    zip_path = repo_dir / DAY1_ZIP_REL
    if not zip_path.exists():
        sys.exit(f"[fetch] missing {zip_path}")

    json_path = DATA / DAY1_JSON_NAME
    if json_path.exists() and not args.force:
        print(f"[fetch] already extracted: {json_path}")
    else:
        print(f"[fetch] extracting {DAY1_JSON_NAME} -> {DATA}")
        with zipfile.ZipFile(zip_path) as zf:
            zf.extract(DAY1_JSON_NAME, DATA)

    print("[fetch] verifying")
    ok = True
    ok &= check_size(zip_path, EXPECTED_ZIP_BYTES, "day1 zip")
    ok &= check_size(json_path, EXPECTED_JSON_BYTES, "day1 host JSON")

    zeek = repo_dir / ZEEK_COMBINED_REL
    if zeek.exists():
        ok &= check_size(zeek, EXPECTED_ZEEK_BYTES, "zeek combined log")
    else:
        print(f"  [BAD] zeek combined log missing: {zeek}")
        ok = False

    lines = count_lines(json_path)
    line_ok = lines == EXPECTED_JSON_LINES
    print(f"  [{'OK ' if line_ok else 'BAD'}] day1 host JSON lines: {lines:,} (expected {EXPECTED_JSON_LINES:,})")
    ok &= line_ok

    if not ok:
        print("\n[fetch] FAILED verification - do not continue to load", file=sys.stderr)
        return 1
    print(f"\n[fetch] OK. Host events: {json_path}")
    print(f"[fetch] Zeek logs:   {repo_dir / 'datasets/day1/zeek'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
