#!/usr/bin/env python3
#
# Copyright (C) 2026 Ellis Huang
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. See the LICENSE file for the full text.
#
"""Stream the APT29 Day 1 host events into Elasticsearch with an ECS overlay.

The source file is 385 MB of JSON Lines, so it is read line by line and pushed
in bulk batches; it is never loaded into memory whole.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ecs_mapper as em  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = ROOT / "data" / "apt29_evals_day1_manual_2020-05-01225525.json"
TEMPLATE = ROOT / "elastic" / "index-template-host.json"
TEMPLATE_NAME = "winlogbeat-apt29-host"
INDEX = "winlogbeat-apt29-host-day1"


def put_template(es_url: str) -> None:
    body = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    r = requests.put(f"{es_url}/_index_template/{TEMPLATE_NAME}", json=body, timeout=60)
    r.raise_for_status()
    print(f"[load] index template '{TEMPLATE_NAME}' applied")


def recreate_index(es_url: str, index: str) -> None:
    requests.delete(f"{es_url}/{index}", timeout=120)
    r = requests.put(f"{es_url}/{index}", timeout=120)
    if r.status_code >= 300:
        sys.exit(f"[load] could not create {index}: {r.text}")
    print(f"[load] created index {index}")


def bulk_send(es_url: str, index: str, lines: list[str], stats: collections.Counter) -> None:
    payload = "".join(lines)
    r = requests.post(
        f"{es_url}/{index}/_bulk?refresh=false",
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        timeout=300,
    )
    if r.status_code >= 300:
        stats["failed"] += len(lines) // 2
        print(f"\n[load] bulk HTTP {r.status_code}: {r.text[:500]}", file=sys.stderr)
        return
    body = r.json()
    if body.get("errors"):
        for item in body["items"]:
            err = item.get("index", {}).get("error")
            if err:
                stats["failed"] += 1
                if stats["failed"] <= 5:
                    print(f"\n[load] doc error: {err.get('type')}: {err.get('reason')[:300]}", file=sys.stderr)
            else:
                stats["indexed"] += 1
    else:
        stats["indexed"] += len(lines) // 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC)
    ap.add_argument("--es-url", default=os.environ.get("ES_URL", "http://localhost:9200"))
    ap.add_argument("--index", default=INDEX)
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument("--limit", type=int, default=0, help="stop after N events (smoke tests)")
    ap.add_argument(
        "--skip-eid",
        type=int,
        action="append",
        default=[],
        help="do not index this Sysmon EventID at all (repeatable)",
    )
    ap.add_argument(
        "--ecs-process-eid",
        type=int,
        action="append",
        default=[],
        help=f"additionally emit process.entity_id for this EventID. "
             f"Off by default for {sorted(em.TOGGLEABLE_EIDS)} because they dominate the "
             f"dataset and swamp the analyzer graph (repeatable)",
    )
    ap.add_argument("--anchor-local", default=None, help="HH:MM (default $ANCHOR_LOCAL or 09:00)")
    ap.add_argument("--anchor-tz", default=None, help="tz name (default $ANCHOR_TZ or Asia/Taipei)")
    ap.add_argument("--anchor-date", default=None,
                    help="YYYY-MM-DD to pin every install to the same timeline, "
                         "or 'today' (default $ANCHOR_DATE)")
    ap.add_argument("--keep-index", action="store_true", help="append instead of recreating the index")
    args = ap.parse_args()

    if not args.src.exists():
        sys.exit(f"[load] missing {args.src} -- run 'make fetch' first")

    shift = em.compute_delta(args.anchor_local, args.anchor_tz, args.anchor_date)
    em.write_shift_delta(shift)
    delta = em.delta_from(shift)
    print(f"[load] anchor {shift['anchor_date']} {shift['anchor_local']} {shift['anchor_tz']} "
          f"({'fixed date' if shift['anchor_date_is_fixed'] else 'today'}) "
          f"-> delta {shift['delta_seconds']:.3f}s")
    print(f"[load] wrote {em.SHIFT_FILE.relative_to(ROOT)} (the Zeek loader reuses this)")

    ecs_process_eids = em.DEFAULT_ECS_PROCESS_EIDS | frozenset(args.ecs_process_eid)
    skip = set(args.skip_eid)
    if args.ecs_process_eid:
        print(f"[load] ECS process mapping additionally enabled for EID {sorted(args.ecs_process_eid)}")
    if skip:
        print(f"[load] skipping EID {sorted(skip)} entirely")

    put_template(args.es_url)
    if not args.keep_index:
        recreate_index(args.es_url, args.index)

    stats: collections.Counter = collections.Counter()
    categories: collections.Counter = collections.Counter()
    action = json.dumps({"index": {}}) + "\n"
    batch: list[str] = []
    started = time.time()

    with args.src.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                stats["unparsable"] += 1
                continue

            stats["read"] += 1
            if event.get("EventID") in skip and "Sysmon" in str(event.get("Channel", "")):
                stats["skipped"] += 1
                continue

            doc = em.map_event(event, delta, ecs_process_eids, event_id=f"{lineno:07d}")

            # map_event() already moved raw scalars that collide with an ECS
            # object (host -> host_raw) and nested the ECS fields.
            for cat in (doc.get("event", {}) or {}).get("category", []) or []:
                categories[cat] += 1
            if (doc.get("process", {}) or {}).get("entity_id"):
                stats["with_entity_id"] += 1

            batch.append(action)
            batch.append(json.dumps(doc, ensure_ascii=False) + "\n")

            if len(batch) >= args.batch_size * 2:
                bulk_send(args.es_url, args.index, batch, stats)
                batch.clear()
                done = stats["indexed"] + stats["failed"]
                rate = done / max(time.time() - started, 0.001)
                print(f"\r[load] {done:,} indexed  ({rate:,.0f}/s)", end="", flush=True)

            if args.limit and stats["read"] >= args.limit:
                break

    if batch:
        bulk_send(args.es_url, args.index, batch, stats)

    print(f"\r[load] flushing...{' ' * 30}")
    requests.post(f"{args.es_url}/{args.index}/_refresh", timeout=300)
    elapsed = time.time() - started

    count = requests.get(f"{args.es_url}/{args.index}/_count", timeout=60).json().get("count")
    print(f"\n[load] done in {elapsed:,.0f}s")
    print(f"  read         : {stats['read']:,}")
    print(f"  indexed      : {stats['indexed']:,}")
    print(f"  failed       : {stats['failed']:,}")
    print(f"  skipped      : {stats['skipped']:,}")
    print(f"  unparsable   : {stats['unparsable']:,}")
    print(f"  entity_id set: {stats['with_entity_id']:,}")
    print(f"  index count  : {count:,}")
    print("  event.category:")
    for cat, n in categories.most_common():
        print(f"    {cat:<12} {n:,}")
    return 1 if stats["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
