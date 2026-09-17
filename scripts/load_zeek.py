#!/usr/bin/env python3
#
# Copyright (C) 2026 Ellis Huang
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. See the LICENSE file for the full text.
#
"""Load the APT29 Day 1 Zeek logs, aligned to the same demo morning as the host events.

Time alignment -- read this before changing it
----------------------------------------------
The build spec says to apply the host delta verbatim to Zeek. That assumes both
captures share a clock. They do not:

    host events : 2020-05-02 02:55:26Z .. 03:28:20Z  (~33 min)
    zeek logs   : 2020-04-30 00:06:38Z .. 00:45:00Z  (~38 min)

They are two views of the same intrusion recorded against clocks ~2 days apart.
Applying one delta to both puts the network traffic two days before the host
events -- precisely the timeline mismatch the spec was trying to avoid, and a
failure of the "zeek overlaps host, not a different day" acceptance check.

So both loaders share one ANCHOR (data/shift_delta.json), and each derives its
own delta from it, putting both streams at the same demo morning. Pass
--same-delta for the spec's literal behaviour.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ecs_mapper as em  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ZEEK_DIR = ROOT / "data" / "detection-hackathon-apt29" / "datasets" / "day1" / "zeek" / "individual_zeek_logs"
TEMPLATE = ROOT / "elastic" / "index-template-zeek.json"
TEMPLATE_NAME = "winlogbeat-apt29-zeek"
INDEX = "winlogbeat-apt29-zeek-day1"

CONN_STREAMS = {"conn"}


def put_template(es_url: str) -> None:
    body = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    r = requests.put(f"{es_url}/_index_template/{TEMPLATE_NAME}", json=body, timeout=60)
    r.raise_for_status()
    print(f"[zeek] index template '{TEMPLATE_NAME}' applied")


def recreate_index(es_url: str, index: str) -> None:
    requests.delete(f"{es_url}/{index}", timeout=120)
    r = requests.put(f"{es_url}/{index}", timeout=120)
    if r.status_code >= 300:
        sys.exit(f"[zeek] could not create {index}: {r.text}")
    print(f"[zeek] created index {index}")


def iter_events(paths: list[Path]):
    for path in paths:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield path, json.loads(line)
                except json.JSONDecodeError:
                    yield path, None


def map_zeek(event: dict, delta: timedelta, source_file: str) -> dict:
    doc = dict(event)
    stream = event.get("@stream") or "unknown"

    ts = event.get("ts")
    if isinstance(ts, (int, float)):
        original = datetime.fromtimestamp(ts, timezone.utc)
        shifted = original + delta
        doc["ts_original"] = ts
        doc["ts"] = shifted.timestamp()
        doc["@timestamp_original"] = em.format_iso8601_utc(original)
        doc["@timestamp"] = em.format_iso8601_utc(shifted)

    # e.g. http 'host' (Host header) and files 'source' (carrier protocol) collide
    # with the ECS host/source objects; preserved as <name>_raw.
    em.deconflict_raw_fields(doc)

    doc["ecs.version"] = em.ECS_VERSION
    doc["event.kind"] = "event"
    doc["event.module"] = "zeek"
    doc["event.dataset"] = f"zeek.{stream}"
    doc["agent.type"] = "zeek"
    doc["zeek.stream"] = stream
    doc["log.file.path"] = source_file
    if event.get("@system"):
        doc["observer.name"] = event["@system"]
        doc["observer.type"] = "ids"
    if event.get("uid"):
        doc["event.id"] = event["uid"]

    doc["event.category"] = ["network"]
    doc["event.type"] = ["connection"] if stream in CONN_STREAMS else ["protocol"]
    doc["event.action"] = stream

    for ecs_field, raw in (
        ("source.ip", "id_orig_h"),
        ("source.port", "id_orig_p"),
        ("destination.ip", "id_resp_h"),
        ("destination.port", "id_resp_p"),
    ):
        if event.get(raw) not in (None, ""):
            doc[ecs_field] = event[raw]

    if stream == "conn":
        if event.get("proto"):
            doc["network.transport"] = str(event["proto"]).lower()
        if event.get("service"):
            doc["network.protocol"] = str(event["service"]).lower()
        if isinstance(event.get("orig_bytes"), int):
            doc["source.bytes"] = event["orig_bytes"]
        if isinstance(event.get("resp_bytes"), int):
            doc["destination.bytes"] = event["resp_bytes"]
    elif stream == "dns":
        doc["network.protocol"] = "dns"
        if event.get("query"):
            doc["dns.question.name"] = event["query"]
        if event.get("qtype_name"):
            doc["dns.question.type"] = event["qtype_name"]
    elif stream == "http":
        doc["network.protocol"] = "http"
        if event.get("uri"):
            doc["url.original"] = event["uri"]
        if doc.get("host_raw"):
            doc["url.domain"] = doc["host_raw"]
        if event.get("method"):
            doc["http.request.method"] = event["method"]
        if event.get("user_agent"):
            doc["user_agent.original"] = event["user_agent"]
        if event.get("status_code") is not None:
            doc["http.response.status_code"] = event["status_code"]
    else:
        doc["network.protocol"] = stream

    return em.nest_ecs_fields(doc)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--zeek-dir", type=Path, default=DEFAULT_ZEEK_DIR)
    ap.add_argument("--es-url", default=os.environ.get("ES_URL", "http://localhost:9200"))
    ap.add_argument("--index", default=INDEX)
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument(
        "--same-delta",
        action="store_true",
        help="apply the host delta verbatim (spec literal); puts Zeek ~2 days before the host events",
    )
    ap.add_argument("--keep-index", action="store_true")
    args = ap.parse_args()

    if not args.zeek_dir.is_dir():
        sys.exit(f"[zeek] missing {args.zeek_dir} -- run 'make fetch' first")
    paths = sorted(args.zeek_dir.glob("*.log"))
    if not paths:
        sys.exit(f"[zeek] no .log files under {args.zeek_dir}")

    shift = em.read_shift_delta()
    host_delta = em.delta_from(shift)
    anchor_utc = em.parse_iso8601_utc(shift["anchor_utc"])
    print(f"[zeek] anchor {shift['anchor_local']} {shift['anchor_tz']} on {shift['anchor_date']} "
          f"(from {em.SHIFT_FILE.name})")

    # First pass: find the earliest Zeek observation so it can meet the anchor.
    zeek_min = None
    for _, event in iter_events(paths):
        if event and isinstance(event.get("ts"), (int, float)):
            ts = event["ts"]
            zeek_min = ts if zeek_min is None or ts < zeek_min else zeek_min
    if zeek_min is None:
        sys.exit("[zeek] no usable 'ts' values found")

    zeek_min_dt = datetime.fromtimestamp(zeek_min, timezone.utc)
    if args.same_delta:
        delta = host_delta
        print("[zeek] --same-delta: reusing the host delta verbatim")
    else:
        delta = anchor_utc - zeek_min_dt
        print(f"[zeek] zeek clock starts {em.format_iso8601_utc(zeek_min_dt)}, "
              f"host clock starts {shift['dataset_min_ts']}")
        print(f"[zeek] deriving a zeek delta from the shared anchor: {delta.total_seconds():.3f}s "
              f"(host delta {host_delta.total_seconds():.3f}s)")

    shift["zeek_min_ts"] = em.format_iso8601_utc(zeek_min_dt)
    shift["zeek_delta_seconds"] = delta.total_seconds()
    shift["zeek_same_delta_as_host"] = bool(args.same_delta)
    em.write_shift_delta(shift)

    put_template(args.es_url)
    if not args.keep_index:
        recreate_index(args.es_url, args.index)

    stats: collections.Counter = collections.Counter()
    streams: collections.Counter = collections.Counter()
    action = json.dumps({"index": {}}) + "\n"
    batch: list[str] = []

    def flush() -> None:
        if not batch:
            return
        r = requests.post(
            f"{args.es_url}/{args.index}/_bulk?refresh=false",
            data="".join(batch).encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            timeout=300,
        )
        if r.status_code >= 300:
            stats["failed"] += len(batch) // 2
            print(f"\n[zeek] bulk HTTP {r.status_code}: {r.text[:400]}", file=sys.stderr)
        else:
            body = r.json()
            if body.get("errors"):
                for item in body["items"]:
                    err = item.get("index", {}).get("error")
                    if err:
                        stats["failed"] += 1
                        if stats["failed"] <= 5:
                            print(f"\n[zeek] doc error: {err.get('type')}: {err.get('reason')[:300]}", file=sys.stderr)
                    else:
                        stats["indexed"] += 1
            else:
                stats["indexed"] += len(batch) // 2
        batch.clear()

    for path, event in iter_events(paths):
        if event is None:
            stats["unparsable"] += 1
            continue
        stats["read"] += 1
        doc = map_zeek(event, delta, path.name)
        streams[(doc.get("zeek", {}) or {}).get("stream")] += 1
        batch.append(action)
        batch.append(json.dumps(doc, ensure_ascii=False) + "\n")
        if len(batch) >= args.batch_size * 2:
            flush()
    flush()

    requests.post(f"{args.es_url}/{args.index}/_refresh", timeout=120)
    count = requests.get(f"{args.es_url}/{args.index}/_count", timeout=60).json().get("count")
    print(f"\n[zeek] read {stats['read']:,}  indexed {stats['indexed']:,}  "
          f"failed {stats['failed']:,}  unparsable {stats['unparsable']:,}")
    print(f"[zeek] index count {count:,}")
    print("[zeek] streams:")
    for stream, n in streams.most_common():
        print(f"    {stream:<14} {n:,}")
    return 1 if stats["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
