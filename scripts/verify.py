#!/usr/bin/env python3
"""Acceptance checks. If any of these fail, stop and fix before building dashboards.

Every expected number here was counted from the actual dataset file, not taken
from the OTRF repo's own README (which disagrees with its data).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ecs_mapper as em  # noqa: E402

HOST_INDEX = "winlogbeat-apt29-host-day1"
ZEEK_INDEX = "winlogbeat-apt29-zeek-day1"

EXPECTED_TOTAL = 196_081
EXPECTED_HOSTS = {
    "SCRANTON.dmevals.local": 131_119,
    "NASHUA.dmevals.local": 29_056,
    "NEWYORK.dmevals.local": 23_935,
    "UTICA.dmevals.local": 11_971,
}
EXPECTED_SECURITY = 41_002          # 28,627 "Security" + 12,375 "security"
EXPECTED_SYSMON = 143_884
EXPECTED_SYSMON_EIDS = {1: 447, 10: 39_283, 12: 61_151}
EXPECTED_PROCESS_STARTS = 446       # 447 EID 1 minus the one with no GUIDs
MIN_PARENT_RESOLUTION = 0.70        # measured: 73.3%


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checks = 0
        self.skipped = 0

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        self.checks += 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' -- ' + detail) if detail else ''}")
        if not ok:
            self.failures.append(label)
        return ok

    def skip(self, label: str, why: str) -> None:
        self.skipped += 1
        print(f"  [SKIP] {label} -- {why}")

    def section(self, name: str) -> None:
        print(f"\n[{name}]")


def es_count(es: str, index: str, query: dict | None = None) -> int:
    body = {"query": query} if query else {}
    r = requests.post(f"{es}/{index}/_count", json=body, timeout=120)
    r.raise_for_status()
    return r.json()["count"]


def es_search(es: str, index: str, body: dict) -> dict:
    r = requests.post(f"{es}/{index}/_search", json=body, timeout=180)
    r.raise_for_status()
    return r.json()


def terms_agg(es: str, index: str, field: str, size: int = 20) -> dict:
    body = {"size": 0, "aggs": {"t": {"terms": {"field": field, "size": size}}}}
    buckets = es_search(es, index, body)["aggregations"]["t"]["buckets"]
    return {b["key"]: b["doc_count"] for b in buckets}


def minmax(es: str, index: str, field: str) -> tuple[str | None, str | None]:
    body = {
        "size": 0,
        "aggs": {
            "mn": {"min": {"field": field, "format": "strict_date_optional_time"}},
            "mx": {"max": {"field": field, "format": "strict_date_optional_time"}},
        },
    }
    agg = es_search(es, index, body)["aggregations"]
    return agg["mn"].get("value_as_string"), agg["mx"].get("value_as_string")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--es-url", default=os.environ.get("ES_URL", "http://localhost:9200"))
    ap.add_argument("--no-zeek", action="store_true",
                    help="the lab was built without Zeek network logs; skip those checks")
    args = ap.parse_args()
    es = args.es_url
    c = Checker()
    check_zeek = not args.no_zeek

    try:
        requests.get(es, timeout=10).raise_for_status()
    except Exception as exc:
        sys.exit(f"Elasticsearch not reachable at {es}: {exc}")

    # ------------------------------------------------------------------ ingest
    c.section("ingest")
    total = es_count(es, HOST_INDEX)
    c.check(total == EXPECTED_TOTAL, f"{HOST_INDEX} total docs", f"{total:,} (expect {EXPECTED_TOTAL:,})")

    hosts = terms_agg(es, HOST_INDEX, "Hostname")
    for name, expected in EXPECTED_HOSTS.items():
        got = hosts.get(name, 0)
        c.check(got == expected, f"Hostname {name}", f"{got:,} (expect {expected:,})")

    sec = es_count(es, HOST_INDEX, {"term": {"Channel": "Security"}})
    c.check(sec == EXPECTED_SECURITY, "normalised Channel:Security",
            f"{sec:,} (expect {EXPECTED_SECURITY:,} = 28,627 + 12,375 lowercase)")
    lower = es_count(es, HOST_INDEX, {"term": {"Channel": "security"}})
    c.check(lower == 0, "no lowercase 'security' Channel left", f"{lower:,}")
    raw_kept = es_count(es, HOST_INDEX, {"term": {"Channel_raw": "security"}})
    c.check(raw_kept == 12_375, "original case preserved in Channel_raw", f"{raw_kept:,} (expect 12,375)")

    sysmon = es_count(es, HOST_INDEX, {"term": {"Channel": "Microsoft-Windows-Sysmon/Operational"}})
    c.check(sysmon == EXPECTED_SYSMON, "Channel:Microsoft-Windows-Sysmon/Operational",
            f"{sysmon:,} (expect {EXPECTED_SYSMON:,})")

    for eid, expected in EXPECTED_SYSMON_EIDS.items():
        got = es_count(es, HOST_INDEX, {"bool": {"filter": [
            {"term": {"Channel": "Microsoft-Windows-Sysmon/Operational"}},
            {"term": {"EventID": eid}}]}})
        c.check(got == expected, f"Sysmon EID {eid}", f"{got:,} (expect {expected:,})")

    omn, omx = minmax(es, HOST_INDEX, "@timestamp_original")
    c.check(omn is not None and omn.startswith("2020-05-02T02:55:26.493"),
            "@timestamp_original min", f"{omn}")
    c.check(omx is not None and omx.startswith("2020-05-02T03:28:20.170"),
            "@timestamp_original max", f"{omx}")

    # -------------------------------------------------------------- time shift
    c.section("time shift")
    shift = em.read_shift_delta()
    tz = ZoneInfo(shift["anchor_tz"])
    anchor_dt = em.parse_iso8601_utc(shift["anchor_utc"])

    smn, smx = minmax(es, HOST_INDEX, "@timestamp")
    smn_dt, smx_dt = em.parse_iso8601_utc(smn), em.parse_iso8601_utc(smx)
    drift = abs((smn_dt - anchor_dt).total_seconds())
    c.check(drift <= 1.0, f"host @timestamp min == anchor {shift['anchor_local']} {shift['anchor_tz']}",
            f"{smn_dt.astimezone(tz):%Y-%m-%d %H:%M:%S %Z} (drift {drift:.3f}s)")

    lo, hi = anchor_dt + timedelta(minutes=30), anchor_dt + timedelta(minutes=35)
    c.check(lo <= smx_dt <= hi, "host @timestamp max within anchor+30..35 min",
            f"{smx_dt.astimezone(tz):%Y-%m-%d %H:%M:%S %Z}")

    if check_zeek:
        zmn, zmx = minmax(es, ZEEK_INDEX, "@timestamp")
        zmn_dt, zmx_dt = em.parse_iso8601_utc(zmn), em.parse_iso8601_utc(zmx)
        same_day = zmn_dt.astimezone(tz).date() == smn_dt.astimezone(tz).date()
        c.check(same_day, "zeek @timestamp lands on the same local day as host",
                f"zeek {zmn_dt.astimezone(tz):%Y-%m-%d %H:%M:%S} .. {zmx_dt.astimezone(tz):%H:%M:%S}")
        overlaps = zmn_dt <= smx_dt and smn_dt <= zmx_dt
        c.check(overlaps, "zeek and host time ranges overlap",
                f"host {smn_dt.astimezone(tz):%H:%M:%S}-{smx_dt.astimezone(tz):%H:%M:%S}, "
                f"zeek {zmn_dt.astimezone(tz):%H:%M:%S}-{zmx_dt.astimezone(tz):%H:%M:%S}")
    else:
        c.skip("zeek time alignment", "lab built without Zeek")

    # EventTime is endpoint-local (UTC-4) and must stay that way after shifting.
    hit = es_search(es, HOST_INDEX, {"size": 1, "query": {"bool": {"filter": [
        {"exists": {"field": "EventTime"}}, {"exists": {"field": "UtcTime"}}]}},
        "_source": ["UtcTime", "EventTime", "UtcTime_original", "EventTime_original"]})["hits"]["hits"]
    if hit:
        src = hit[0]["_source"]
        utc = datetime.strptime(src["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")
        local = datetime.strptime(src["EventTime"], "%Y-%m-%d %H:%M:%S")
        offset = (utc - local).total_seconds() / 3600
        c.check(3.9 <= offset <= 4.1, "EventTime keeps its UTC-4 endpoint offset after shifting",
                f"UtcTime {src['UtcTime']} vs EventTime {src['EventTime']} = {offset:.2f}h")
        c.check(bool(src.get("UtcTime_original") and src.get("EventTime_original")),
                "original time values preserved", f"{src.get('UtcTime_original')}")

    # --------------------------------------------------------------------- ECS
    c.section("ECS")
    with_entity = es_count(es, HOST_INDEX, {"exists": {"field": "process.entity_id"}})
    c.check(with_entity > 0, "docs with process.entity_id", f"{with_entity:,}")

    starts = es_count(es, HOST_INDEX, {"bool": {"filter": [
        {"term": {"event.category": "process"}}, {"term": {"event.type": "start"}}]}})
    c.check(starts == EXPECTED_PROCESS_STARTS, "event.category:process AND event.type:start",
            f"{starts:,} (expect {EXPECTED_PROCESS_STARTS:,})")

    both = es_count(es, HOST_INDEX, {"bool": {"filter": [
        {"term": {"event.category": "process"}}, {"term": {"event.type": "start"}},
        {"exists": {"field": "process.entity_id"}}, {"exists": {"field": "process.parent.entity_id"}}]}})
    c.check(both == EXPECTED_PROCESS_STARTS, "all process starts have entity_id AND parent.entity_id",
            f"{both:,}/{starts:,}")

    # Parent resolution: how many parents exist as a process.entity_id in the index.
    page = es_search(es, HOST_INDEX, {"size": 0, "query": {"bool": {"filter": [
        {"term": {"event.category": "process"}}, {"term": {"event.type": "start"}}]}},
        "aggs": {"p": {"terms": {"field": "process.parent.entity_id", "size": 1000}}}})
    parents = [b["key"] for b in page["aggregations"]["p"]["buckets"]]
    counts = {b["key"]: b["doc_count"] for b in page["aggregations"]["p"]["buckets"]}
    # A parent only becomes a full node in the analyzer graph if it has its own
    # process-start event, so resolution is measured against those, not against
    # any event that merely carries the same entity_id.
    known_starts, known_any = set(), set()
    for i in range(0, len(parents), 500):
        chunk = parents[i:i + 500]
        res = es_search(es, HOST_INDEX, {"size": 0, "query": {"bool": {"filter": [
            {"terms": {"process.entity_id": chunk}},
            {"term": {"event.category": "process"}}, {"term": {"event.type": "start"}}]}},
            "aggs": {"g": {"terms": {"field": "process.entity_id", "size": 1000}}}})
        known_starts |= {b["key"] for b in res["aggregations"]["g"]["buckets"]}
        res = es_search(es, HOST_INDEX, {"size": 0, "query": {"terms": {"process.entity_id": chunk}},
                                         "aggs": {"g": {"terms": {"field": "process.entity_id", "size": 1000}}}})
        known_any |= {b["key"] for b in res["aggregations"]["g"]["buckets"]}
    resolved = sum(n for guid, n in counts.items() if guid in known_starts)
    resolved_any = sum(n for guid, n in counts.items() if guid in known_any)
    ratio = resolved / starts if starts else 0
    c.check(ratio >= MIN_PARENT_RESOLUTION, "parent GUID resolves to another process start",
            f"{resolved}/{starts} = {ratio:.1%} (need >= {MIN_PARENT_RESOLUTION:.0%}, measured 73.3%); "
            f"the rest pre-date collection. {resolved_any}/{starts} = {resolved_any / starts:.1%} "
            f"resolve to any event carrying that entity_id")

    # No empty values in the four ECS fields that must never be blank.
    for field in ("ecs.version", "event.kind", "event.category", "event.type"):
        present = es_count(es, HOST_INDEX, {"exists": {"field": field}})
        blank = es_count(es, HOST_INDEX, {"bool": {
            "filter": [{"exists": {"field": field}}], "must": [{"term": {field: ""}}]}})
        c.check(blank == 0, f"{field} has no empty values", f"{present:,} docs populated, {blank} blank")

    for field in ("ecs.version", "event.kind"):
        n = es_count(es, HOST_INDEX, {"exists": {"field": field}})
        c.check(n == total, f"{field} present on every doc", f"{n:,}/{total:,}")

    # ----------------------------------------------------------------- mapping
    c.section("mapping")
    r = requests.get(f"{es}/{HOST_INDEX}/_mapping/field/process.entity_id,process.parent.entity_id", timeout=60)
    fields = list(r.json().values())[0]["mappings"]
    for field in ("process.entity_id", "process.parent.entity_id"):
        leaf = field.rsplit(".", 1)[-1]
        ftype = fields.get(field, {}).get("mapping", {}).get(leaf, {}).get("type")
        c.check(ftype == "keyword", f"{field} mapped as keyword", f"got '{ftype}' (text would silently break the analyzer)")

    # The event analyzer sorts its node-detail queries on (@timestamp, event.id).
    # With event.id unmapped that sort throws, and every node in the graph shows
    # "Node details were unable to be retrieved" while the graph still draws --
    # so this is invisible unless you click a node.
    eid_mapped = requests.get(f"{es}/{HOST_INDEX}/_mapping/field/event.id", timeout=60).json()
    has_field = bool(list(eid_mapped.values())[0]["mappings"]) if eid_mapped else False
    c.check(has_field, "event.id is mapped", "required by the analyzer's node-detail sort")

    sort_probe = requests.post(
        f"{es}/{HOST_INDEX}/_search",
        json={"size": 1, "sort": [{"@timestamp": "asc"}, {"event.id": "asc"}]}, timeout=60)
    c.check(sort_probe.status_code < 300, "sorting on (@timestamp, event.id) works",
            "the analyzer node-detail query uses exactly this sort")

    with_id = es_count(es, HOST_INDEX, {"exists": {"field": "event.id"}})
    c.check(with_id == total, "event.id present on every doc", f"{with_id:,}/{total:,}")

    uniq = es_search(es, HOST_INDEX, {"size": 0, "aggs": {"u": {"cardinality": {
        "field": "event.id", "precision_threshold": 40000}}}})["aggregations"]["u"]["value"]
    c.check(abs(uniq - total) <= total * 0.01, "event.id is unique per document",
            f"~{uniq:,} distinct of {total:,} (approximate count)")

    # ECS fields must be nested objects in _source, not flat dotted keys.
    # Elasticsearch resolves "process.entity_id" as a path at query time either
    # way, so every query above still passes with flat keys -- but Kibana's
    # Security app reads _source in the browser as `event.process?.entity_id`.
    # With flat keys the analyzer graph draws and then every node reports
    # "Node details were unable to be retrieved".
    doc = es_search(es, HOST_INDEX, {"size": 1, "query": {"bool": {"filter": [
        {"term": {"event.category": "process"}}, {"term": {"event.type": "start"}}]}}})["hits"]["hits"][0]["_source"]
    flat = [k for k in doc if "." in k and k.split(".")[0] in
            ("process", "event", "host", "agent", "user", "ecs", "winlog", "file", "registry", "dll")]
    c.check(not flat, "ECS fields are nested objects in _source, not dotted keys",
            f"found flat keys {flat[:3]}" if flat else "nested")
    c.check(isinstance(doc.get("process"), dict) and bool(doc["process"].get("entity_id")),
            "_source.process.entity_id readable by the Kibana client",
            "this is what the analyzer's node-detail panel reads")
    c.check(isinstance(doc.get("event"), dict) and "process" in (doc["event"].get("category") or []),
            "_source.event.category readable by the Kibana client", "")

    # ------------------------------------------------------------------ zeek
    c.section("zeek")
    if check_zeek:
        zt = es_count(es, ZEEK_INDEX)
        c.check(zt == 2_140, f"{ZEEK_INDEX} total docs", f"{zt:,} (expect 2,140)")
    else:
        c.skip(f"{ZEEK_INDEX} total docs", "lab built without Zeek network logs")
        stale = requests.head(f"{es}/{ZEEK_INDEX}", timeout=30).status_code < 300
        c.check(not stale, "no leftover Zeek index from an earlier build",
                "found one -- its timestamps will not match this build" if stale else "none")

    # ----------------------------------------------------------------- summary
    print(f"\n{'=' * 62}")
    if c.failures:
        print(f"FAILED {len(c.failures)}/{c.checks} checks:")
        for f in c.failures:
            print(f"  - {f}")
        print("\nDo not continue to dashboards until these pass.")
        return 1
    print(f"All {c.checks} checks passed."
          + (f" ({c.skipped} skipped)" if c.skipped else ""))
    anchor_day = shift["anchor_date"]
    print("\nSTILL TO DO BY HAND (no script can check rendering):")
    print(f"  Kibana > Security > Explore > Hosts > Events, time range {anchor_day},")
    print("  filter  process.entity_id:*  -- click the 'Analyze event' icon on a row.")
    print("  1. the process tree draws, walking up to ancestors and down to children")
    print("  2. clicking any node fills in the details panel (host.name, process.*)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
