#!/usr/bin/env python3
"""Map NXLog/WEC flat Windows events onto the subset of ECS that Kibana needs.

Design rules (from the build spec):

* Original fields are never removed. The demo has to be able to show people what
  raw Sysmon looks like, and the Sigma rules query the raw names directly.
* ECS fields are written alongside. The only reason they exist is to light up
  Kibana's visual event analyzer, which keys off ``process.entity_id``.
* EID 10 (39,283 docs) and EID 12 (61,151 docs) get every raw field and their
  category mapping, but deliberately no ``process.entity_id`` -- wiring those
  into the process graph makes it unreadable. Turn them on per-EID when a demo
  needs them.
"""
from __future__ import annotations

import hashlib
import ntpath
from datetime import date, datetime, timedelta, timezone

ECS_VERSION = "8.11.0"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
POWERSHELL_CHANNELS = ("Microsoft-Windows-PowerShell/Operational", "Windows PowerShell")

# The dataset ships 12,375 events on a lowercase "security" channel and 28,627 on
# "Security". Without this they look like two different log sources.
CHANNEL_CANON = {"security": "Security"}

# Sysmon EIDs that get a full ECS process mapping by default.
# 10 and 12 are excluded on purpose -- see module docstring.
DEFAULT_ECS_PROCESS_EIDS = frozenset({1, 3, 5, 7, 8, 11, 13, 14, 22, 23})
TOGGLEABLE_EIDS = frozenset({10, 12})

_SYSMON_ACTIONS = {
    1: "Process Create (rule: ProcessCreate)",
    2: "File creation time changed (rule: FileCreateTime)",
    3: "Network connection detected (rule: NetworkConnect)",
    5: "Process terminated (rule: ProcessTerminate)",
    7: "Image loaded (rule: ImageLoad)",
    8: "CreateRemoteThread detected (rule: CreateRemoteThread)",
    10: "Process accessed (rule: ProcessAccess)",
    11: "File created (rule: FileCreate)",
    12: "Registry object added or deleted (rule: RegistryEvent)",
    13: "Registry value set (rule: RegistryEvent)",
    14: "Registry object renamed (rule: RegistryEvent)",
    22: "Dns query (rule: DnsQuery)",
    23: "File Delete archived (rule: FileDelete)",
}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def normalize_channel(channel: str | None) -> str | None:
    if channel is None:
        return None
    return CHANNEL_CANON.get(channel, channel)


def host_id(hostname: str | None) -> str | None:
    """Stable synthetic host.id. Resolver groups nodes per host."""
    if not hostname:
        return None
    return hashlib.sha1(hostname.encode("utf-8")).hexdigest()[:16]


def short_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    return hostname.split(".")[0]


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return ntpath.basename(path.replace("/", "\\")) or path


def to_int(value):
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip(), 0) if str(value).strip().lower().startswith("0x") else int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_hashes(raw: str | None) -> dict[str, str]:
    """'SHA1=..,MD5=..,SHA256=..,IMPHASH=..' -> {'sha1': .., ...} (lowercased)."""
    out: dict[str, str] = {}
    if not raw or raw == "-":
        return out
    for part in raw.split(","):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip().lower()
        if value and value.strip("0"):
            out[key] = value
    return out


def split_args(command_line: str | None) -> list[str] | None:
    """Windows-ish argv split: double quotes group, everything else splits on space."""
    if not command_line:
        return None
    args: list[str] = []
    current: list[str] = []
    in_quotes = False
    has_token = False
    for ch in command_line:
        if ch == '"':
            in_quotes = not in_quotes
            has_token = True
        elif ch.isspace() and not in_quotes:
            if has_token or current:
                args.append("".join(current))
                current = []
                has_token = False
        else:
            current.append(ch)
            has_token = True
    if has_token or current:
        args.append("".join(current))
    return args or None


def split_user(user: str | None) -> tuple[str | None, str | None]:
    """'DMEVALS\\pbeesly' -> ('pbeesly', 'DMEVALS')."""
    if not user or user == "-":
        return None, None
    if "\\" in user:
        domain, _, name = user.rpartition("\\")
        return (name or None), (domain or None)
    return user, None


# --------------------------------------------------------------------------- #
# time shifting
# --------------------------------------------------------------------------- #
def parse_iso8601_utc(value: str) -> datetime | None:
    """'2020-05-02T02:55:57.730Z' -> aware UTC datetime."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def format_iso8601_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_naive(value: str) -> tuple[datetime | None, bool]:
    """'2020-05-02 02:55:56.157' -> (datetime, had_fraction)."""
    if not value:
        return None, False
    text = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt), "." in text
        except ValueError:
            continue
    return None, False


def shift_naive(value: str, delta: timedelta) -> str | None:
    """Shift a naive local/UTC timestamp string, preserving its original precision.

    EventTime is endpoint-local (UTC-4 in this dataset). It is shifted by the same
    delta and deliberately NOT normalised to UTC -- keeping the 4h skew is how the
    demo shows what the raw data actually looked like.
    """
    dt, had_fraction = _parse_naive(value)
    if dt is None:
        return None
    shifted = dt + delta
    if had_fraction:
        return shifted.strftime("%Y-%m-%d %H:%M:%S.") + f"{shifted.microsecond // 1000:03d}"
    return shifted.strftime("%Y-%m-%d %H:%M:%S")


def apply_time_shift(event: dict, delta: timedelta) -> None:
    """Shift @timestamp / UtcTime / EventTime in place, keeping *_original."""
    ts = event.get("@timestamp")
    if isinstance(ts, str):
        parsed = parse_iso8601_utc(ts)
        if parsed is not None:
            event["@timestamp_original"] = ts
            event["@timestamp"] = format_iso8601_utc(parsed + delta)

    for field in ("UtcTime", "EventTime"):
        value = event.get(field)
        if isinstance(value, str):
            shifted = shift_naive(value, delta)
            if shifted is not None:
                event[f"{field}_original"] = value
                event[field] = shifted


# --------------------------------------------------------------------------- #
# ECS mapping
# --------------------------------------------------------------------------- #
def _set(doc: dict, key: str, value) -> None:
    if value is not None and value != "" and value != "-":
        doc[key] = value


def _module_and_dataset(channel: str | None) -> tuple[str | None, str | None]:
    if channel == SYSMON_CHANNEL:
        return "sysmon", "sysmon.operational"
    if channel == SECURITY_CHANNEL:
        return "security", "windows.security"
    if channel in POWERSHELL_CHANNELS:
        return "powershell", "windows.powershell"
    if channel == "System":
        return "system", "windows.system"
    return None, None


def map_common(event: dict, doc: dict) -> None:
    channel = normalize_channel(event.get("Channel"))
    hostname = event.get("Hostname")
    module, dataset = _module_and_dataset(channel)

    doc["ecs.version"] = ECS_VERSION
    doc["event.kind"] = "event"
    _set(doc, "event.code", str(event["EventID"]) if event.get("EventID") is not None else None)
    _set(doc, "event.module", module)
    _set(doc, "event.dataset", dataset)
    _set(doc, "event.provider", event.get("SourceName"))
    doc["agent.type"] = "winlogbeat"
    _set(doc, "host.name", hostname)
    _set(doc, "host.hostname", short_hostname(hostname))
    _set(doc, "host.id", host_id(hostname))
    doc["host.os.family"] = "windows"
    _set(doc, "winlog.channel", channel)
    _set(doc, "winlog.event_id", to_int(event.get("EventID")))
    _set(doc, "winlog.record_id", to_int(event.get("RecordNumber")))


def _map_process_common(event: dict, doc: dict, with_entity: bool, guid_field: str = "ProcessGuid") -> None:
    if with_entity:
        _set(doc, "process.entity_id", event.get(guid_field))
    _set(doc, "process.pid", to_int(event.get("ProcessId")))
    _set(doc, "process.executable", event.get("Image"))
    _set(doc, "process.name", basename(event.get("Image")))


def map_sysmon(event: dict, doc: dict, ecs_process_eids: frozenset[int]) -> None:
    eid = event.get("EventID")
    with_entity = eid in ecs_process_eids
    _set(doc, "event.action", _SYSMON_ACTIONS.get(eid))

    if eid == 1:
        guid, parent_guid = event.get("ProcessGuid"), event.get("ParentProcessGuid")
        # One of the 447 EID 1 events has neither GUID. It cannot join the process
        # graph, so it gets no process mapping at all rather than a fabricated id.
        if not guid or not parent_guid:
            return
        doc["event.category"] = ["process"]
        doc["event.type"] = ["start", "process_started"]
        _map_process_common(event, doc, with_entity)
        _set(doc, "process.command_line", event.get("CommandLine"))
        _set(doc, "process.args", split_args(event.get("CommandLine")))
        _set(doc, "process.working_directory", event.get("CurrentDirectory"))
        for algo, value in parse_hashes(event.get("Hashes")).items():
            if algo in ("md5", "sha1", "sha256"):
                doc[f"process.hash.{algo}"] = value
        _set(doc, "process.parent.entity_id", parent_guid)
        _set(doc, "process.parent.pid", to_int(event.get("ParentProcessId")))
        _set(doc, "process.parent.executable", event.get("ParentImage"))
        _set(doc, "process.parent.name", basename(event.get("ParentImage")))
        _set(doc, "process.parent.command_line", event.get("ParentCommandLine"))
        name, domain = split_user(event.get("User"))
        _set(doc, "user.name", name)
        _set(doc, "user.domain", domain)

    elif eid == 3:
        doc["event.category"] = ["network"]
        doc["event.type"] = ["connection", "start"]
        _map_process_common(event, doc, with_entity)
        _set(doc, "source.ip", event.get("SourceIp"))
        _set(doc, "source.port", to_int(event.get("SourcePort")))
        _set(doc, "destination.ip", event.get("DestinationIp"))
        _set(doc, "destination.port", to_int(event.get("DestinationPort")))
        protocol = event.get("Protocol")
        _set(doc, "network.transport", protocol.lower() if protocol else None)
        if str(event.get("Initiated", "")).lower() == "true":
            doc["network.direction"] = "egress"

    elif eid == 5:
        doc["event.category"] = ["process"]
        doc["event.type"] = ["end", "process_stopped"]
        _map_process_common(event, doc, with_entity)

    elif eid == 7:
        doc["event.category"] = ["library"]
        doc["event.type"] = ["start"]
        _map_process_common(event, doc, with_entity)
        _set(doc, "dll.path", event.get("ImageLoaded"))
        _set(doc, "dll.name", basename(event.get("ImageLoaded")))

    elif eid == 8:
        doc["event.category"] = ["process"]
        doc["event.type"] = ["change"]
        # EID 8 spells it SourceProcessGuid; EID 10 spells it SourceProcessGUID.
        if with_entity:
            _set(doc, "process.entity_id", event.get("SourceProcessGuid") or event.get("SourceProcessGUID"))
        _set(doc, "process.pid", to_int(event.get("SourceProcessId")))
        _set(doc, "process.executable", event.get("SourceImage"))
        _set(doc, "process.name", basename(event.get("SourceImage")))

    elif eid == 10:
        doc["event.category"] = ["process"]
        doc["event.type"] = ["access"]
        if with_entity:
            _set(doc, "process.entity_id", event.get("SourceProcessGUID") or event.get("SourceProcessGuid"))
        _set(doc, "process.pid", to_int(event.get("SourceProcessId")))
        _set(doc, "process.executable", event.get("SourceImage"))
        _set(doc, "process.name", basename(event.get("SourceImage")))

    elif eid in (11, 23):
        doc["event.category"] = ["file"]
        doc["event.type"] = ["creation"] if eid == 11 else ["deletion"]
        _map_process_common(event, doc, with_entity)
        target = event.get("TargetFilename")
        _set(doc, "file.path", target)
        name = basename(target)
        _set(doc, "file.name", name)
        if name and "." in name:
            _set(doc, "file.extension", name.rsplit(".", 1)[1].lower())

    elif eid in (12, 13, 14):
        doc["event.category"] = ["registry"]
        doc["event.type"] = ["creation"] if eid == 12 else ["change"]
        _map_process_common(event, doc, with_entity)
        target = event.get("TargetObject")
        _set(doc, "registry.path", target)
        if target:
            _set(doc, "registry.value", target.rsplit("\\", 1)[-1])
        details = event.get("Details")
        if details not in (None, "", "-"):
            doc["registry.data.strings"] = [details]

    elif eid == 22:
        doc["event.category"] = ["network"]
        doc["event.type"] = ["protocol"]
        doc["network.protocol"] = "dns"
        _map_process_common(event, doc, with_entity)
        _set(doc, "dns.question.name", event.get("QueryName"))


def map_security(event: dict, doc: dict) -> None:
    """Security channel. 4688 has process data but no GUID.

    It deliberately gets no process.entity_id -- inventing one would grow orphan
    nodes in the analyzer graph -- and no event.type, so that the
    ``event.category:process and event.type:start`` query stays the 446 Sysmon
    process creations that actually resolve in the graph.
    """
    if event.get("EventID") == 4688:
        doc["event.category"] = ["process"]
        doc["event.action"] = "created-process"
        _set(doc, "process.pid", to_int(event.get("NewProcessId")))
        _set(doc, "process.executable", event.get("NewProcessName"))
        _set(doc, "process.name", basename(event.get("NewProcessName")))
        _set(doc, "process.command_line", event.get("CommandLine"))
        _set(doc, "process.parent.pid", to_int(event.get("ProcessId")))
        _set(doc, "process.parent.executable", event.get("ParentProcessName"))
        _set(doc, "process.parent.name", basename(event.get("ParentProcessName")))
        _set(doc, "user.name", event.get("SubjectUserName"))
        _set(doc, "user.domain", event.get("SubjectDomainName"))


def map_event(event: dict, delta: timedelta,
              ecs_process_eids: frozenset[int] = DEFAULT_ECS_PROCESS_EIDS,
              event_id: str | None = None) -> dict:
    """Return the indexable document: raw fields + shifted time + ECS overlay.

    event_id must be unique per document. Kibana's event analyzer sorts its
    node-detail queries on (@timestamp, event.id); if event.id is missing from
    the mapping that query fails and every node shows "Node details were unable
    to be retrieved", even though the graph itself still draws.
    """
    doc = dict(event)

    raw_channel = doc.get("Channel")
    channel = normalize_channel(raw_channel)
    if channel != raw_channel:
        doc["Channel_raw"] = raw_channel
        doc["Channel"] = channel

    apply_time_shift(doc, delta)
    map_common(doc, doc)
    if event_id is not None:
        doc["event.id"] = event_id

    if channel == SYSMON_CHANNEL:
        map_sysmon(event, doc, ecs_process_eids)
    elif channel == SECURITY_CHANNEL:
        map_security(event, doc)

    deconflict_raw_fields(doc)
    return nest_ecs_fields(doc)


# --------------------------------------------------------------------------- #
# anchor / delta
#
# Both loaders must apply the SAME delta or the host and network timelines drift
# apart, so it is computed once, written to data/shift_delta.json, and reused.
# --------------------------------------------------------------------------- #
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
from zoneinfo import ZoneInfo  # noqa: E402

# Earliest @timestamp in apt29_evals_day1_manual (verified against the file).
DATASET_MIN_TS = "2020-05-02T02:55:26.493Z"
DATASET_MAX_TS = "2020-05-02T03:28:20.170Z"

DEFAULT_ANCHOR_LOCAL = "09:00"
DEFAULT_ANCHOR_TZ = "Asia/Taipei"
# Blank or "today" anchors to whatever day the loader runs on. A fixed
# YYYY-MM-DD pins every install to the same timeline, so an instructor and a
# room full of students all see identical timestamps.
DEFAULT_ANCHOR_DATE = "today"

SHIFT_FILE = Path(__file__).resolve().parent.parent / "data" / "shift_delta.json"


def resolve_anchor_date(anchor_date: str | None, tz: ZoneInfo) -> tuple[date, bool]:
    """Return (date, is_fixed). Blank or "today" means the current local date."""
    value = (anchor_date if anchor_date is not None
             else os.environ.get("ANCHOR_DATE", DEFAULT_ANCHOR_DATE))
    value = (value or "").strip()
    if not value or value.lower() == "today":
        return datetime.now(tz).date(), False
    try:
        return date.fromisoformat(value), True
    except ValueError:
        raise SystemExit(
            f"ANCHOR_DATE must be YYYY-MM-DD or 'today', got {value!r}"
        ) from None


def compute_delta(anchor_local: str | None = None, anchor_tz: str | None = None,
                  anchor_date: str | None = None, on_date=None) -> dict:
    """delta = anchor(date, local time, tz) - earliest original @timestamp."""
    anchor_local = anchor_local or os.environ.get("ANCHOR_LOCAL") or DEFAULT_ANCHOR_LOCAL
    anchor_tz = anchor_tz or os.environ.get("ANCHOR_TZ") or DEFAULT_ANCHOR_TZ

    tz = ZoneInfo(anchor_tz)
    hour, _, minute = anchor_local.partition(":")
    if on_date is not None:
        day, fixed = on_date, True
    else:
        day, fixed = resolve_anchor_date(anchor_date, tz)
    anchor_dt = datetime(day.year, day.month, day.day, int(hour), int(minute), tzinfo=tz)
    anchor_utc = anchor_dt.astimezone(timezone.utc)

    dataset_min = parse_iso8601_utc(DATASET_MIN_TS)
    delta = anchor_utc - dataset_min

    return {
        "anchor_local": anchor_local,
        "anchor_tz": anchor_tz,
        "anchor_date": day.isoformat(),
        "anchor_date_is_fixed": fixed,
        "anchor_utc": format_iso8601_utc(anchor_utc),
        "dataset_min_ts": DATASET_MIN_TS,
        "dataset_max_ts": DATASET_MAX_TS,
        "delta_seconds": delta.total_seconds(),
        "computed_at": format_iso8601_utc(datetime.now(timezone.utc)),
    }


def write_shift_delta(info: dict, path: Path = SHIFT_FILE) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return path


def read_shift_delta(path: Path = SHIFT_FILE) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run the host loader first -- it computes the delta "
            "that the Zeek loader has to reuse."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def delta_from(info: dict) -> timedelta:
    return timedelta(seconds=info["delta_seconds"])


# --------------------------------------------------------------------------- #
# raw/ECS name collisions
# --------------------------------------------------------------------------- #
# Raw field names that clash with an ECS object we write. Elasticsearch cannot
# hold both a scalar `source` and an object `source.ip`, so the scalar is moved
# aside. Real examples in this dataset:
#   host   -> WEC collector name (host events) / HTTP Host header (zeek http)
#   source -> Zeek files.log carrier protocol ("HTTP", "SMB")
ECS_OBJECT_ROOTS = (
    "agent", "destination", "dll", "dns", "ecs", "event", "file", "host",
    "http", "log", "network", "observer", "process", "registry", "source",
    "url", "user", "user_agent", "winlog", "zeek",
)


def nest_ecs_fields(doc: dict, roots: tuple[str, ...] = ECS_OBJECT_ROOTS) -> dict:
    """Expand flat dotted ECS keys into real nested objects.

    This is not cosmetic. A document written with a literal "process.entity_id"
    key satisfies every Elasticsearch query, because dotted paths are resolved
    at query time -- so the analyzer graph still draws, since the tree is built
    server-side. But Kibana's Security app reads _source in the browser with
    `event.process?.entity_id`, which is undefined for a flat key. The result is
    a graph that renders and then reports "Node details were unable to be
    retrieved" on every node.

    Raw Windows/Sysmon field names never contain a dot, so they are left alone.
    Run deconflict_raw_fields() first: a raw scalar sharing a name with an ECS
    object (host, source) would otherwise be overwritten here.
    """
    out: dict = {}
    for key, value in doc.items():
        if "." not in key or key.split(".", 1)[0] not in roots:
            out[key] = value
            continue
        parts = key.split(".")
        cursor = out
        for part in parts[:-1]:
            nxt = cursor.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cursor[part] = nxt
            cursor = nxt
        cursor[parts[-1]] = value
    return out


def deconflict_raw_fields(doc: dict, roots: tuple[str, ...] = ECS_OBJECT_ROOTS) -> list[str]:
    """Move scalar raw fields that would collide with an ECS object to <name>_raw."""
    moved = []
    for root in roots:
        if root in doc and not isinstance(doc[root], dict):
            doc[f"{root}_raw"] = doc.pop(root)
            moved.append(root)
    return moved
