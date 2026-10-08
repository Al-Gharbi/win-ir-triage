"""
parser.py
---------
Parses Windows EVTX event log files into a stream of normalized, flat
dictionaries. Both classic Windows Security auditing events and Sysmon
events share the same underlying structure:

    <System>
        <EventID>...</EventID>
        <TimeCreated SystemTime="..."/>
        <Channel>...</Channel>
        <Computer>...</Computer>
        <Provider Name="..."/>
        <EventRecordID>...</EventRecordID>
    </System>
    <EventData>
        <Data Name="Field1">Value1</Data>
        <Data Name="Field2">Value2</Data>
        ...
    </EventData>

We flatten this into a single dict where every <Data Name="X"> becomes a
top level key "X", alongside the System-level fields (EventID, Channel,
Computer, TimeCreated, Provider, EventRecordID). This flat, single
namespace layout intentionally mirrors how real Sigma rules reference
fields (e.g. "EventID", "Image", "TargetUserName") so the same rule
files work unmodified against events coming from this parser.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

# The XML documents returned by python-evtx declare this default namespace.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass
class NormalizedEvent:
    """A single, flattened Windows event ready for rule matching / timelining."""

    event_id: int
    timestamp: datetime
    channel: str
    computer: str
    provider: str
    record_id: int
    source_file: str
    fields: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Flat dict used by the Sigma-subset matching engine (see sigma.py)."""
        base = {
            "EventID": self.event_id,
            "Channel": self.channel,
            "Computer": self.computer,
            "Provider": self.provider,
            "EventRecordID": self.record_id,
        }
        # EventData fields take precedence only if they don't collide with
        # the reserved System-level names above.
        merged = {**self.fields, **base}
        return merged

    def as_timeline_dict(self) -> dict[str, Any]:
        """Compact dict used for timeline / report rendering."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "channel": self.channel,
            "computer": self.computer,
            "provider": self.provider,
            "record_id": self.record_id,
            "source_file": self.source_file,
            "fields": self.fields,
        }


def _text(el: ET.Element | None) -> str | None:
    if el is None:
        return None
    return (el.text or "").strip()


# Placeholder for records whose timestamp is missing or unparseable. It is
# timezone-aware so it can be sorted together with real timestamps (mixing
# naive and aware datetimes raises TypeError).
UNKNOWN_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)

_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)


def _parse_timestamp(raw: str | None) -> datetime:
    """Parse an EVTX SystemTime into a timezone-aware UTC datetime.

    Accepts ``2019-09-22 11:22:05.201725``, ``2019-09-22T11:22:05.2017250Z`` and
    ``...+00:00``. EVTX stores UTC, so a value without an offset is taken as
    UTC. Fractions longer than 6 digits are truncated. Anything else returns
    ``UNKNOWN_TIME`` (it is never silently shifted to a plausible date).
    """
    if not raw:
        return UNKNOWN_TIME
    m = _TS_RE.match(raw.strip())
    if not m:
        return UNKNOWN_TIME
    y, mo, d, h, mi, sec, frac, tz = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), micro,
                      tzinfo=timezone.utc)
    except ValueError:
        return UNKNOWN_TIME
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        dt -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return dt


def parse_record_xml(xml_str: str, source_file: str) -> NormalizedEvent | None:
    """Parse a single <Event>...</Event> XML string into a NormalizedEvent."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find(f"{_NS}System")
    if system is None:
        return None

    event_id_el = system.find(f"{_NS}EventID")
    event_id_raw = _text(event_id_el)
    try:
        event_id = int(event_id_raw) if event_id_raw else -1
    except ValueError:
        event_id = -1

    time_created = system.find(f"{_NS}TimeCreated")
    ts_raw = time_created.get("SystemTime") if time_created is not None else None

    provider_el = system.find(f"{_NS}Provider")
    provider = provider_el.get("Name", "") if provider_el is not None else ""

    channel = _text(system.find(f"{_NS}Channel")) or ""
    computer = _text(system.find(f"{_NS}Computer")) or ""

    record_id_raw = _text(system.find(f"{_NS}EventRecordID"))
    try:
        record_id = int(record_id_raw) if record_id_raw else -1
    except ValueError:
        record_id = -1

    fields: dict[str, Any] = {}
    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for data_el in event_data.findall(f"{_NS}Data"):
            name = data_el.get("Name")
            if name:
                fields[name] = (data_el.text or "").strip()

    # Some providers (older / legacy XP-style logs) use <UserData> instead of
    # <EventData>. We fold any nested elements into `fields` too, using the
    # tag's local name (namespace stripped) as the key.
    user_data = root.find(f"{_NS}UserData")
    if user_data is not None:
        for child in user_data.iter():
            tag = child.tag.split("}")[-1]
            if child.text and child.text.strip() and tag not in fields:
                fields[tag] = child.text.strip()

    return NormalizedEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(ts_raw),
        channel=channel,
        computer=computer,
        provider=provider,
        record_id=record_id,
        source_file=source_file,
        fields=fields,
    )


def parse_evtx_file(path: str | Path) -> Iterator[NormalizedEvent]:
    """Yield NormalizedEvent objects for every parsable record in an EVTX file.

    Corrupt / truncated individual records are skipped rather than aborting
    the whole file, since real-world triage images frequently contain a
    handful of damaged records.
    """
    try:
        import Evtx.Evtx as Evtx  # imported lazily: XML parsing works without it
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "python-evtx is required to read .evtx files: pip install python-evtx"
        ) from exc
    path = Path(path)
    with Evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
            except Exception:
                continue
            event = parse_record_xml(xml_str, source_file=path.name)
            if event is not None:
                yield event


def parse_evtx_paths(paths: list[str | Path]) -> list[NormalizedEvent]:
    """Parse multiple EVTX files and return a single combined, time-sorted list."""
    events: list[NormalizedEvent] = []
    for p in paths:
        events.extend(parse_evtx_file(p))
    events.sort(key=lambda e: e.timestamp)
    return events
