"""
timeline.py
-----------
Merges parsed events from (potentially many) EVTX files into a single
chronologically-sorted timeline, and attaches the Sigma-subset detection
results from sigma.scan() back onto their originating events so the
report layer has one simple structure to render.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .parser import NormalizedEvent, UNKNOWN_TIME
from .sigma import SigmaRule, evaluate_rule
from . import mitre


@dataclass
class TimelineEntry:
    event: NormalizedEvent
    matched_rules: list[SigmaRule] = field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return len(self.matched_rules) > 0

    @property
    def highest_level(self) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        if not self.matched_rules:
            return "informational"
        return max(self.matched_rules, key=lambda r: order.get(r.level, 0)).level

    def to_dict(self) -> dict[str, Any]:
        d = self.event.as_timeline_dict()
        d["flagged"] = self.is_flagged
        d["level"] = self.highest_level
        d["detections"] = [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "level": r.level,
                "mitre": [
                    {"id": tid, **mitre.describe(tid)} for tid in r.mitre_technique_ids
                ],
            }
            for r in self.matched_rules
        ]
        return d


def build_timeline(events: list[NormalizedEvent], rules: list[SigmaRule]) -> list[TimelineEntry]:
    """Evaluate every rule against every event and return a time-sorted
    timeline with detections attached in place."""
    entries = []
    for event in sorted(events, key=lambda e: e.timestamp):
        flat = event.as_dict()
        matched = [r for r in rules if evaluate_rule(r, flat)]
        entries.append(TimelineEntry(event=event, matched_rules=matched))
    return entries


def summarize(entries: list[TimelineEntry]) -> dict[str, Any]:
    """Aggregate stats used at the top of the report (counts by level,
    distinct techniques touched, hosts involved, time span covered)."""
    level_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    technique_ids: set[str] = set()
    hosts: set[str] = set()
    rule_hit_counts: dict[str, int] = {}

    flagged = [e for e in entries if e.is_flagged]
    for e in flagged:
        level_counts[e.highest_level] = level_counts.get(e.highest_level, 0) + 1
        hosts.add(e.event.computer)
        for r in e.matched_rules:
            technique_ids.update(r.mitre_technique_ids)
            rule_hit_counts[r.rule_id] = rule_hit_counts.get(r.rule_id, 0) + 1

    timestamps = [e.event.timestamp for e in entries if e.event.timestamp != UNKNOWN_TIME]
    return {
        "total_events": len(entries),
        "flagged_events": len(flagged),
        "level_counts": level_counts,
        "distinct_techniques": sorted(technique_ids),
        "hosts_involved": sorted(hosts),
        "time_range": {
            "start": min(timestamps).isoformat() if timestamps else None,
            "end": max(timestamps).isoformat() if timestamps else None,
        },
        "top_rules": sorted(rule_hit_counts.items(), key=lambda kv: -kv[1]),
    }
