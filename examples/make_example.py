"""Regenerate examples/sample_report.* from the synthetic incident fixture.

    python examples/make_example.py

The fixture is hand-written (see tests/fixtures/synthetic_incident.py); the
output is NOT derived from any real system.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.fixtures.synthetic_incident import SYNTHETIC_INCIDENT  # noqa: E402
from win_ir_triage.parser import NormalizedEvent  # noqa: E402
from win_ir_triage.report import export_json, export_navigator_layer, render_html  # noqa: E402
from win_ir_triage.sigma import load_rules_dir  # noqa: E402
from win_ir_triage.timeline import build_timeline  # noqa: E402

RESERVED = {"EventID", "TimeCreated", "Channel", "Computer", "Provider", "EventRecordID"}


def main() -> None:
    events = [
        NormalizedEvent(
            event_id=d["EventID"], timestamp=datetime.fromisoformat(d["TimeCreated"]),
            channel=d["Channel"], computer=d["Computer"], provider=d["Provider"],
            record_id=d["EventRecordID"], source_file="synthetic_incident_example.evtx",
            fields={k: v for k, v in d.items() if k not in RESERVED})
        for d in SYNTHETIC_INCIDENT
    ]
    timeline = build_timeline(events, load_rules_dir(ROOT / "rules"))
    out = ROOT / "examples"
    src = ["synthetic_incident_example.evtx"]
    render_html(timeline, "example-incident", src, out / "sample_report.html")
    export_json(timeline, "example-incident", src, out / "sample_report.json")
    export_navigator_layer(timeline, "example-incident", out / "sample_report.navigator.json")
    print("examples regenerated")


if __name__ == "__main__":
    main()
