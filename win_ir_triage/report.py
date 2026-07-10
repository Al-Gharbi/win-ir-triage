"""
report.py
---------
Renders the analysis results produced by timeline.py into:
  - a self-contained, bilingual (EN/AR, full RTL) HTML report
  - a machine-readable JSON export (for feeding into other tooling)
  - a MITRE ATT&CK Navigator layer JSON (drag-and-drop onto
    https://mitre-attack.github.io/attack-navigator/)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import mitre
from .timeline import TimelineEntry, summarize

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )


def render_html(
    entries: list[TimelineEntry],
    case_name: str,
    source_files: list[str],
    output_path: str | Path,
) -> Path:
    summary = summarize(entries)
    flagged = [e.to_dict() for e in entries if e.is_flagged]
    mitre_lookup = {tid: mitre.describe(tid) for tid in summary["distinct_techniques"]}

    template = _env().get_template("report.html.j2")
    html = template.render(
        case_name=case_name,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        source_files=source_files,
        summary=summary,
        flagged_entries=flagged,
        mitre_lookup=mitre_lookup,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def export_json(
    entries: list[TimelineEntry],
    case_name: str,
    source_files: list[str],
    output_path: str | Path,
) -> Path:
    summary = summarize(entries)
    payload: dict[str, Any] = {
        "case_name": case_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_files": source_files,
        "summary": summary,
        "events": [e.to_dict() for e in entries],
    }
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return output_path


def export_navigator_layer(
    entries: list[TimelineEntry], case_name: str, output_path: str | Path
) -> Path:
    summary = summarize(entries)
    layer = mitre.attack_navigator_layer(summary["distinct_techniques"], layer_name=case_name)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    return output_path
