"""
cli.py
------
Command-line entry point.

Usage:
    python -m win_ir_triage --evtx path/to/Security.evtx path/to/Sysmon.evtx \
        --rules rules/ --case-name "HOST01 incident" --out-dir out/

    python -m win_ir_triage --evtx *.evtx --rules rules/ --out-dir out/ --json --navigator
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .parser import parse_evtx_paths
from .sigma import load_rules_dir
from .timeline import build_timeline, summarize
from .report import render_html, export_json, export_navigator_layer

console = Console()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="win-ir-triage",
        description="Parse Windows EVTX logs, run Sigma-subset detection rules, "
        "and produce a bilingual (EN/AR) HTML incident timeline.",
    )
    p.add_argument("--evtx", nargs="+", required=True, metavar="FILE",
                    help="One or more .evtx files to parse")
    p.add_argument("--rules", default="rules", metavar="DIR",
                    help="Directory containing Sigma-subset .yml rules (default: rules/)")
    p.add_argument("--case-name", default="untitled-case", metavar="NAME",
                    help="Label shown in the report header and used for output filenames")
    p.add_argument("--out-dir", default="out", metavar="DIR",
                    help="Directory to write the report(s) into (default: out/)")
    p.add_argument("--json", action="store_true", help="Also export a JSON timeline")
    p.add_argument("--navigator", action="store_true",
                    help="Also export a MITRE ATT&CK Navigator layer JSON")
    p.add_argument("--min-level", default="low",
                    choices=["low", "medium", "high", "critical"],
                    help="Only print (not filter from the report) rule hits at or above this level in the console summary")
    return p


def _level_rank(level: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 0)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    evtx_paths = [Path(p) for p in args.evtx]
    missing = [str(p) for p in evtx_paths if not p.exists()]
    if missing:
        console.print(f"[red]Error:[/red] file(s) not found: {', '.join(missing)}")
        return 1

    rules_dir = Path(args.rules)
    if not rules_dir.exists():
        console.print(f"[red]Error:[/red] rules directory not found: {rules_dir}")
        return 1

    with console.status("[bold blue]Parsing EVTX files..."):
        events = parse_evtx_paths(evtx_paths)

    with console.status("[bold blue]Loading detection rules..."):
        rules = load_rules_dir(rules_dir)

    with console.status("[bold blue]Building timeline and running detections..."):
        timeline = build_timeline(events, rules)

    summary = summarize(timeline)

    console.print(f"\n[bold]win-ir-triage[/bold] — {args.case_name}")
    console.print(f"  Parsed {summary['total_events']} events from {len(evtx_paths)} file(s) "
                   f"using {len(rules)} rules\n")

    table = Table(title="Detections by severity")
    table.add_column("Level")
    table.add_column("Count", justify="right")
    for level in ("critical", "high", "medium", "low"):
        table.add_row(level, str(summary["level_counts"].get(level, 0)))
    console.print(table)

    if summary["distinct_techniques"]:
        console.print(
            f"\n[bold]MITRE ATT&CK techniques observed:[/bold] "
            f"{', '.join(summary['distinct_techniques'])}"
        )

    if summary["flagged_events"] == 0:
        console.print("\n[green]No detections fired against the parsed events.[/green]")

    out_dir = Path(args.out_dir)
    html_path = render_html(
        timeline,
        case_name=args.case_name,
        source_files=[p.name for p in evtx_paths],
        output_path=out_dir / f"{args.case_name}.html",
    )
    console.print(f"\n[bold green]HTML report:[/bold green] {html_path}")

    if args.json:
        json_path = export_json(
            timeline, args.case_name, [p.name for p in evtx_paths],
            out_dir / f"{args.case_name}.json",
        )
        console.print(f"[bold green]JSON export:[/bold green] {json_path}")

    if args.navigator:
        nav_path = export_navigator_layer(
            timeline, args.case_name, out_dir / f"{args.case_name}.navigator.json"
        )
        console.print(f"[bold green]ATT&CK Navigator layer:[/bold green] {nav_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
