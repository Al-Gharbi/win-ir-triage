"""
cli.py
------
Command-line entry point.

Usage:
    python -m win_ir_triage --evtx Security.evtx Sysmon.evtx \
        --rules rules/ --case-name "HOST01 incident" --out-dir out/

Exit codes:
    0  finished; no detection at or above --fail-on (or --fail-on not given)
    1  usage / input error (missing file, unreadable EVTX, no usable rules)
    2  at least one detection at or above --fail-on
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from . import __version__
from .parser import parse_evtx_paths
from .report import export_json, export_navigator_layer, render_html
from .sigma import load_rules_dir
from .timeline import build_timeline, summarize

LEVELS = ("low", "medium", "high", "critical")
EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="win-ir-triage",
        description="Parse Windows EVTX logs, run Sigma-subset detection rules, "
        "and produce a bilingual (EN/AR) HTML incident timeline.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--evtx", nargs="+", required=True, metavar="FILE",
                   help="One or more .evtx files to parse")
    p.add_argument("--rules", default="rules", metavar="DIR",
                   help="Directory containing Sigma-subset .yml rules (default: rules/)")
    p.add_argument("--case-name", default="untitled-case", metavar="NAME",
                   help="Label shown in the report header; also used (sanitised) for output filenames")
    p.add_argument("--out-dir", default="out", metavar="DIR",
                   help="Directory to write the report(s) into (default: out/)")
    p.add_argument("--json", action="store_true", help="Also export a JSON timeline")
    p.add_argument("--navigator", action="store_true",
                   help="Also export a MITRE ATT&CK Navigator layer JSON")
    p.add_argument("--min-level", default="low", choices=LEVELS,
                   help="Only list individual detections at or above this level in the console "
                        "output (the report always contains all of them)")
    p.add_argument("--fail-on", choices=LEVELS, default=None, metavar="LEVEL",
                   help="Exit with status 2 if any detection is at or above LEVEL "
                        f"({'|'.join(LEVELS)}). Default: always exit 0 after a successful run")
    return p


def _rank(level: str) -> int:
    return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 0)


def safe_filename(name: str) -> str:
    """Make a case name safe to use as a file name (no separators, no '..')."""
    cleaned = re.sub(r"[^\w.\-]+", "_", name, flags=re.UNICODE).strip("._")
    return cleaned or "case"


def _err(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    evtx_paths = [Path(p) for p in args.evtx]
    missing = [str(p) for p in evtx_paths if not p.is_file()]
    if missing:
        _err(f"file(s) not found: {', '.join(missing)}")
        return EXIT_ERROR

    rules_dir = Path(args.rules)
    if not rules_dir.is_dir():
        _err(f"rules directory not found: {rules_dir}")
        return EXIT_ERROR

    skipped: list[str] = []

    def on_rule_error(path: Path, exc: Exception) -> None:
        skipped.append(path.name)
        print(f"[!] Skipping rule {path.name}: {exc}", file=sys.stderr)

    rules = load_rules_dir(rules_dir, on_error=on_rule_error)
    if not rules:
        _err(f"no usable rules in {rules_dir}")
        return EXIT_ERROR

    try:
        events = parse_evtx_paths(evtx_paths)
    except RuntimeError as exc:  # python-evtx missing
        _err(str(exc))
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - corrupt/unsupported file
        _err(f"could not read EVTX input: {exc}")
        return EXIT_ERROR

    timeline = build_timeline(events, rules)
    summary = summarize(timeline)

    print(f"\nwin-ir-triage {__version__} - {args.case_name}")
    print(f"  Parsed {summary['total_events']} events from {len(evtx_paths)} file(s) "
          f"using {len(rules)} rules" + (f" ({len(skipped)} skipped)" if skipped else ""))
    print("\n  Detections by severity (events)")
    for level in reversed(LEVELS):
        print(f"    {level:<9} {summary['level_counts'].get(level, 0):>6}")

    shown = [e for e in timeline if e.is_flagged and _rank(e.highest_level) >= _rank(args.min_level)]
    if shown:
        print(f"\n  Detections at or above '{args.min_level}':")
        for e in shown[:50]:
            titles = "; ".join(r.title for r in e.matched_rules)
            print(f"    {e.event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}Z  "
                  f"[{e.highest_level}] {e.event.computer}  {titles}")
        if len(shown) > 50:
            print(f"    ... and {len(shown) - 50} more (see the report)")
    if summary["distinct_techniques"]:
        print(f"\n  MITRE ATT&CK techniques: {', '.join(summary['distinct_techniques'])}")
    if summary["flagged_events"] == 0:
        print("\n  No detections fired against the parsed events.")

    out_dir = Path(args.out_dir)
    stem = safe_filename(args.case_name)
    sources = [p.name for p in evtx_paths]
    html_path = render_html(timeline, case_name=args.case_name, source_files=sources,
                            output_path=out_dir / f"{stem}.html")
    print(f"\n  HTML report: {html_path}")
    if args.json:
        print(f"  JSON export: {export_json(timeline, args.case_name, sources, out_dir / f'{stem}.json')}")
    if args.navigator:
        print("  ATT&CK Navigator layer: "
              f"{export_navigator_layer(timeline, args.case_name, out_dir / f'{stem}.navigator.json')}")

    if args.fail_on:
        threshold = _rank(args.fail_on)
        if any(_rank(e.highest_level) >= threshold for e in timeline if e.is_flagged):
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
