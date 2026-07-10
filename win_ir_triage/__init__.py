"""win_ir_triage — Windows Incident Response Triage & Timeline Builder.

A small, dependency-light toolkit that parses Windows EVTX event logs,
runs them through a Sigma-subset detection rule engine, correlates hits
against MITRE ATT&CK, and produces a bilingual (English/Arabic) HTML
incident timeline plus JSON / ATT&CK Navigator exports.
"""
from .parser import parse_evtx_file, parse_evtx_paths, NormalizedEvent
from .sigma import load_rule, load_rules_dir, evaluate_rule, scan, SigmaRule
from .timeline import build_timeline, summarize, TimelineEntry

__version__ = "0.1.0"

__all__ = [
    "parse_evtx_file",
    "parse_evtx_paths",
    "NormalizedEvent",
    "load_rule",
    "load_rules_dir",
    "evaluate_rule",
    "scan",
    "SigmaRule",
    "build_timeline",
    "summarize",
    "TimelineEntry",
    "__version__",
]
