"""CLI exit codes, output files, report escaping and version consistency."""
from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import win_ir_triage  # noqa: E402
from win_ir_triage import cli  # noqa: E402
from win_ir_triage.parser import NormalizedEvent  # noqa: E402
from win_ir_triage.report import render_html  # noqa: E402
from win_ir_triage.sigma import load_rules_dir  # noqa: E402
from win_ir_triage.timeline import build_timeline  # noqa: E402
from tests.fixtures.synthetic_incident import SYNTHETIC_INCIDENT  # noqa: E402

RESERVED = {"EventID", "TimeCreated", "Channel", "Computer", "Provider", "EventRecordID"}


def to_event(d: dict) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=d["EventID"], timestamp=datetime.fromisoformat(d["TimeCreated"]),
        channel=d["Channel"], computer=d["Computer"], provider=d["Provider"],
        record_id=d["EventRecordID"], source_file="t.evtx",
        fields={k: v for k, v in d.items() if k not in RESERVED})


INCIDENT = [to_event(d) for d in SYNTHETIC_INCIDENT]
BENIGN = [e for e in INCIDENT if e.event_id == 4624]


def run_cli(*argv, events=INCIDENT):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(cli, "parse_evtx_paths", return_value=events), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.evtx = Path(self.tmp.name) / "Security.evtx"
        self.evtx.write_bytes(b"stub")  # parse_evtx_paths is mocked
        self.out = Path(self.tmp.name) / "out"

    def args(self, *extra, case="case1"):
        return ["--evtx", str(self.evtx), "--rules", str(ROOT / "rules"),
                "--out-dir", str(self.out), "--case-name", case, *extra]

    def test_default_run_exits_zero_and_writes_all_outputs(self):
        code, out, _ = run_cli(*self.args("--json", "--navigator"))
        self.assertEqual(code, 0)
        for suffix in (".html", ".json", ".navigator.json"):
            self.assertTrue((self.out / f"case1{suffix}").is_file(), suffix)
        data = json.loads((self.out / "case1.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(data["summary"]["flagged_events"], 5)
        self.assertIn("critical", out)

    def test_fail_on_exit_codes(self):
        self.assertEqual(run_cli(*self.args("--fail-on", "critical"))[0], 2)
        self.assertEqual(run_cli(*self.args("--fail-on", "low"), events=BENIGN)[0], 0)

    def test_fail_on_threshold_is_respected(self):
        medium_only = [e for e in INCIDENT if e.event_id == 4720]  # wit-002, level medium
        self.assertEqual(run_cli(*self.args("--fail-on", "medium"), events=medium_only)[0], 2)
        self.assertEqual(run_cli(*self.args("--fail-on", "high"), events=medium_only)[0], 0)

    def test_min_level_filters_console_listing_only(self):
        _, out, _ = run_cli(*self.args("--min-level", "critical"))
        self.assertIn("Office", out)               # wit-010 (critical) listed
        self.assertNotIn("New Local User", out)    # medium not listed
        html = (self.out / "case1.html").read_text(encoding="utf-8")
        self.assertIn("New Local User", html)      # but still in the report

    def test_missing_input_and_rules_dir(self):
        code, _, err = run_cli("--evtx", "/nonexistent.evtx", "--rules", str(ROOT / "rules"))
        self.assertEqual(code, 1)
        self.assertIn("not found", err)
        code, _, err = run_cli("--evtx", str(self.evtx), "--rules", "/nonexistent-dir")
        self.assertEqual(code, 1)

    def test_all_rules_invalid_is_an_error(self):
        bad = Path(self.tmp.name) / "rules"
        bad.mkdir()
        (bad / "x.yml").write_text("title: x\ndetection:\n  s:\n    A|nope: 1\n  condition: s\n")
        code, _, err = run_cli("--evtx", str(self.evtx), "--rules", str(bad))
        self.assertEqual(code, 1)
        self.assertIn("Skipping rule x.yml", err)

    def test_case_name_cannot_escape_out_dir(self):
        code, _, _ = run_cli(*self.args(case="../../evil name"))
        self.assertEqual(code, 0)
        self.assertEqual([p.name for p in self.out.iterdir()], ["evil_name.html"])
        self.assertEqual(cli.safe_filename("///"), "case")
        self.assertEqual(cli.safe_filename("تقرير 1"), "تقرير_1")

    def test_parse_failure_is_reported_not_a_traceback(self):
        with mock.patch.object(cli, "parse_evtx_paths", side_effect=RuntimeError("python-evtx is required")), \
                contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(self.args())
        self.assertEqual(code, 1)
        self.assertIn("python-evtx", err.getvalue())


class ReportTests(unittest.TestCase):
    def test_html_escapes_event_data(self):
        evil = to_event({**SYNTHETIC_INCIDENT[0],
                         "CommandLine": "powershell -enc </script><img src=x onerror=alert(1)>AAAAAAAAAAAAAAAAAAAA",
                         "Computer": "<b>HOST</b>"})
        rules = load_rules_dir(ROOT / "rules")
        with tempfile.TemporaryDirectory() as d:
            path = render_html(build_timeline([evil], rules), "<svg onload=1>", ["a<b.evtx"], Path(d) / "r.html")
            html = path.read_text(encoding="utf-8")
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<svg onload", html)
        self.assertNotIn("<b>HOST</b>", html)
        self.assertEqual(html.count("</script>"), 1)  # only the template's own closing tag


class VersionTests(unittest.TestCase):
    def test_package_and_pyproject_versions_match(self):
        m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M)
        self.assertEqual(m.group(1), win_ir_triage.__version__)


if __name__ == "__main__":
    unittest.main()
