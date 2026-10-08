"""Unit tests for the Sigma-subset engine (sigma.py). Pure unittest (also run by pytest)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from win_ir_triage import sigma  # noqa: E402
from tests.fixtures.synthetic_incident import SYNTHETIC_INCIDENT  # noqa: E402

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def make_rule(detection_yaml: str, condition: str, level: str = "high") -> sigma.SigmaRule:
    rule = sigma.SigmaRule(
        rule_id="test", title="test", description="", level=level, tags=[],
        logsource={}, detection=yaml.safe_load(detection_yaml), condition=condition,
        source_path="<test>",
    )
    sigma.validate_rule(rule)
    return rule


def ev(rule, event) -> bool:
    return sigma.evaluate_rule(rule, event)


class FieldMatching(unittest.TestCase):
    def test_plain_equality_is_case_insensitive(self):
        r = make_rule("selection:\n  EventID: 4732\n  TargetUserName: 'administrators'", "selection")
        self.assertTrue(ev(r, {"EventID": 4732, "TargetUserName": "Administrators"}))

    def test_plain_list_is_or(self):
        r = make_rule("selection:\n  EventID:\n    - 1102\n    - 104", "selection")
        self.assertTrue(ev(r, {"EventID": 104}))
        self.assertFalse(ev(r, {"EventID": 999}))

    def test_contains_startswith_endswith(self):
        r = make_rule("selection:\n  CommandLine|contains: '-enc'", "selection")
        self.assertTrue(ev(r, {"CommandLine": "powershell.exe -Enc AAAA"}))
        self.assertFalse(ev(r, {"CommandLine": "powershell.exe -File a.ps1"}))
        r = make_rule("selection:\n  Image|endswith: '\\lsass.exe'", "selection")
        self.assertTrue(ev(r, {"Image": r"C:\Windows\system32\lsass.exe"}))
        self.assertFalse(ev(r, {"Image": r"C:\Windows\system32\lsass.exe.bak"}))
        r = make_rule("selection:\n  Image|startswith: 'C:\\Windows'", "selection")
        self.assertTrue(ev(r, {"Image": r"c:\windows\x.exe"}))

    def test_contains_all_requires_every_value(self):
        r = make_rule("selection:\n  T|contains|all:\n    - '_Classes\\'\n    - 'shell\\open\\command'", "selection")
        self.assertTrue(ev(r, {"T": r"HKU\S-1_Classes\ms-settings\shell\open\command"}))
        self.assertFalse(ev(r, {"T": r"HKU\S-1_Classes\Other"}))

    def test_regex(self):
        r = make_rule("selection:\n  C|re: '\\s-e[a-z]*\\s+[A-Za-z0-9+/=]{8,}'", "selection")
        self.assertTrue(ev(r, {"C": "powershell -EncodedCommand AAAABBBBCCCC"}))
        self.assertFalse(ev(r, {"C": "powershell -ExecutionPolicy Bypass"}))

    def test_wildcards_in_plain_values(self):
        r = make_rule("selection:\n  Image: '*\\cmd.exe'", "selection")
        self.assertTrue(ev(r, {"Image": r"C:\Windows\System32\cmd.exe"}))
        self.assertFalse(ev(r, {"Image": r"C:\Windows\System32\cmd.exe.txt"}))

    def test_null_means_absent_or_empty(self):
        r = make_rule("selection:\n  User: null", "selection")
        self.assertTrue(ev(r, {}))
        self.assertTrue(ev(r, {"User": ""}))
        self.assertFalse(ev(r, {"User": "bob"}))

    def test_missing_field_never_matches_modifier(self):
        r = make_rule("selection:\n  Image|endswith: '.exe'", "selection")
        self.assertFalse(ev(r, {}))

    def test_list_of_maps_is_or_of_ands(self):
        r = make_rule("selection:\n  - A: 1\n    B: 2\n  - C: 3", "selection")
        self.assertTrue(ev(r, {"A": 1, "B": 2}))
        self.assertTrue(ev(r, {"C": 3}))
        self.assertFalse(ev(r, {"A": 1}))

    def test_hex_values_match_regardless_of_zero_padding(self):
        r = make_rule("selection:\n  GrantedAccess: '0x1f1fff'", "selection")
        self.assertTrue(ev(r, {"GrantedAccess": "0x001f1fff"}))
        self.assertTrue(ev(r, {"GrantedAccess": "0x1f1fff"}))
        self.assertFalse(ev(r, {"GrantedAccess": "0x1400"}))


class Conditions(unittest.TestCase):
    def rule(self, cond, a, b):
        return sigma.SigmaRule(
            rule_id="t", title="t", description="", level="low", tags=[], logsource={},
            detection={"a": {"X": "1"} if a else {"X": "no"}, "b": {"Y": "1"} if b else {"Y": "no"}},
            condition=cond, source_path="<t>")

    def test_boolean_logic(self):
        cases = [("a and b", True, True, True), ("a and b", True, False, False),
                 ("a or b", False, True, True), ("a and not b", True, False, True),
                 ("(a and b) or (not a and not b)", False, False, True),
                 ("not (a and b)", True, True, False)]
        for cond, a, b, want in cases:
            with self.subTest(cond=cond, a=a, b=b):
                self.assertIs(ev(self.rule(cond, a, b), {"X": "1", "Y": "1"}), want)

    def test_precedence_and_binds_tighter_than_or(self):
        # a or b and not a  ==  a or (b and not a)
        r = make_rule("a:\n  X: 1\nb:\n  Y: 1", "a or b and not a")
        self.assertTrue(ev(r, {"X": 1, "Y": 1}))

    def test_quantifiers(self):
        det = "selection_a:\n  A: 1\nselection_b:\n  B: 1\nfilter_x:\n  C: 1"
        r = make_rule(det, "1 of selection_* and not filter_x")
        self.assertTrue(ev(r, {"B": 1}))
        self.assertFalse(ev(r, {"B": 1, "C": 1}))
        self.assertFalse(ev(r, {}))
        r = make_rule(det, "all of selection_*")
        self.assertTrue(ev(r, {"A": 1, "B": 1}))
        self.assertFalse(ev(r, {"A": 1}))
        self.assertTrue(ev(make_rule(det, "1 of them"), {"C": 1}))
        self.assertFalse(ev(make_rule(det, "all of them"), {"C": 1}))
        self.assertTrue(ev(make_rule(det, "1 of filter_x"), {"C": 1}))

    def test_invalid_conditions_are_rejected_not_ignored(self):
        det = "selection:\n  A: 1\nfilter:\n  B: 1"
        for cond in ("selection and nonexistent", "selection and", "(selection", "selection)",
                     "selection filter", "1 of nothing_*", "", "and selection", "not"):
            with self.subTest(cond=cond):
                with self.assertRaises(sigma.RuleError):
                    make_rule(det, cond)


class Validation(unittest.TestCase):
    def test_unknown_modifier_rejected_at_load(self):
        with self.assertRaises(sigma.RuleError):
            make_rule("selection:\n  A|base64offset|contains: x", "selection")

    def test_bad_regex_rejected_at_load(self):
        with self.assertRaises(sigma.RuleError):
            make_rule("selection:\n  A|re: '(unclosed'", "selection")

    def test_keyword_block_rejected(self):
        with self.assertRaises(sigma.RuleError):
            make_rule("selection:\n  - foo\n  - bar", "selection")

    def _load_dir(self, files: dict[str, str]):
        errors = []
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                (Path(d) / name).write_text(text, encoding="utf-8")
            rules = sigma.load_rules_dir(d, on_error=lambda p, e: errors.append((p.name, str(e))))
        return rules, errors

    GOOD = "title: ok\nid: r1\nlevel: low\ndetection:\n  selection:\n    A: 1\n  condition: selection\n"

    def test_bad_rule_is_skipped_visibly_and_good_rules_survive(self):
        rules, errors = self._load_dir({
            "good.yml": self.GOOD,
            "bad.yml": "title: bad\nid: r2\ndetection:\n  selection:\n    A|nope: 1\n  condition: selection\n",
            "broken.yml": "title: [unterminated\n",
            "nodet.yml": "title: x\n",
        })
        self.assertEqual([r.rule_id for r in rules], ["r1"])
        self.assertEqual(sorted(n for n, _ in errors), ["bad.yml", "broken.yml", "nodet.yml"])

    def test_duplicate_ids_and_unknown_level_rejected(self):
        rules, errors = self._load_dir({
            "a.yml": self.GOOD,
            "b.yml": self.GOOD,
            "c.yml": self.GOOD.replace("id: r1", "id: r3").replace("level: low", "level: urgent"),
        })
        self.assertEqual(len(rules), 1)
        self.assertEqual(sorted(n for n, _ in errors), ["b.yml", "c.yml"])


class ShippedRules(unittest.TestCase):
    def test_all_shipped_rules_load_without_error(self):
        errors = []
        rules = sigma.load_rules_dir(RULES_DIR, on_error=lambda p, e: errors.append((p.name, str(e))))
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), len(list(RULES_DIR.glob("*.yml"))))
        self.assertGreaterEqual(len(rules), 10)

    def test_mitre_ids_are_extracted_from_tags(self):
        rules = sigma.load_rules_dir(RULES_DIR)
        admins = next(r for r in rules if r.rule_id == "wit-001")
        self.assertIn("T1098", admins.mitre_technique_ids)
        self.assertIn("T1059.001", next(r for r in rules if r.rule_id == "wit-005").mitre_technique_ids)

    def test_every_mitre_id_used_by_rules_is_in_the_lookup(self):
        from win_ir_triage import mitre
        for r in sigma.load_rules_dir(RULES_DIR):
            for tid in r.mitre_technique_ids:
                with self.subTest(rule=r.rule_id, tid=tid):
                    self.assertIn(tid, mitre.TECHNIQUES)

    def test_synthetic_incident_triggers_expected_rules(self):
        fired = {h["rule"].rule_id for h in sigma.scan(SYNTHETIC_INCIDENT, sigma.load_rules_dir(RULES_DIR))}
        for rid in ("wit-001", "wit-002", "wit-003", "wit-004", "wit-005", "wit-007", "wit-010"):
            with self.subTest(rule=rid):
                self.assertIn(rid, fired)

    def test_benign_logon_event_is_not_flagged(self):
        benign = next(e for e in SYNTHETIC_INCIDENT if e["EventID"] == 4624 and e.get("LogonType") == "2")
        self.assertEqual(sigma.scan([benign], sigma.load_rules_dir(RULES_DIR)), [])


if __name__ == "__main__":
    unittest.main()
