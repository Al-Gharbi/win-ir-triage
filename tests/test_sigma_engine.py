"""Unit tests for the Sigma-subset rule engine (sigma.py).

These run entirely against synthetic, hand-authored fixtures -- no real
EVTX files or third-party data are required, so `pytest` runs in well
under a second and works identically in CI.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from win_ir_triage import sigma  # noqa: E402
from tests.fixtures.synthetic_incident import SYNTHETIC_INCIDENT  # noqa: E402

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def make_rule(detection_yaml: str, condition: str, level: str = "high") -> sigma.SigmaRule:
    detection = yaml.safe_load(detection_yaml)
    return sigma.SigmaRule(
        rule_id="test", title="test", description="", level=level, tags=[],
        logsource={}, detection=detection, condition=condition, source_path="<test>",
    )


# --------------------------------------------------------------------
# Field-level matching
# --------------------------------------------------------------------

def test_plain_equality_is_case_insensitive():
    rule = make_rule("selection:\n  EventID: 4732\n  TargetUserName: 'administrators'", "selection")
    event = {"EventID": 4732, "TargetUserName": "Administrators"}
    assert sigma.evaluate_rule(rule, event) is True


def test_plain_equality_list_is_or():
    rule = make_rule("selection:\n  EventID:\n    - 1102\n    - 104", "selection")
    assert sigma.evaluate_rule(rule, {"EventID": 104}) is True
    assert sigma.evaluate_rule(rule, {"EventID": 999}) is False


def test_contains_modifier():
    rule = make_rule("selection:\n  CommandLine|contains: '-enc'", "selection")
    assert sigma.evaluate_rule(rule, {"CommandLine": "powershell.exe -Enc AAAA"}) is True
    assert sigma.evaluate_rule(rule, {"CommandLine": "powershell.exe -File a.ps1"}) is False


def test_endswith_modifier():
    rule = make_rule("selection:\n  Image|endswith: '\\lsass.exe'", "selection")
    assert sigma.evaluate_rule(rule, {"Image": r"C:\Windows\system32\lsass.exe"}) is True
    assert sigma.evaluate_rule(rule, {"Image": r"C:\Windows\system32\lsass.exe.bak"}) is False


def test_contains_all_requires_every_value():
    rule = make_rule(
        "selection:\n  TargetObject|contains|all:\n    - '_Classes\\'\n    - 'shell\\open\\command'",
        "selection",
    )
    hit = {"TargetObject": r"HKU\S-1-5-21-1_Classes\ms-settings\shell\open\command"}
    miss = {"TargetObject": r"HKU\S-1-5-21-1_Classes\SomethingElse"}
    assert sigma.evaluate_rule(rule, hit) is True
    assert sigma.evaluate_rule(rule, miss) is False


def test_hex_values_match_regardless_of_zero_padding():
    """Regression test: found while validating wit-004 against real Sysmon
    data -- GrantedAccess is zero-padded inconsistently across providers."""
    rule = make_rule("selection:\n  GrantedAccess: '0x1f1fff'", "selection")
    assert sigma.evaluate_rule(rule, {"GrantedAccess": "0x001f1fff"}) is True
    assert sigma.evaluate_rule(rule, {"GrantedAccess": "0x1f1fff"}) is True
    assert sigma.evaluate_rule(rule, {"GrantedAccess": "0x1400"}) is False


# --------------------------------------------------------------------
# Condition expression parser
# --------------------------------------------------------------------

@pytest.mark.parametrize(
    "condition,a,b,expected",
    [
        ("a and b", True, True, True),
        ("a and b", True, False, False),
        ("a or b", False, True, True),
        ("a and not b", True, False, True),
        ("(a and b) or (not a and not b)", False, False, True),
        ("not (a and b)", True, True, False),
    ],
)
def test_condition_boolean_logic(condition, a, b, expected):
    class FakeRule:
        pass
    rule = sigma.SigmaRule(
        rule_id="t", title="t", description="", level="low", tags=[], logsource={},
        detection={"a": {"X": "1"} if a else {"X": "nomatch"},
                   "b": {"Y": "1"} if b else {"Y": "nomatch"}},
        condition=condition, source_path="<t>",
    )
    event = {"X": "1", "Y": "1"}
    assert sigma.evaluate_rule(rule, event) is expected


# --------------------------------------------------------------------
# Rule pack sanity (every shipped .yml file must at least load)
# --------------------------------------------------------------------

def test_all_shipped_rules_load_without_error():
    rules = sigma.load_rules_dir(RULES_DIR)
    assert len(rules) >= 10
    for r in rules:
        assert r.title
        assert r.condition
        assert r.detection


def test_mitre_ids_are_extracted_from_tags():
    rules = sigma.load_rules_dir(RULES_DIR)
    admins_rule = next(r for r in rules if r.rule_id == "wit-001")
    assert "T1136.001" in admins_rule.mitre_technique_ids


# --------------------------------------------------------------------
# End-to-end against the synthetic incident fixture
# --------------------------------------------------------------------

def test_synthetic_incident_triggers_expected_rules():
    rules = sigma.load_rules_dir(RULES_DIR)
    hits = sigma.scan(SYNTHETIC_INCIDENT, rules)
    fired_ids = {h["rule"].rule_id for h in hits}

    # Every technique deliberately written into the fixture should fire.
    assert "wit-001" in fired_ids  # added to Administrators
    assert "wit-003" in fired_ids  # log cleared
    assert "wit-004" in fired_ids  # lsass access
    assert "wit-005" in fired_ids  # encoded hidden powershell
    assert "wit-007" in fired_ids  # suspicious service (cmd.exe ImagePath)


def test_benign_logon_event_is_not_flagged():
    """The fixture intentionally includes one normal interactive logon
    (EventID 4624, LogonType 2) -- it must not trip any rule."""
    rules = sigma.load_rules_dir(RULES_DIR)
    benign = next(e for e in SYNTHETIC_INCIDENT if e["EventID"] == 4624 and e.get("LogonType") == "2")
    hits = sigma.scan([benign], rules)
    assert hits == []
