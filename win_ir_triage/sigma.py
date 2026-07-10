"""
sigma.py
--------
A small, dependency-free evaluator for a practical subset of the Sigma
detection rule format (https://github.com/SigmaHQ/sigma).

Supported:
    - Multiple named blocks under `detection` (selection, filter, ...)
    - Field: value                      -> exact match (case-insensitive for strings)
    - Field: [v1, v2, ...]              -> OR match (value equals any of these)
    - Field|contains: value             -> substring match
    - Field|contains: [v1, v2]          -> OR of substrings
    - Field|contains|all: [v1, v2]      -> AND of substrings (all must appear)
    - Field|startswith: value / Field|endswith: value
    - Field|re: value                   -> regular expression search
    - `condition` as a boolean expression over block names using
      `and`, `or`, `not`, and parentheses, e.g. "selection and not filter"

Deliberately NOT supported (documented as roadmap in README):
    - "1 of selection*" / "all of them" aggregate quantifiers
    - correlation rules / near-miss timeframes
    - the full Sigma value-list / near() extensions

Rules are matched with a small hand-written recursive-descent parser for
the `condition` expression instead of Python's eval(), since shelling out
to eval() on rule-file content is exactly the kind of shortcut a security
tool shouldn't take even when the input is "trusted".
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


# --------------------------------------------------------------------------
# Rule representation
# --------------------------------------------------------------------------

@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    level: str
    tags: list[str]
    logsource: dict[str, Any]
    detection: dict[str, Any]
    condition: str
    source_path: str

    @property
    def mitre_technique_ids(self) -> list[str]:
        ids = []
        for tag in self.tags:
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
            if m:
                ids.append(m.group(1).upper())
        return ids


def load_rule(path: str | Path) -> SigmaRule:
    path = Path(path)
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    detection = dict(raw.get("detection", {}))
    condition = detection.pop("condition", "selection")

    return SigmaRule(
        rule_id=str(raw.get("id", path.stem)),
        title=raw.get("title", path.stem),
        description=raw.get("description", ""),
        level=raw.get("level", "medium"),
        tags=list(raw.get("tags", [])),
        logsource=dict(raw.get("logsource", {})),
        detection=detection,
        condition=condition,
        source_path=str(path),
    )


def load_rules_dir(directory: str | Path) -> list[SigmaRule]:
    directory = Path(directory)
    rules = []
    for p in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        try:
            rules.append(load_rule(p))
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a skip
            print(f"[!] Skipping unreadable rule {p}: {exc}")
    return rules


# --------------------------------------------------------------------------
# Field matching (selection blocks)
# --------------------------------------------------------------------------

def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _looks_hex(s: str) -> bool:
    s = s.strip().lower()
    return s.startswith("0x") and len(s) > 2 and all(c in "0123456789abcdef" for c in s[2:])


def _str_eq(event_val: Any, target: Any) -> bool:
    if event_val is None:
        return False
    ev, tv = str(event_val).strip(), str(target).strip()
    if ev.casefold() == tv.casefold():
        return True
    # Windows event fields (e.g. Sysmon GrantedAccess) are inconsistently
    # zero-padded across providers/OS versions ("0x1f1fff" vs "0x001f1fff").
    # Compare numerically whenever both sides parse as hex so rules don't
    # silently miss real hits over formatting alone.
    if _looks_hex(ev) and _looks_hex(tv):
        try:
            return int(ev, 16) == int(tv, 16)
        except ValueError:
            return False
    return False


def _match_single_field(event: dict[str, Any], field_expr: str, expected: Any) -> bool:
    """Evaluate one `Field[|modifier[|modifier2]]: expected` clause."""
    parts = field_expr.split("|")
    field_name, modifiers = parts[0], parts[1:]
    event_val = event.get(field_name)

    if not modifiers:
        # Plain equality; list of expected values means OR.
        return any(_str_eq(event_val, v) for v in _as_list(expected))

    modifier = modifiers[0]
    combine_all = "all" in modifiers[1:]
    expected_values = _as_list(expected)

    if event_val is None:
        return False
    haystack = str(event_val)

    def one(target: Any) -> bool:
        target = str(target)
        if modifier == "contains":
            return target.casefold() in haystack.casefold()
        if modifier == "startswith":
            return haystack.casefold().startswith(target.casefold())
        if modifier == "endswith":
            return haystack.casefold().endswith(target.casefold())
        if modifier == "re":
            return re.search(target, haystack, re.IGNORECASE) is not None
        raise ValueError(f"Unsupported Sigma modifier: |{modifier}")

    results = [one(v) for v in expected_values]
    return all(results) if combine_all else any(results)


def _match_block(event: dict[str, Any], block: dict[str, Any]) -> bool:
    """A block (e.g. `selection:`) is an implicit AND of all its field clauses."""
    return all(_match_single_field(event, k, v) for k, v in block.items())


# --------------------------------------------------------------------------
# Condition expression parser (hand-written, no eval())
# --------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|\bnot\b|\band\b|\bor\b|[A-Za-z_][A-Za-z0-9_]*", re.IGNORECASE)


class _ConditionParser:
    """Recursive-descent parser/evaluator for `selection and not filter` style
    boolean expressions over pre-computed block match results."""

    def __init__(self, expr: str, block_results: dict[str, bool]):
        self.tokens = [t.strip() for t in _TOKEN_RE.findall(expr)]
        self.pos = 0
        self.block_results = block_results

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _advance(self) -> str | None:
        tok = self._peek()
        self.pos += 1
        return tok

    def parse(self) -> bool:
        result = self._or_expr()
        return result

    def _or_expr(self) -> bool:
        value = self._and_expr()
        while self._peek() and self._peek().lower() == "or":
            self._advance()
            rhs = self._and_expr()
            value = value or rhs
        return value

    def _and_expr(self) -> bool:
        value = self._not_expr()
        while self._peek() and self._peek().lower() == "and":
            self._advance()
            rhs = self._not_expr()
            value = value and rhs
        return value

    def _not_expr(self) -> bool:
        if self._peek() and self._peek().lower() == "not":
            self._advance()
            return not self._not_expr()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._advance()
        if tok == "(":
            value = self._or_expr()
            if self._peek() == ")":
                self._advance()
            return value
        if tok is None:
            return False
        # A bare identifier: look up its precomputed block result.
        return bool(self.block_results.get(tok, False))


def evaluate_rule(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """Return True if `event` (a flat dict, see parser.NormalizedEvent.as_dict())
    satisfies this rule's detection logic."""
    block_results = {
        name: _match_block(event, block)
        for name, block in rule.detection.items()
        if isinstance(block, dict)
    }
    if not block_results:
        return False
    return _ConditionParser(rule.condition, block_results).parse()


def scan(events: list[dict[str, Any]], rules: list[SigmaRule]) -> list[dict[str, Any]]:
    """Run every rule against every event; return a list of hit descriptors."""
    hits = []
    for event in events:
        for rule in rules:
            if evaluate_rule(rule, event):
                hits.append({"event": event, "rule": rule})
    return hits
