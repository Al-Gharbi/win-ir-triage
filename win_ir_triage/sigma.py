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
    - `*` / `?` wildcards in plain (modifier-less) values
    - `Field: null` (field absent or empty)
    - a block given as a list of maps (OR of the maps)
    - `condition` as a boolean expression over block names using
      `and`, `or`, `not`, parentheses and the quantifiers
      `1 of <pattern>`, `all of <pattern>`, `1 of them`, `all of them`
      (`<pattern>` may end in `*`), e.g. "selection and not 1 of filter_*"

Rules are validated when they are loaded: an unknown modifier, an invalid
regular expression, a malformed `condition` or a `condition` that names a
block that does not exist raises `RuleError` and the rule is skipped with a
visible message. They are never silently ignored at match time.

Deliberately NOT supported:
    - correlation rules / timeframes / `near`
    - keyword (field-less) searches and list-of-strings blocks
    - `logsource` is stored but NOT used to pre-filter events: a rule is
      evaluated against every event, so rules must pin down their events
      with `EventID` / `Channel` themselves (the bundled rules do)

Rules are matched with a small hand-written recursive-descent parser for
the `condition` expression instead of Python's eval(), since shelling out
to eval() on rule-file content is exactly the kind of shortcut a security
tool shouldn't take even when the input is "trusted".
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

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


class RuleError(ValueError):
    """A rule file is unreadable or uses something this engine cannot evaluate."""


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
LEVELS = ("informational", "low", "medium", "high", "critical")


def load_rule(path: str | Path) -> SigmaRule:
    path = Path(path)
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("detection"), dict):
        raise RuleError(f"{path.name}: missing 'detection' mapping")

    detection = dict(raw["detection"])
    condition = detection.pop("condition", "selection")
    if not isinstance(condition, str):
        raise RuleError(f"{path.name}: 'condition' must be a single string")

    level = str(raw.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"{path.name}: unknown level {level!r} (use one of {', '.join(LEVELS)})")

    rule = SigmaRule(
        rule_id=str(raw.get("id", path.stem)),
        title=raw.get("title", path.stem),
        description=raw.get("description", ""),
        level=level,
        tags=list(raw.get("tags", [])),
        logsource=dict(raw.get("logsource", {})),
        detection=detection,
        condition=condition,
        source_path=str(path),
    )
    validate_rule(rule)
    return rule


def validate_rule(rule: SigmaRule) -> None:
    """Raise RuleError if the rule cannot be evaluated faithfully."""
    name = Path(rule.source_path).name
    if not rule.detection:
        raise RuleError(f"{name}: no detection blocks")
    for block_name, block in rule.detection.items():
        for clause in _block_maps(block, name, block_name):
            for field_expr, expected in clause.items():
                parts = str(field_expr).split("|")
                bad = [m for m in parts[1:] if m not in SUPPORTED_MODIFIERS]
                if bad:
                    raise RuleError(
                        f"{name}: block '{block_name}' uses unsupported modifier "
                        f"|{bad[0]} on {parts[0]}"
                    )
                mods = parts[1:]
                if "re" in mods:
                    for v in _as_list(expected):
                        try:
                            re.compile(str(v))
                        except re.error as exc:
                            raise RuleError(f"{name}: invalid regex {v!r}: {exc}") from exc
    try:
        # Dry run: syntax and block-name resolution.
        _ConditionParser(rule.condition, {n: True for n in rule.detection}).parse()
    except RuleError as exc:
        raise RuleError(f"{name}: {exc}") from exc


def _block_maps(block: Any, rule_name: str = "", block_name: str = "") -> list[dict]:
    if isinstance(block, dict):
        return [block]
    if isinstance(block, list) and block and all(isinstance(b, dict) for b in block):
        return list(block)
    raise RuleError(
        f"{rule_name}: block '{block_name}' must be a mapping or a list of mappings "
        "(keyword/list-of-strings blocks are not supported)"
    )


def load_rules_dir(
    directory: str | Path,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> list[SigmaRule]:
    """Load every *.yml / *.yaml rule in a directory.

    Rules that fail validation are skipped and reported through ``on_error``
    (default: a line on stderr), so a bad rule is never silent.
    """
    directory = Path(directory)
    rules: list[SigmaRule] = []
    seen_ids: dict[str, Path] = {}
    for p in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        try:
            rule = load_rule(p)
            if rule.rule_id in seen_ids:
                raise RuleError(f"duplicate rule id {rule.rule_id!r} (also in {seen_ids[rule.rule_id].name})")
            seen_ids[rule.rule_id] = p
            rules.append(rule)
        except RuleError as exc:
            if on_error:
                on_error(p, exc)
            else:
                print(f"[!] Skipping rule {p.name}: {exc}", file=sys.stderr)
    return rules


# --------------------------------------------------------------------------
# Field matching (selection blocks)
# --------------------------------------------------------------------------

def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _looks_hex(s: str) -> bool:
    s = s.strip().lower()
    return s.startswith("0x") and len(s) > 2 and all(c in "0123456789abcdef" for c in s[2:])


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    out = []
    for ch in pattern:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL)


def _str_eq(event_val: Any, target: Any) -> bool:
    if target is None:  # `Field: null` -> field absent or empty
        return event_val is None or str(event_val) == ""
    if event_val is None:
        return False
    ev, tv = str(event_val).strip(), str(target).strip()
    if ev.casefold() == tv.casefold():
        return True
    if ("*" in tv or "?" in tv) and _wildcard_to_regex(tv).fullmatch(ev):
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

    string_mods = [m for m in modifiers if m != "all"]
    if not string_mods:
        results = [_str_eq(event_val, v) for v in _as_list(expected)]
        return all(results) if "all" in modifiers else any(results)

    modifier = string_mods[0]
    combine_all = "all" in modifiers

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
        raise RuleError(f"unsupported modifier |{modifier}")  # unreachable after validation

    results = [one(v) for v in _as_list(expected)]
    return all(results) if combine_all else any(results)


def _match_block(event: dict[str, Any], block: Any) -> bool:
    """A mapping is an implicit AND of its clauses; a list of mappings is an OR."""
    maps = block if isinstance(block, list) else [block]
    return any(
        all(_match_single_field(event, k, v) for k, v in m.items()) for m in maps
    )


# --------------------------------------------------------------------------
# Condition expression parser (hand-written, no eval())
# --------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9_*]+|\S", re.IGNORECASE)


class _ConditionParser:
    """Recursive-descent parser/evaluator for Sigma `condition` strings:

        or_expr  := and_expr ('or' and_expr)*
        and_expr := not_expr ('and' not_expr)*
        not_expr := 'not' not_expr | atom
        atom     := '(' or_expr ')' | ('1'|'all') 'of' (NAME_PATTERN|'them') | NAME

    Anything else (unknown block names, unbalanced parentheses, leftover
    tokens) raises RuleError instead of being ignored.
    """

    def __init__(self, expr: str, block_results: dict[str, bool]):
        self.tokens = _TOKEN_RE.findall(expr)
        self.pos = 0
        self.block_results = block_results

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _peek_kw(self) -> str | None:
        t = self._peek()
        return t.lower() if t else None

    def _advance(self) -> str | None:
        tok = self._peek()
        self.pos += 1
        return tok

    def parse(self) -> bool:
        if not self.tokens:
            raise RuleError("empty condition")
        result = self._or_expr()
        if self._peek() is not None:
            raise RuleError(f"unexpected token {self._peek()!r} in condition")
        return result

    def _or_expr(self) -> bool:
        value = self._and_expr()
        while self._peek_kw() == "or":
            self._advance()
            rhs = self._and_expr()  # always parse both sides: errors must surface
            value = value or rhs
        return value

    def _and_expr(self) -> bool:
        value = self._not_expr()
        while self._peek_kw() == "and":
            self._advance()
            rhs = self._not_expr()
            value = value and rhs
        return value

    def _not_expr(self) -> bool:
        if self._peek_kw() == "not":
            self._advance()
            return not self._not_expr()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._advance()
        if tok is None:
            raise RuleError("condition ends unexpectedly")
        if tok == "(":
            value = self._or_expr()
            if self._advance() != ")":
                raise RuleError("missing ')' in condition")
            return value
        if tok == ")":
            raise RuleError("unexpected ')' in condition")
        if tok.lower() in ("1", "all") and self._peek_kw() == "of":
            self._advance()  # 'of'
            target = self._advance()
            if target is None:
                raise RuleError(f"'{tok} of' needs a block pattern or 'them'")
            names = self._select(target)
            results = [self.block_results[n] for n in names]
            return any(results) if tok == "1" else all(results)
        if tok.lower() in ("and", "or", "not", "of"):
            raise RuleError(f"unexpected keyword {tok!r} in condition")
        if tok not in self.block_results:
            raise RuleError(f"condition refers to unknown block {tok!r}")
        return bool(self.block_results[tok])

    def _select(self, pattern: str) -> list[str]:
        if pattern.lower() == "them":
            names = list(self.block_results)
        elif "*" in pattern:
            rx = re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$")
            names = [n for n in self.block_results if rx.match(n)]
        else:
            names = [pattern] if pattern in self.block_results else []
        if not names:
            raise RuleError(f"pattern {pattern!r} matches no detection block")
        return names


def evaluate_rule(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """Return True if `event` (a flat dict, see parser.NormalizedEvent.as_dict())
    satisfies this rule's detection logic."""
    block_results = {name: _match_block(event, block) for name, block in rule.detection.items()}
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
