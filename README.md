# win-ir-triage

**Windows Incident Response Triage & Timeline Builder.** Parses Windows EVTX
event logs, runs them through a real Sigma-format detection rule engine
(hand-written evaluator, no `eval()`), correlates hits against MITRE
ATT&CK, and produces a bilingual (English/Arabic, full RTL) HTML incident
timeline — plus JSON and ATT&CK Navigator exports for feeding into other
tooling.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://github.com/Al-Gharbi/win-ir-triage/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)

## Why this exists

Most of the individual pieces here (EVTX parsing, Sigma rules, MITRE
mapping) already exist as mature, separate tools. What's usually missing
in a fast triage scenario is the glue: point it at a handful of exported
logs, get one chronological, prioritized, MITRE-tagged view back —
without standing up a full SIEM first. This is meant for the first 30
minutes of a case, not as a Splunk/Elastic replacement.

## Features

- **Real Sigma-format rules** — a genuine (documented) subset of the
  [Sigma](https://github.com/SigmaHQ/sigma) YAML detection format:
  named selection/filter blocks, `contains` / `startswith` / `endswith` /
  `re` modifiers, list-as-OR and `|all` list-as-AND, and boolean
  `condition` expressions (`and` / `or` / `not` / parentheses) — matched
  with a small hand-written recursive-descent parser, not `eval()`.
- **10 bundled detection rules** spanning Persistence, Defense Evasion,
  Credential Access, Execution, Privilege Escalation, Lateral Movement
  and Discovery (see [table below](#bundled-rule-pack)).
- **MITRE ATT&CK correlation**, including a ready-to-import
  [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
  layer export.
- **Bilingual HTML report** (EN/Arabic, live-toggle, proper RTL layout) —
  built for analysts and stakeholders who work in Arabic, not just an
  afterthought translation.
- **JSON export** for piping into other tooling.
- Handles both classic **Windows Security auditing** events and
  **Sysmon** events (and the `<UserData>`-based schema some providers,
  e.g. the log-clear event, use instead of `<EventData>`).

## How it works

```
 .evtx files            rules/*.yml (Sigma subset)
      |                          |
      v                          v
 parser.py  ---------------->  sigma.py
 (flatten to one record       (evaluate every rule
  per event, System +          against every event)
  EventData/UserData in
  one namespace)
      |                          |
      +----------> timeline.py <-+
                  (sort chronologically,
                   attach hits, summarize)
                        |
                        v
                    report.py
            (bilingual HTML / JSON / Navigator layer)
```

Events are flattened into one flat dict per record (`EventID`, `Channel`,
`Computer`, plus every `<Data Name="X">` field merged into the same
namespace) specifically so rule files can reference fields the same way
real-world Sigma rules do (`Image`, `TargetUserName`, `GrantedAccess`,
...) with no translation layer.

## Installation

```bash
git clone https://github.com/Al-Gharbi/win-ir-triage.git
cd win-ir-triage
pip install -r requirements.txt
```

Requires Python 3.10+ (uses `from __future__ import annotations` and
modern type-hint syntax throughout).

## Usage

```bash
python -m win_ir_triage \
  --evtx Security.evtx Microsoft-Windows-Sysmon%4Operational.evtx \
  --rules rules/ \
  --case-name "HOST01-2026-05-11" \
  --out-dir out/ \
  --json --navigator
```

This prints a console summary (severity counts, MITRE techniques touched)
and writes `out/HOST01-2026-05-11.html` (open directly in a browser —
fully self-contained, no external assets), plus optionally a `.json`
timeline and a `.navigator.json` ATT&CK layer.

See [`examples/sample_report.html`](examples/sample_report.html) for a
full example report (generated from the synthetic fixture described
below, not real data).

## Bundled rule pack

| ID | Title | Tactic | MITRE |
|----|-------|--------|-------|
| wit-001 | Member Added to Local Administrators Group | Persistence / Priv Esc | T1098, T1136.001 |
| wit-002 | New Local User Account Created | Persistence | T1136.001 |
| wit-003 | Windows Event Log Cleared | Defense Evasion | T1070.001 |
| wit-004 | Suspicious LSASS Process Access | Credential Access | T1003.001 |
| wit-005 | Suspicious Encoded/Hidden-Window PowerShell | Execution | T1059.001 |
| wit-006 | UAC Bypass via Registry Hijack (Fodhelper/EventVwr-style) | Privilege Escalation | T1548.002 |
| wit-007 | Suspicious Service Installation (PsExec-style) | Lateral Movement | T1569.002 |
| wit-008 | Host/Network Reconnaissance Commands | Discovery | T1087, T1082, T1016 |
| wit-009 | Explicit Credential Logon / Interactive RDP | Lateral Movement | T1078, T1021.001 |
| wit-010 | Office/PDF App Spawning a Command Interpreter | Initial Access / Execution | T1566.001, T1204.002 |

Writing your own rules is just adding a `.yml` file to `rules/` — see
[`rules/persistence_account_added_to_admins.yml`](rules/persistence_account_added_to_admins.yml)
for a minimal example and the [Sigma subset spec](#sigma-subset-supported--not-supported) below.

## Sigma subset: supported / not supported

**Supported:** named `detection` blocks combined via a `condition` string
(`and`/`or`/`not`/parentheses); field matching with `|contains`,
`|startswith`, `|endswith`, `|re`; list values as OR; `|all` combinable
modifier for AND-across-list; case-insensitive string matching; numeric
comparison for hex fields regardless of zero-padding (see
[Methodology](#methodology--validation) below for why that last one
exists).

**Not (yet) supported** — documented here rather than silently failing:
`1 of selection*` / `all of them` aggregate quantifiers, Sigma
correlation rules / `near()` timeframes, and the full official Sigma
value-list extensions. A rule using these will load but the unsupported
parts are simply not evaluated — check
[`win_ir_triage/sigma.py`](win_ir_triage/sigma.py) if in doubt about a
specific rule. Real conversion to SIEM query languages (Splunk SPL,
Elastic, Sentinel KQL) is intentionally out of scope for this tool —
that's a solved problem ([`pySigma`](https://github.com/SigmaHQ/pySigma)
does it well); this project is about **direct, local, no-SIEM-required
evaluation**, which is a different use case.

**⚠️ One documented YAML gotcha:** if a rule needs two conditions on the
*same field* inside one selection block, you cannot repeat the key
(`Image|contains: 'a'` then `Image|contains: 'b'` in the same mapping) —
YAML silently keeps only the last one. Use a list with the `|all`
modifier instead: `Image|contains|all: ['a', 'b']`. This is exactly the
bug caught during development of `wit-006` (see below).

## Methodology / validation

Every bundled rule was validated during development against real,
technique-labeled samples from
[**EVTX-ATTACK-SAMPLES**](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(Samir Bousseaden) — a well-known public corpus of EVTX exports, each
capturing one specific ATT&CK technique. That dataset is **not bundled**
in this repository (it's GPL-licensed and fairly large); clone it
separately if you want to reproduce the validation or stress-test new
rules against real technique samples.

That testing process caught two real bugs, both left as regression tests
so they can't silently come back:

1. **Hex zero-padding mismatch** — Sysmon's `GrantedAccess` field is
   zero-padded inconsistently (`0x1f1fff` vs `0x001f1fff`) depending on
   provider/OS version, which broke plain string-equality matching on the
   LSASS-access rule against a real sample. Fixed by comparing
   hex-looking values numerically. See
   `test_hex_values_match_regardless_of_zero_padding` in
   `tests/test_sigma_engine.py`.
2. **Duplicate YAML keys silently collide** — an early draft of the UAC
   bypass rule (`wit-006`) had two `TargetObject|contains:` keys in the
   same block; YAML kept only the second, silently dropping the first
   condition. Rewritten using `|contains|all` (see the gotcha above).

The unit test suite (`tests/`) itself uses a small, fully **original,
hand-authored synthetic incident fixture**
(`tests/fixtures/synthetic_incident.py`) rather than bundling third-party
sample data — it's a fictional, dramatized single-host scenario (phishing
attachment → encoded PowerShell → credential dumping → backdoor admin
account → lateral movement → log clearing) invented to exercise every
bundled rule plus one deliberately benign event, so the suite has zero
external data dependencies and runs in well under a second. The example
report in `examples/` is generated from this same fixture.

```bash
pytest tests/ -v
```

## Roadmap

- Registry hive parsing (Run/RunOnce keys, UserAssist) to widen coverage
  beyond event-log-based artifacts
- `1 of selection*` / `all of them` Sigma quantifier support
- Optional real `pySigma` backend for SIEM-query export alongside the
  local evaluator
- Prefetch / Amcache / ShimCache ingestion

## License

MIT — see [LICENSE](LICENSE).

## Credits

Rule validation performed against the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
dataset by Samir Bousseaden (not redistributed here — see
[Methodology](#methodology--validation)). Detection logic is inspired by
the [Sigma](https://github.com/SigmaHQ/sigma) project and the
[MITRE ATT&CK](https://attack.mitre.org) framework.
