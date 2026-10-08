# win-ir-triage

**Windows Incident Response Triage & Timeline Builder.** Parses Windows EVTX
event logs, runs them through a small evaluator for a documented subset of
the Sigma rule format (hand-written, no `eval()`), correlates hits against MITRE
ATT&CK, and produces a bilingual (English/Arabic, full RTL) HTML incident
timeline — plus JSON and ATT&CK Navigator exports for feeding into other
tooling.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
[![CI](https://github.com/Al-Gharbi/win-ir-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/Al-Gharbi/win-ir-triage/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-green)

## Why this exists

Most of the individual pieces here (EVTX parsing, Sigma rules, MITRE
mapping) already exist as mature, separate tools. What's usually missing
in a fast triage scenario is the glue: point it at a handful of exported
logs, get one chronological, prioritized, MITRE-tagged view back —
without standing up a full SIEM first. This is meant for the first 30
minutes of a case, not as a Splunk/Elastic replacement.

## Features

- **A documented subset of the [Sigma](https://github.com/SigmaHQ/sigma)
  rule format** — named selection/filter blocks, `contains` / `startswith` /
  `endswith` / `re` modifiers, `*` / `?` wildcards, `null`, list-as-OR and
  `|all`, and `condition` expressions with `and` / `or` / `not`,
  parentheses and `1 of x*` / `all of them` — parsed by a small recursive-
  descent parser, not `eval()`. Rules are **validated when loaded**: a typo
  in a condition, an unknown modifier or a bad regex skips the rule with a
  visible message instead of silently never firing.
- **10 bundled detection rules** (Sysmon and, where the fields exist, Security 4688) spanning Persistence, Defense Evasion,
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

Requires Python 3.10+. Runtime dependencies: `python-evtx`, `PyYAML`,
`Jinja2`. CI runs the tests on 3.10 – 3.13.

## Usage

```bash
python -m win_ir_triage \
  --evtx Security.evtx Microsoft-Windows-Sysmon%4Operational.evtx \
  --rules rules/ \
  --case-name "HOST01-2026-05-11" \
  --out-dir out/ \
  --json --navigator
```

This prints a console summary (severity counts, detections at or above
`--min-level`, MITRE techniques touched) and writes `out/HOST01-2026-05-11.html` (open directly in a browser —
fully self-contained, no external assets), plus optionally a `.json`
timeline and a `.navigator.json` ATT&CK layer.

**Exit codes** (for scripts and CI): `0` finished, `1` input/usage error
(missing file, unreadable EVTX, no valid rules), `2` at least one detection at
or above `--fail-on LEVEL` (`low|medium|high|critical`; omitted = always `0`).
The case name is sanitised before it is used as a file name.

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
| wit-005 | Encoded PowerShell, or hidden window + NoProfile/Bypass | Execution | T1059.001 |
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
(`and` / `or` / `not` / parentheses, `1 of <pattern>`, `all of <pattern>`,
`1 of them`, `all of them`, with a trailing `*` in patterns); field matching
with `|contains`, `|startswith`, `|endswith`, `|re`, and `|all`; list values
as OR; a block written as a list of maps (OR of the maps); `*` / `?`
wildcards in plain values; `Field: null`; case-insensitive string matching;
numeric comparison for hex fields regardless of zero-padding.

**Not supported** (a rule that needs these is rejected at load time, with a
message, rather than being half-evaluated): correlation rules and
timeframes, keyword / list-of-strings blocks, `near`, and any other value
modifier (`base64`, `cidr`, `windash`, ...).

**`logsource` is not used to pre-filter events.** A rule is evaluated against
every event, so each bundled rule pins its events with `EventID` (and
`Channel` where an ID is ambiguous). Do the same in rules you add.
Converting rules to SIEM query languages is out of scope; use
[`pySigma`](https://github.com/SigmaHQ/pySigma) for that.

**⚠️ One documented YAML gotcha:** if a rule needs two conditions on the
*same field* inside one selection block, you cannot repeat the key
(`Image|contains: 'a'` then `Image|contains: 'b'` in the same mapping) —
YAML silently keeps only the last one. Use a list with the `|all`
modifier instead: `Image|contains|all: ['a', 'b']`. This is exactly the
bug caught during development of `wit-006` (see below).

## Validation status

**Automated (in this repository, runs in CI):** 66 unit tests covering the
parser (EVTX-style XML, timestamps), the rule engine (every modifier,
quantifiers, rejection of invalid rules), one positive and one negative case
per bundled rule, the CLI (exit codes, `--fail-on`, `--min-level`, file-name
sanitising), and HTML escaping of hostile event data.

```bash
python -m unittest discover -s tests -t . -v      # or: pytest tests/
python examples/make_example.py                   # regenerate examples/
```

**What these tests do not show.** They use hand-written events
(`tests/fixtures/synthetic_incident.py`, inline dicts), so they demonstrate
the logic, not behaviour on real logs. In particular, no CI test reads a real
`.evtx` file; the `python-evtx` reading path is exercised only on the
author's machine.

**Real-data validation (author's claim, evidence not included).** The
author reports having run the original rules against technique-labelled
samples from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(not redistributed here). The per-sample results are not recorded in this
repository, and several rules were changed afterwards (see
[CHANGELOG](CHANGELOG.md)). Until a results table is added to
`docs/VALIDATION.md`, treat the rules as **unvalidated on real data** and
expect false positives (for example deployment tooling that uses
`-EncodedCommand`, or EDR agents opening LSASS).

Two real bugs found earlier by that process stay covered by regression
tests: inconsistent hex zero-padding in `GrantedAccess`, and duplicate YAML
keys silently overwriting each other (hence `|contains|all`).

## Roadmap

- Registry hive parsing (Run/RunOnce keys, UserAssist) to widen coverage
  beyond event-log-based artifacts
- A `docs/VALIDATION.md` results table from re-running every rule on real samples
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
