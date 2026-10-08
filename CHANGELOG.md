# Changelog

## [0.2.0] - 2026-10-08

### Fixed
- Unsupported Sigma modifiers raised an exception on the first event and
  aborted the whole scan; rules are now validated at load time and rejected
  with a message.
- Unknown block names or malformed `condition` strings silently evaluated to
  false (the rule never fired); they are now load-time errors. Trailing
  tokens and unbalanced parentheses are rejected.
- `wit-004`: the Defender filter ended in a doubled backslash and never
  matched, so Defender was never excluded.
- `wit-005`: any `-NoProfile`, `-e ` or `-ExecutionPolicy Bypass` fired. Now
  requires an encoded command, or a hidden window plus NoProfile/Bypass.
- Rules documented for Security 4688 never matched it (they only read Sysmon
  field names); wit-005/008/010 now accept both.
- Event IDs 104 / 1102 are pinned to their channels (wit-003).
- Mixed naive / timezone-aware timestamps could raise `TypeError` when
  sorting; all timestamps are now UTC-aware, unparseable ones map to a fixed
  `UNKNOWN_TIME` sentinel.
- `--min-level` did nothing; it now filters the console listing.
- `--case-name` was used verbatim in file paths; it is sanitised.

### Added
- `1 of x*`, `all of x*`, `1 of them`, `all of them`, `*`/`?` wildcards,
  `null`, list-of-maps blocks.
- `--fail-on LEVEL` (exit 2), `--version`; exit code 1 for input errors.
- Duplicate rule ids are rejected.
- 66 tests (rules, engine, CLI, report escaping), CI on Python 3.10-3.13 with
  ruff and a "no rule silently skipped" check; `examples/make_example.py`.

### Changed
- `rich` dependency removed (plain console output).
- `python-evtx` is imported lazily, so the rule engine and XML parser work
  (and are testable) without it.
- README no longer presents the rule validation as reproducible; see
  "Validation status".

