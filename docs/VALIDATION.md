# Validation log

Fill this in by running each rule against real, legally redistributable EVTX
samples (for example [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES);
check its licence before copying anything). Record the commit of win-ir-triage
used, because rules change.

| Date | win-ir-triage commit | Sample (name, source) | Rule(s) expected | Fired? | False positives seen | Notes |
|---|---|---|---|---|---|---|
| - | - | - | - | NOT YET RECORDED | | |

## Procedure

1. `python -m win_ir_triage --evtx <sample.evtx> --rules rules/ --json --out-dir out/`
2. Compare `out/*.json` detections with the sample's documented technique.
3. For a benign baseline, run a clean Windows VM's Security / Sysmon logs and
   count flagged events per rule.
4. Add every miss or false positive as a unit test (inline dict in
   `tests/test_rules.py`) before changing the rule.
