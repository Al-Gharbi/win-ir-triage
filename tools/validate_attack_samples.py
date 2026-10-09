#!/usr/bin/env python3
"""Run win-ir-triage over a checkout of EVTX-ATTACK-SAMPLES and report.

    python tools/validate_attack_samples.py /path/to/EVTX-ATTACK-SAMPLES [--json out.json]

Needs python-evtx importable (pip install python-evtx). The dataset is GPL-
licensed and is not bundled. Besides the per-rule hit counts, the script checks
a small, hand-labelled table (EXPECT_FIRE / EXPECT_QUIET below). Labels were
assigned by reading the events in each sample, not from file names alone.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from win_ir_triage.parser import UNKNOWN_TIME, parse_evtx_file  # noqa: E402
from win_ir_triage.sigma import load_rules_dir  # noqa: E402
from win_ir_triage.timeline import build_timeline  # noqa: E402

# (rule id, sample path relative to the dataset root). The technique is present in the events.
EXPECT_FIRE = [
    ("wit-001", "Persistence/Network_Service_Guest_added_to_admins_4732.evtx"),
    ("wit-002", "Defense Evasion/DE_Fake_ComputerAccount_4720.evtx"),
    ("wit-003", "Defense Evasion/DE_104_system_log_cleared.evtx"),
    ("wit-003", "Defense Evasion/DE_1102_security_log_cleared.evtx"),
    ("wit-004", "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"),
    ("wit-004", "Credential Access/sysmon_10_11_lsass_memdump.evtx"),
    ("wit-005", "Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx"),   # -nop -noni -enc <base64>
    ("wit-005", "Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx"),                          # -nop -w hidden
    ("wit-006", "Privilege Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx"),
    ("wit-006", "Privilege Escalation/sysmon_13_1_compmgmtlauncherUACBypass.evtx"),
    ("wit-007", "Lateral Movement/LM_Remote_Service02_7045.evtx"),
    ("wit-007", "Privilege Escalation/System_7045_namedpipe_privesc.evtx"),                         # %COMSPEC% /c ... \\.\pipe\
    ("wit-009", "Command and Control/DE_RDP_Tunneling_4624.evtx"),
    # a malware copy named WINWORD.exe under AppData spawning cmd.exe: matches on file name only
    ("wit-010", "AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx"),
]
# Samples whose name suggests the technique, but where the events do not contain what the rule looks for.
EXPECT_QUIET = [
    ("wit-004", "Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx"),    # the dumped process is notepad.exe, not lsass
    ("wit-006", "Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx"),    # sdclt uses App Paths, a different registry path (known gap)
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--json")
    args = ap.parse_args()
    root = Path(args.root)
    files = sorted(root.rglob("*.evtx"))
    if not files:
        sys.exit(f"no .evtx files under {root}")
    rules = load_rules_dir(Path(__file__).resolve().parent.parent / "rules")
    per_file: dict[str, dict] = {}
    t0 = time.time()
    for f in files:
        rel = f.relative_to(root).as_posix()
        rec: dict = {"events": 0, "hits": {}}
        try:
            events = list(parse_evtx_file(f))
            rec["events"] = len(events)
            rec["unknown_timestamps"] = sum(1 for e in events if e.timestamp == UNKNOWN_TIME)
            hits = collections.Counter(m.rule_id for e in build_timeline(events, rules) for m in e.matched_rules)
            rec["hits"] = dict(hits)
        except Exception as exc:  # noqa: BLE001
            rec["error"] = f"{type(exc).__name__}: {exc}"[:200]
        per_file[rel] = rec
    elapsed = time.time() - t0

    errors = [k for k, v in per_file.items() if "error" in v]
    total_events = sum(v["events"] for v in per_file.values())
    print(f"files: {len(files)}  parse errors: {len(errors)}  events: {total_events}  "
          f"unparseable timestamps: {sum(v.get('unknown_timestamps', 0) for v in per_file.values())}  seconds: {elapsed:.0f}")
    files_per_rule = collections.Counter(r for v in per_file.values() for r in v["hits"])
    print("files with >=1 hit, per rule:", dict(sorted(files_per_rule.items())))

    bad = 0
    print("\nlabelled samples")
    for rule, rel in EXPECT_FIRE:
        got = per_file.get(rel, {}).get("hits", {}).get(rule, 0)
        ok = got > 0
        bad += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {rule} fires      {rel}  ({got} hits)")
    for rule, rel in EXPECT_QUIET:
        got = per_file.get(rel, {}).get("hits", {}).get(rule, 0)
        ok = got == 0
        bad += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {rule} quiet      {rel}  ({got} hits)")
    if args.json:
        Path(args.json).write_text(json.dumps(per_file, indent=1), encoding="utf-8")
    return 1 if (bad or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
