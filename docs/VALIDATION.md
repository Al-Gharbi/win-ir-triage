# Validation log

Reproduce with:

```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
pip install python-evtx PyYAML Jinja2
python tools/validate_attack_samples.py EVTX-ATTACK-SAMPLES
```

The dataset is GPL-licensed and is not bundled here.

## Run of 2026-10-09 (commit after this change)

Data: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) at commit `4ceed2f` (shallow clone), 278 `.evtx` files, read with python-evtx 0.8.1 (`c000744`), Python 3.13.

| Check | Result |
|---|---|
| Files that parsed without exception | 278 / 278 |
| Events read | 37,364 |
| Events with an unparseable timestamp | 0 |
| Event count per file vs the dataset's own `evtx_data.csv` (249 files listed in it) | identical for all 249 |
| Files with at least one hit, per rule | wit-001: 1, wit-002: 1, wit-003: 26, wit-004: 13, wit-005: 2, wit-006: 8, wit-007: 2, wit-008: 21, wit-009: 4, wit-010: 1 |
| Hand-labelled samples that behave as expected | 16 / 16 (14 must fire, 2 must stay quiet) |
| Time to process the whole set | about 170 s on one core |

### What the data showed (and what was changed because of it)

* **wit-007 missed a real sample.** `System_7045_namedpipe_privesc.evtx` installs a service whose `ImagePath` is `%COMSPEC% /c ... > \\.\pipe\...`; the rule only looked for `cmd.exe`. Added `%COMSPEC%`, `cmd /c` and `\\.\pipe\`, plus a regression test.
* **wit-003 fires on 26 files, correctly.** In each, the first record is a real Security 1102 event: the dataset's author cleared the log before recording. This is a true positive that looks like noise.
* **wit-010 hit is not Office.** The only hit is a malware copy named `WINWORD.exe` under `AppData\Roaming` spawning `cmd.exe` (matched on file name). No real Office to shell chain exists in this dataset, so the rule's main use case is **still untested on real data**.
* **wit-006 does not cover every UAC bypass.** It looks for writes to `...\shell\open\command` under a `_Classes` hive. The SDCLT bypass (`App Paths`) and about 30 other UACME/UAC samples use different registry paths and do not fire. That is by design but means "UAC bypass detection" is narrow.
* **wit-005 recall is small-n.** The dataset has exactly one encoded-PowerShell command line and one hidden-window launcher; both fire. That is 2 data points, not a recall estimate.

### Limits of this validation

* The labelled samples were chosen **after** looking at which rules fired, so this is not a blind test.
* The dataset contains attacks only. **False-positive rates on a clean system are not measured**; expect hits from administration tooling (for example `-EncodedCommand` in management agents, EDR processes opening LSASS).
* It covers Sysmon and Security logs on Windows 7/10/Server-era exports; other channels and newer Windows builds are untested.
* The `hexdump` import that python-evtx needs was satisfied by a 6-line stand-in in this run (PyPI was not reachable); parsing does not use it.
