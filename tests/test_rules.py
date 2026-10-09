"""Per-rule positive / negative cases for the bundled rule pack.

Events are hand-written dicts shaped like NormalizedEvent.as_dict(); they show
what each rule does and does not fire on. They do not prove behaviour on real
EVTX files (see README, "Validation status").
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from win_ir_triage import sigma  # noqa: E402

RULES = {r.rule_id: r for r in sigma.load_rules_dir(Path(__file__).resolve().parent.parent / "rules")}
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def fires(rule_id: str, event: dict) -> bool:
    return sigma.evaluate_rule(RULES[rule_id], event)


class PowerShell(unittest.TestCase):
    def sysmon(self, cmd, image=PS):
        return {"EventID": 1, "Image": image, "CommandLine": cmd}

    def test_encoded_command_fires(self):
        for flag in ("-enc", "-Enc", "-e", "-ec", "-EncodedCommand"):
            with self.subTest(flag=flag):
                self.assertTrue(fires("wit-005", self.sysmon(f"powershell.exe {flag} SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcw==")))

    def test_hidden_plus_noprofile_or_bypass_fires(self):
        self.assertTrue(fires("wit-005", self.sysmon("powershell -NoProfile -WindowStyle Hidden -File x.ps1")))
        self.assertTrue(fires("wit-005", self.sysmon("powershell -w hidden -ep bypass -File x.ps1")))

    def test_security_4688_is_supported(self):
        self.assertTrue(fires("wit-005", {"EventID": 4688, "NewProcessName": PS,
                                          "CommandLine": "powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcw=="}))

    def test_single_benign_flags_do_not_fire(self):
        for cmd in ("powershell.exe -NoProfile -File backup.ps1",
                    "powershell.exe -ExecutionPolicy Bypass -File deploy.ps1",
                    "powershell.exe -WindowStyle Hidden -File tray.ps1",
                    "powershell.exe -Command Get-Process",
                    "powershell.exe -e"):
            with self.subTest(cmd=cmd):
                self.assertFalse(fires("wit-005", self.sysmon(cmd)))

    def test_other_process_or_event_type_does_not_fire(self):
        self.assertFalse(fires("wit-005", self.sysmon("x.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcw==", r"C:\x\x.exe")))
        self.assertFalse(fires("wit-005", {"EventID": 3, "Image": PS,
                                           "CommandLine": "powershell -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcw=="}))


class Lsass(unittest.TestCase):
    base = {"EventID": 10, "TargetImage": r"C:\Windows\system32\lsass.exe", "GrantedAccess": "0x1fffff"}

    def test_fires_on_broad_access(self):
        self.assertTrue(fires("wit-004", {**self.base, "SourceImage": r"C:\Windows\Temp\x.exe"}))

    def test_defender_filter_actually_filters(self):
        # regression: the filter used to end in a doubled backslash and never matched
        self.assertFalse(fires("wit-004", {**self.base, "SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"}))
        self.assertFalse(fires("wit-004", {**self.base, "SourceImage": r"C:\Program Files\Windows Defender\x.exe"}))

    def test_other_target_or_access_does_not_fire(self):
        self.assertFalse(fires("wit-004", {**self.base, "TargetImage": r"C:\Windows\notepad.exe", "SourceImage": "x"}))
        self.assertFalse(fires("wit-004", {**self.base, "GrantedAccess": "0x0400", "SourceImage": "x"}))


class LogCleared(unittest.TestCase):
    def test_fires(self):
        self.assertTrue(fires("wit-003", {"EventID": 1102, "Channel": "Security"}))
        self.assertTrue(fires("wit-003", {"EventID": 104, "Channel": "System"}))

    def test_same_ids_in_other_channels_do_not_fire(self):
        self.assertFalse(fires("wit-003", {"EventID": 104, "Channel": "Application"}))
        self.assertFalse(fires("wit-003", {"EventID": 1102, "Channel": "System"}))


class Accounts(unittest.TestCase):
    def test_admin_group_add(self):
        self.assertTrue(fires("wit-001", {"EventID": 4732, "TargetSid": "S-1-5-32-544"}))
        self.assertFalse(fires("wit-001", {"EventID": 4732, "TargetSid": "S-1-5-32-545"}))

    def test_new_user(self):
        self.assertTrue(fires("wit-002", {"EventID": 4720}))
        self.assertFalse(fires("wit-002", {"EventID": 4722}))


class Service(unittest.TestCase):
    def test_fires_on_cmd_service(self):
        self.assertTrue(fires("wit-007", {"EventID": 7045, "ImagePath": r"cmd.exe /c C:\Windows\Temp\x.bat"}))

    def test_comspec_and_named_pipe_services_fire(self):
        # found on real data: a service whose ImagePath is %COMSPEC% /c ... > \\.\pipe\x
        self.assertTrue(fires("wit-007", {"EventID": 7045, "ImagePath": r"%COMSPEC% /c echo x > \\.\pipe\svcpipe"}))
        self.assertTrue(fires("wit-007", {"EventID": 7045, "ImagePath": r"%SystemRoot%\system32\cmd /c whoami"}))

    def test_normal_service_does_not_fire(self):
        self.assertFalse(fires("wit-007", {"EventID": 7045, "ImagePath": r"C:\Program Files\App\svc.exe"}))
        self.assertFalse(fires("wit-007", {"EventID": 7036, "ImagePath": "cmd.exe"}))


class Uac(unittest.TestCase):
    def test_fires(self):
        self.assertTrue(fires("wit-006", {"EventID": 13, "TargetObject": r"HKU\S-1-5-21-1_Classes\ms-settings\shell\open\command\(Default)"}))

    def test_normal_registry_write_does_not_fire(self):
        self.assertFalse(fires("wit-006", {"EventID": 13, "TargetObject": r"HKU\S-1-5-21-1\Software\Foo"}))


class Recon(unittest.TestCase):
    def test_sysmon_and_security_variants(self):
        self.assertTrue(fires("wit-008", {"EventID": 1, "Image": r"C:\Windows\System32\whoami.exe"}))
        self.assertTrue(fires("wit-008", {"EventID": 4688, "NewProcessName": r"C:\Windows\System32\net.exe", "CommandLine": "net localgroup administrators"}))

    def test_other_net_usage_does_not_fire(self):
        self.assertFalse(fires("wit-008", {"EventID": 1, "Image": r"C:\Windows\System32\net.exe", "CommandLine": "net use Z: \\\\srv\\s"}))
        self.assertFalse(fires("wit-008", {"EventID": 11, "Image": r"C:\Windows\System32\whoami.exe"}))


class Logons(unittest.TestCase):
    def test_fires(self):
        self.assertTrue(fires("wit-009", {"EventID": 4648}))
        self.assertTrue(fires("wit-009", {"EventID": 4624, "LogonType": "10"}))

    def test_console_logon_does_not_fire(self):
        self.assertFalse(fires("wit-009", {"EventID": 4624, "LogonType": "2"}))


class OfficeShell(unittest.TestCase):
    def test_sysmon_and_security(self):
        self.assertTrue(fires("wit-010", {"EventID": 1, "ParentImage": r"C:\O\WINWORD.EXE", "Image": r"C:\Windows\System32\cmd.exe"}))
        self.assertTrue(fires("wit-010", {"EventID": 4688, "ParentProcessName": r"C:\O\EXCEL.EXE", "NewProcessName": r"C:\Windows\System32\mshta.exe"}))

    def test_benign_pairs_do_not_fire(self):
        self.assertFalse(fires("wit-010", {"EventID": 1, "ParentImage": r"C:\Windows\explorer.exe", "Image": r"C:\Windows\System32\cmd.exe"}))
        self.assertFalse(fires("wit-010", {"EventID": 1, "ParentImage": r"C:\O\WINWORD.EXE", "Image": r"C:\Windows\notepad.exe"}))


if __name__ == "__main__":
    unittest.main()
