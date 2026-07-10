"""
Synthetic (fully original, hand-authored) sample events used by the test
suite and to generate the bundled example report in examples/. These are
NOT extracted from any real system or third-party dataset -- every field
value below was written by hand to be illustrative of what each detection
rule looks for, loosely dramatized into a single fictional incident
storyline for readability.

Intentionally kept as plain Python dicts (the same shape NormalizedEvent.as_dict()
produces) rather than real .evtx binaries, so the test suite has zero
external data dependencies and runs anywhere in <1s.
"""
from __future__ import annotations

# A small fictional incident on a single fictional host: a user opens a
# phishing attachment, a hidden PowerShell stager runs, the attacker dumps
# credentials, adds a backdoor admin account, moves laterally, and clears
# the security log on the way out. Every value is invented for this example.

SYNTHETIC_INCIDENT: list[dict] = [
    {
        "EventID": 1,
        "TimeCreated": "2026-05-11T09:14:02.000000+00:00",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "CORP-WKS-042.example.corp",
        "Provider": "Microsoft-Windows-Sysmon",
        "EventRecordID": 100001,
        "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -NoP -W Hidden -Enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcw==",
        "User": "CORP\\j.alharbi",
    },
    {
        "EventID": 10,
        "TimeCreated": "2026-05-11T09:16:40.000000+00:00",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "CORP-WKS-042.example.corp",
        "Provider": "Microsoft-Windows-Sysmon",
        "EventRecordID": 100002,
        "SourceImage": r"C:\Windows\Temp\upd_cache.exe",
        "TargetImage": r"C:\Windows\system32\lsass.exe",
        "GrantedAccess": "0x1fffff",
        "CallTrace": "unknown",
    },
    {
        "EventID": 4720,
        "TimeCreated": "2026-05-11T09:21:55.000000+00:00",
        "Channel": "Security",
        "Computer": "CORP-WKS-042.example.corp",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventRecordID": 100003,
        "TargetUserName": "svc-updater",
        "SubjectUserName": "j.alharbi",
    },
    {
        "EventID": 4732,
        "TimeCreated": "2026-05-11T09:22:10.000000+00:00",
        "Channel": "Security",
        "Computer": "CORP-WKS-042.example.corp",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventRecordID": 100004,
        "TargetUserName": "Administrators",
        "TargetSid": "S-1-5-32-544",
        "MemberName": "svc-updater",
        "SubjectUserName": "j.alharbi",
    },
    {
        "EventID": 7045,
        "TimeCreated": "2026-05-11T09:30:03.000000+00:00",
        "Channel": "System",
        "Computer": "CORP-FILESRV-01.example.corp",
        "Provider": "Service Control Manager",
        "EventRecordID": 100005,
        "ServiceName": "WinRMHelper29",
        "ImagePath": r"cmd.exe /c C:\Windows\Temp\stage2.bat",
        "AccountName": "LocalSystem",
    },
    {
        "EventID": 1102,
        "TimeCreated": "2026-05-11T09:42:17.000000+00:00",
        "Channel": "Security",
        "Computer": "CORP-WKS-042.example.corp",
        "Provider": "Microsoft-Windows-Eventlog",
        "EventRecordID": 100006,
        "SubjectUserName": "svc-updater",
    },
    # A benign event included on purpose to prove the rule set does NOT
    # flag routine admin activity: a normal interactive logon.
    {
        "EventID": 4624,
        "TimeCreated": "2026-05-11T08:55:00.000000+00:00",
        "Channel": "Security",
        "Computer": "CORP-WKS-042.example.corp",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventRecordID": 100000,
        "TargetUserName": "j.alharbi",
        "LogonType": "2",
    },
]
