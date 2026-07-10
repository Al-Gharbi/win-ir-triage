"""Unit tests for parser.py's XML -> NormalizedEvent logic.

Uses hand-built XML strings shaped exactly like what python-evtx's
record.xml() returns (confirmed against real EVTX samples during
development), so these tests need no binary .evtx fixture files at all.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from win_ir_triage.parser import parse_record_xml  # noqa: E402

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

EVENTDATA_XML = f"""<Event xmlns='{NS}'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/>
    <EventID Qualifiers=''>4732</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime='2026-05-11T09:22:10.000000+00:00'/>
    <EventRecordID>100004</EventRecordID>
    <Correlation/>
    <Execution ProcessID='600' ThreadID='684'/>
    <Channel>Security</Channel>
    <Computer>CORP-WKS-042.example.corp</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='TargetUserName'>Administrators</Data>
    <Data Name='TargetSid'>S-1-5-32-544</Data>
    <Data Name='MemberName'>svc-updater</Data>
  </EventData>
</Event>"""

USERDATA_XML = f"""<Event xmlns='{NS}'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID Qualifiers=''>1102</EventID>
    <TimeCreated SystemTime='2026-05-11T09:42:17.000000+00:00'/>
    <EventRecordID>100006</EventRecordID>
    <Channel>Security</Channel>
    <Computer>CORP-WKS-042.example.corp</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
      <SubjectUserName>svc-updater</SubjectUserName>
    </LogFileCleared>
  </UserData>
</Event>"""


def test_parses_eventdata_fields():
    event = parse_record_xml(EVENTDATA_XML, source_file="test.evtx")
    assert event is not None
    assert event.event_id == 4732
    assert event.channel == "Security"
    assert event.computer == "CORP-WKS-042.example.corp"
    assert event.record_id == 100004
    assert event.fields["TargetSid"] == "S-1-5-32-544"
    assert event.fields["MemberName"] == "svc-updater"


def test_parses_userdata_fallback_fields():
    """Some providers (notably the 1102 'log cleared' event) use <UserData>
    instead of <EventData> -- confirmed against a real sample during
    development; this locks that behaviour in."""
    event = parse_record_xml(USERDATA_XML, source_file="test.evtx")
    assert event is not None
    assert event.event_id == 1102
    assert event.fields.get("SubjectUserName") == "svc-updater"


def test_as_dict_merges_system_and_data_fields_flat():
    event = parse_record_xml(EVENTDATA_XML, source_file="test.evtx")
    flat = event.as_dict()
    # Sigma rules reference both System-level fields (EventID, Channel)
    # and EventData fields (TargetSid) in the SAME flat namespace.
    assert flat["EventID"] == 4732
    assert flat["Channel"] == "Security"
    assert flat["TargetSid"] == "S-1-5-32-544"


def test_malformed_xml_returns_none_instead_of_raising():
    assert parse_record_xml("<Event><System>", source_file="broken.evtx") is None


def test_missing_event_id_defaults_gracefully():
    xml = f"""<Event xmlns='{NS}'><System>
        <Channel>Application</Channel>
        <Computer>HOST</Computer>
    </System></Event>"""
    event = parse_record_xml(xml, source_file="test.evtx")
    assert event is not None
    assert event.event_id == -1
