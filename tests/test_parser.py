"""Unit tests for parser.py's XML -> NormalizedEvent logic.

Uses hand-built XML strings shaped exactly like what python-evtx's
record.xml() returns (confirmed against real EVTX samples during
development), so these tests need no binary .evtx fixture files at all.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from datetime import datetime, timedelta, timezone

from win_ir_triage.parser import UNKNOWN_TIME, _parse_timestamp, parse_record_xml  # noqa: E402

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


class ParseRecordTests(unittest.TestCase):
    def test_parses_eventdata_fields(self):
        event = parse_record_xml(EVENTDATA_XML, source_file="test.evtx")
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 4732)
        self.assertEqual(event.channel, "Security")
        self.assertEqual(event.computer, "CORP-WKS-042.example.corp")
        self.assertEqual(event.record_id, 100004)
        self.assertEqual(event.fields["TargetSid"], "S-1-5-32-544")
        self.assertEqual(event.fields["MemberName"], "svc-updater")

    def test_parses_userdata_fallback_fields(self):
        """Some providers (the 1102 'log cleared' event) use <UserData>
        instead of <EventData>."""
        event = parse_record_xml(USERDATA_XML, source_file="test.evtx")
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 1102)
        self.assertEqual(event.fields.get("SubjectUserName"), "svc-updater")

    def test_as_dict_merges_system_and_data_fields_flat(self):
        flat = parse_record_xml(EVENTDATA_XML, source_file="test.evtx").as_dict()
        self.assertEqual(flat["EventID"], 4732)
        self.assertEqual(flat["Channel"], "Security")
        self.assertEqual(flat["TargetSid"], "S-1-5-32-544")

    def test_system_fields_win_over_eventdata_collisions(self):
        xml = EVENTDATA_XML.replace(
            "<Data Name='MemberName'>", "<Data Name='Channel'>spoofed</Data><Data Name='MemberName'>")
        flat = parse_record_xml(xml, source_file="t.evtx").as_dict()
        self.assertEqual(flat["Channel"], "Security")

    def test_malformed_xml_returns_none_instead_of_raising(self):
        self.assertIsNone(parse_record_xml("<Event><System>", source_file="broken.evtx"))

    def test_missing_event_id_defaults_gracefully(self):
        xml = f"""<Event xmlns='{NS}'><System>
            <Channel>Application</Channel><Computer>HOST</Computer></System></Event>"""
        event = parse_record_xml(xml, source_file="test.evtx")
        self.assertEqual(event.event_id, -1)
        self.assertEqual(event.timestamp, UNKNOWN_TIME)


class TimestampTests(unittest.TestCase):
    def test_formats_seen_in_evtx_exports(self):
        expected = datetime(2019, 9, 22, 11, 22, 5, 201725, tzinfo=timezone.utc)
        for raw in ("2019-09-22 11:22:05.201725",
                    "2019-09-22T11:22:05.2017250Z",
                    "2019-09-22T11:22:05.201725+00:00"):
            with self.subTest(raw=raw):
                self.assertEqual(_parse_timestamp(raw), expected)

    def test_offset_is_converted_to_utc(self):
        self.assertEqual(_parse_timestamp("2026-05-11T11:22:10+02:00"),
                         datetime(2026, 5, 11, 9, 22, 10, tzinfo=timezone.utc))

    def test_bad_values_become_unknown_time_and_stay_sortable(self):
        for raw in (None, "", "garbage", "2026-13-40 00:00:00"):
            with self.subTest(raw=raw):
                self.assertEqual(_parse_timestamp(raw), UNKNOWN_TIME)
        # all values are timezone-aware, so mixing them in sorted() cannot raise
        sorted([_parse_timestamp("garbage"), _parse_timestamp("2026-01-01 00:00:00")])

    def test_unknown_time_is_not_shifted_to_a_real_date(self):
        self.assertLess(UNKNOWN_TIME, datetime(2000, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(UNKNOWN_TIME.utcoffset(), timedelta(0))


if __name__ == "__main__":
    unittest.main()
