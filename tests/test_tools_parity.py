"""Parity with the triage tools of the Microsoft Sentinel MCP server and custom hunts."""
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone

from defender_mcp import custom_hunts
from defender_mcp.errors import InputError
from defender_mcp.tools import admin_response, devices, hunting, hunts, incidents, vulnerabilities
from helpers import DEVICE_ROW, MDE1, FakeGraph, configure, device_responder, env, make_settings

INC = {"id": "1", "displayName": "Multi-stage incident involving Ransomware", "status": "active", "severity": "high",
       "createdDateTime": "2026-11-01T08:00:00Z",
       "alerts": [{"title": "Ransomware behavior", "severity": "high", "serviceSource": "microsoftDefenderForEndpoint",
                   "mitreTechniques": ["T1486"], "evidence": [
                       {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "pc-01"}]}]}


class IncidentParityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", "/security/incidents", {"value": [INC, dict(INC, id="2", displayName="Phishing", alerts=[])]})
        configure(self.g)

    async def test_determination_alerts_and_name(self):
        res = await incidents.list_incidents(determination="malware", include_alerts=True, name_contains="ransom")
        params = self.g.calls[-1].params
        self.assertIn("determination eq 'malware'", params["$filter"])
        self.assertEqual(params["$expand"], "alerts")
        self.assertEqual([i["id"] for i in res["items"]], ["1"])
        row = res["items"][0]
        self.assertEqual(row["alerts"][0]["mitreTechniques"], ["T1486"])
        self.assertEqual(row["alertCount"], 1)
        self.assertIn("entities", row)


class SchemaTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: [{"ColumnName": "Timestamp", "ColumnType": "datetime"}])
        configure(self.g)

    async def test_search_and_multiple_tables(self):
        res = await hunting.get_hunting_schema(search="email")
        names = [t["table"] for items in res["tables"].values() for t in items]
        self.assertIn("EmailEvents", names)
        self.assertNotIn("DeviceProcessEvents", names)
        self.assertTrue(self.g.queries()[-1].startswith("Usage"))   # search also lists the workspace tables
        before = len(self.g.queries())
        res = await hunting.get_hunting_schema(table="DeviceProcessEvents, DeviceNetworkEvents")
        self.assertEqual(sorted(res["tables"]), ["DeviceNetworkEvents", "DeviceProcessEvents"])
        self.assertEqual(len(self.g.queries()) - before, 2)
        with self.assertRaises(InputError):
            await hunting.get_hunting_schema(table="A1, B1, C1, D1, E1, F1")
        with self.assertRaises(InputError):
            await hunting.get_hunting_schema(table="DeviceInfo | take 1")


class IocParityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()

        def responder(q):
            if q.startswith("AlertInfo"):
                return [{"AlertId": "da1", "Title": "Malware detected", "Severity": "High"}]
            if "by DeviceName = Entity" in q:
                return [{"DeviceName": "pc-01", "Hits": 4}]
            return []
        self.g.hunting(responder)
        configure(self.g)

    async def test_file_devices_and_alerts(self):
        sha1 = "c" * 40
        res = await hunts.hunt_ioc(sha1)
        self.assertEqual(res["devices"]["items"][0]["DeviceName"], "pc-01")
        self.assertEqual(res["alerts"][0]["AlertId"], "da1")
        queries = self.g.queries()
        self.assertTrue(any(f"where SHA1 == '{sha1}' | distinct AlertId" in q for q in queries))
        self.assertTrue(any("DistinctEntities = dcount(Entity)" in q for q in queries))
        before = len(self.g.queries())
        await hunts.hunt_ioc("d" * 32)   # MD5: AlertEvidence has no MD5 column, so no alert lookup
        self.assertFalse(any(q.startswith("AlertInfo") for q in self.g.queries()[before:]))
        await hunts.hunt_ioc("203.0.113.7")
        ips = "('203.0.113.7', '::ffff:203.0.113.7')"   # IPv4 also IPv4-mapped (FourToSixMapping)
        self.assertTrue(any(f"where RemoteIP in {ips} | distinct AlertId" in q for q in self.g.queries()))
        self.assertTrue(any(f"where RemoteIP in {ips} or LocalIP in {ips}" in q for q in self.g.queries()))

    async def test_sha256_also_searches_profile_sha1(self):
        sha256, sha1 = "e" * 64, "f" * 40

        def responder(q):
            if "invoke FileProfile" in q:
                return [{"SHA1": sha1.upper(), "SHA256": sha256, "ProfileAvailability": "Available"}]
            return []
        self.g.hunting(responder)
        res = await hunts.hunt_ioc(sha256)
        self.assertEqual(res["alsoSearchedSha1"], sha1)
        queries = self.g.queries()
        self.assertIn("invoke FileProfile", queries[0])   # profile first, then the hunt with both hashes
        self.assertTrue(any(f"where SHA256 == '{sha256}' or SHA1 == '{sha1}' or InitiatingProcessSHA256 == "
                            f"'{sha256}' or InitiatingProcessSHA1 == '{sha1}'" in q for q in queries))
        self.assertTrue(any(f"where SHA256 == '{sha256}' or SHA1 == '{sha1}' | distinct AlertId" in q for q in queries))
        self.assertTrue(any(f"(EmailAttachmentInfo | where Timestamp > ago(30d) | where SHA256 == '{sha256}' |" in q
                            for q in queries))
        self.g.hunting(lambda q: [{"SHA1": "", "ProfileAvailability": "Not available"}] if "FileProfile" in q else [])
        res = await hunts.hunt_ioc(sha256)
        self.assertNotIn("alsoSearchedSha1", res)
        self.assertFalse(any("or SHA1 ==" in q for q in self.g.queries()[len(queries):]))


class DeviceParityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(device_responder())
        self.mde = FakeGraph()
        self.mde.on("GET", "/api/machines", {"value": [
            {"id": MDE1, "computerDnsName": "pc-01", "riskScore": "High", "healthStatus": "Active",
             "machineTags": ["Tier0"], "lastSeen": "2026-11-02T08:00:00Z", "rbacGroupName": "Clients"},
            {"id": "b" * 40, "computerDnsName": "srv-01", "riskScore": "High", "machineTags": [],
             "lastSeen": "2026-11-01T08:00:00Z", "rbacGroupName": "Servers"}]})
        configure(self.g, mde=self.mde)

    async def test_device_by_internal_ip(self):
        at = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0)
        res = await devices.find_defender_devices(ip_address="10.1.2.3", seen_at=at.strftime("%Y-%m-%dT%H:%M:%SZ"))
        q = self.g.queries()[-1]
        self.assertIn("LocalIP in ('10.1.2.3', '::ffff:10.1.2.3')", q)
        self.assertIn("NetworkAdapterStatus == \"Up\" and IPAddresses has '10.1.2.3' and IPAddresses contains "
                      "'\"10.1.2.3\"'", q)
        self.assertIn(f"Timestamp > datetime({at.strftime('%Y-%m-%dT%H:%M:%SZ')})", q)
        self.assertIn("| order by Distance asc", q)
        start = (at - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertIn(f"between (datetime({start}) ..", q)
        self.assertEqual(res["windowMinutes"], 15)
        with self.assertRaises(InputError):
            await devices.find_defender_devices(ip_address="10.1.2.3", os_family="windows")
        with self.assertRaises(InputError):
            await devices.find_defender_devices(seen_at="2026-11-02T08:00:00Z")
        with self.assertRaises(InputError):
            await devices.find_defender_devices(ip_address="not-an-ip")

    async def test_risk_score_and_device_details(self):
        res = await devices.find_defender_devices(risk_score="High", tag="tier0")
        self.assertEqual(self.mde.calls[-1].params["$filter"], "riskScore eq 'High'")
        self.assertEqual([i["computerDnsName"] for i in res["items"]], ["pc-01"])
        with self.assertRaises(InputError):
            await devices.find_defender_devices(risk_score="High", sensor_health="inactive")

        def extra(q):
            if q.startswith("DeviceLogonEvents"):
                return [{"AccountName": "max", "Logons": 4, "AdminLogons": 1}]
            return []
        self.g.hunting(device_responder(extra=extra))
        res = await devices.get_defender_device("PC-01")
        self.assertEqual(res["machine"]["riskScore"], "High")
        self.assertEqual(res["logonUsers30d"][0]["AccountName"], "max")
        logon_q = next(q for q in self.g.queries() if q.startswith("DeviceLogonEvents"))
        self.assertIn('not(AccountDomain in~ ("nt authority", "font driver host", "window manager"))', logon_q)
        self.assertEqual(self.mde.calls[-1].params, {"$filter": f"id eq '{MDE1}'"})

    async def test_software_filters(self):
        await devices.get_device_exposure("PC-01", view="vulnerabilities", software="chrome")
        self.assertIn("| where strcat(SoftwareVendor, '_', SoftwareName) contains 'chrome'", self.g.queries()[-1])
        await devices.get_device_exposure("PC-01", view="software", software="Google Chrome")
        self.assertIn("contains 'google' and strcat(SoftwareVendor, '_', SoftwareName) contains 'chrome'",
                      self.g.queries()[-1])
        with self.assertRaises(InputError):
            await devices.get_device_exposure("PC-01", view="software", software="a b c d e f")
        with self.assertRaises(InputError):
            await devices.get_device_exposure("PC-01", view="configuration", software="chrome")
        await vulnerabilities.get_vulnerability_overview("top_cves", software="office", severity="High")
        q = self.g.queries()[-1]
        self.assertIn("strcat(SoftwareVendor, '_', SoftwareName) contains 'office'", q)
        self.assertIn("VulnerabilitySeverityLevel in ('High', 'Critical')", q)
        with self.assertRaises(InputError):
            await vulnerabilities.get_vulnerability_overview("misconfigurations", software="office")


class RemediationAndInvestigationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(device_responder([dict(DEVICE_ROW)]))
        self.mde = FakeGraph()
        past = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.mde.on("GET", "/api/remediationTasks", {"value": [
            {"id": "t-low", "title": "Update 7-Zip", "priority": "Low", "status": "Active", "dueOn": future,
             "targetDevices": 10, "fixedDevices": 5},
            {"id": "t-late", "title": "Update Chrome", "priority": "Medium", "status": "Active", "dueOn": past,
             "targetDevices": 4, "fixedDevices": 1},
            {"id": "t-high", "title": "Update Office", "priority": "High", "status": "Active", "dueOn": future}]})
        self.mde.on("GET", "/api/remediationTasks/t-late", {"id": "t-late", "title": "Update Chrome", "status": "Active",
                                                            "description": "Update Chrome to fix 12 CVEs"})
        self.mde.on("GET", "/api/remediationTasks/t-late/machineReferences", {"value": [
            {"id": MDE1, "computerDnsName": "pc-01", "osPlatform": "Windows11"}]})
        self.mde.on("GET", "/api/investigations", {"value": [
            {"id": "5", "state": "PendingApproval", "startTime": "2026-11-02T07:00:00Z", "machineId": MDE1},
            {"id": "6", "state": "Running", "startTime": "2026-11-02T09:00:00Z", "machineId": MDE1}]})
        self.mde.on("GET", "/api/investigations/5", {"id": "5", "state": "PendingApproval", "triggeringAlertId": "da1"})
        configure(self.g, mde=self.mde)

    async def test_remediation_tasks(self):
        res = await vulnerabilities.get_remediation_tasks()
        self.assertEqual([t["id"] for t in res["items"]], ["t-late", "t-high", "t-low"])   # overdue, then priority
        self.assertEqual(res["overdue"], 1)
        self.assertEqual(res["items"][0]["progressPercent"], 25.0)
        self.assertEqual(self.mde.calls[-1].params["$filter"], "status eq 'Active'")
        res = await vulnerabilities.get_remediation_tasks(task_id="t-late", include_devices=True)
        self.assertEqual(res["exposedDevices"]["items"][0]["computerDnsName"], "pc-01")
        self.assertIn("12 CVEs", res["description"])

    async def test_investigations(self):
        res = await admin_response.get_response_actions(kind="investigations", device="PC-01", state="PendingApproval")
        flt = self.mde.calls[-1].params["$filter"]
        self.assertIn(f"machineId eq '{MDE1}'", flt)
        self.assertIn("state eq 'PendingApproval'", flt)
        self.assertEqual([i["id"] for i in res["items"]], ["6", "5"])   # newest first
        res = await admin_response.get_response_actions(investigation_id="5")
        self.assertEqual(res["investigation"]["triggeringAlertId"], "da1")
        with self.assertRaises(InputError):
            await admin_response.get_response_actions(state="Running")


class CustomHuntTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        custom_hunts.load_catalog.cache_clear()
        self.g = FakeGraph()
        self.g.hunting(lambda q: [{"DeviceName": "pc-01", "Logons": 2}])
        configure(self.g)

    def tearDown(self):
        custom_hunts.load_catalog.cache_clear()

    async def test_list_and_run_shipped_catalog(self):
        res = await hunting.run_custom_hunt()
        names = [h["name"] for h in res["hunts"]]
        self.assertIn("rdp_logons_from_internet", names)
        res = await hunting.run_custom_hunt("process_runs_on_device",
                                            parameters=json.dumps({"device": "PC-01", "file_name": "x'.exe"}))
        q = self.g.queries()[-1]
        self.assertIn("DeviceId =~ 'PC-01' or DeviceName =~ 'PC-01'", q)   # name or Defender device ID
        self.assertIn("ago(3d)", q)                    # default for days
        self.assertIn("FileName =~ 'x\\'.exe'", q)     # text values are escaped KQL literals
        self.assertEqual(res["hunt"], "process_runs_on_device")
        for bad in ({"name": "nope"}, {"name": "process_runs_on_device", "parameters": "{not json"},
                    {"name": "process_runs_on_device", "parameters": json.dumps({"device": "PC-01"})},
                    {"name": "process_runs_on_device", "parameters": json.dumps({"device": "pc' or 1==1",
                                                                                 "file_name": "a.exe"})},
                    {"name": "rdp_logons_from_internet", "parameters": json.dumps({"days": 90})},
                    {"name": "rdp_logons_from_internet", "parameters": json.dumps({"other": 1})}):
            with self.assertRaises(InputError, msg=str(bad)):
                await hunting.run_custom_hunt(**bad)

    async def test_catalog_override_and_validation(self):
        catalog = [{"name": "ip_logons", "description": "Sign-ins from one IP address in the last days.",
                    "query": "DeviceLogonEvents | where RemoteIP == {{ip}} | where Timestamp > ago({{days}}d)",
                    "parameters": {"ip": {"type": "ip"}, "days": {"type": "days", "default": 2}}}]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hunts.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(catalog, fh)
            configure(self.g, settings=make_settings(custom_hunts_file=path))
            await hunting.run_custom_hunt("ip_logons", parameters='{"ip": "203.0.113.5"}')
            self.assertIn("RemoteIP == '203.0.113.5' | where Timestamp > ago(2d)", self.g.queries()[-1])
        bad_catalogs = [
            [dict(catalog[0], name="Bad Name")],
            [dict(catalog[0], query="T | where X == {{ip}}")],                                   # days unused
            [dict(catalog[0], query="T | where X == {{ip}} and Y == {{other}} | take {{days}}")],  # undefined placeholder
            [dict(catalog[0], parameters={"ip": {"type": "nonsense"}, "days": {"type": "days"}})],
            [dict(catalog[0], parameters={"ip": {"type": "ip", "default": "x"}, "days": {"type": "days"}})],
            {"not": "a list"},
        ]
        for raw in bad_catalogs:
            with self.assertRaises(custom_hunts.CatalogError, msg=str(raw)):
                custom_hunts._validate(raw, "test")

    def test_invalid_catalog_stops_start(self):
        from defender_mcp import __main__ as entry
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hunts.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('[{"name": "x"}]')
            err = io.StringIO()
            with mock.patch.dict(os.environ, env(CUSTOM_HUNTS_FILE=path), clear=True), \
                    mock.patch.object(sys, "stderr", err):
                self.assertEqual(entry.main(), 2)
            self.assertIn("Invalid custom hunt catalog", err.getvalue())
            self.assertIn("hunt #1", err.getvalue())


if __name__ == "__main__":
    unittest.main()
