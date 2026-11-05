import types
import unittest
from unittest import mock

from defender_mcp.auth import identity
from defender_mcp.errors import ConfirmationError, InputError
from defender_mcp.tools import admin_detections, admin_identity, admin_incidents, admin_response
from helpers import ACTION1, DEVICE_ROW, MDE1, FakeGraph, configure, device_responder

INC = {"id": "29", "displayName": "Incident", "status": "active", "severity": "high", "classification": "unknown",
       "customTags": ["Demo"]}
ALERT = {"id": "da1", "title": "Alert", "status": "new", "classification": "unknown"}


class TriageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", "/security/incidents/29", INC)
        self.g.on("PATCH", "/security/incidents/29", lambda p, b: dict(INC, **b))
        self.g.on("GET", "/security/alerts_v2/da1", ALERT)
        self.g.on("PATCH", "/security/alerts_v2/da1", lambda p, b: dict(ALERT, **b))
        configure(self.g)

    async def test_update_incident_two_step(self):
        preview = await admin_incidents.update_incident("29", status="resolved", classification="truePositive",
                                                        determination="malware", add_tags=["Ransomware"])
        self.assertEqual(preview["status"], "confirmation_required")
        self.assertEqual(self.g.paths("PATCH"), [])
        self.assertIn("also resolves", " ".join(preview["preview"]["warnings"]))
        self.assertEqual(preview["preview"]["changes"]["customTags"]["to"], ["Demo", "Ransomware"])
        token = preview["confirmation_token"]
        with self.assertRaises(ConfirmationError):   # different arguments
            await admin_incidents.update_incident("29", status="resolved", classification="falsePositive",
                                                  determination="notMalicious", add_tags=["Ransomware"],
                                                  confirmation_token=token)
        done = await admin_incidents.update_incident("29", status="resolved", classification="truePositive",
                                                     determination="malware", add_tags=["Ransomware"],
                                                     confirmation_token=token)
        self.assertEqual(done["status"], "done")
        self.assertEqual(self.g.calls[-1].json_body, {"status": "resolved", "classification": "truePositive",
                                                      "determination": "malware", "customTags": ["Demo", "Ransomware"]})

    async def test_determination_must_fit_classification(self):
        with self.assertRaises(InputError):
            await admin_incidents.update_incident("29", classification="falsePositive", determination="malware")
        with self.assertRaises(InputError):   # alert enum differs from incident enum
            await admin_incidents.update_alert("da1", classification="falsePositive", determination="notMalicious")
        await admin_incidents.update_alert("da1", classification="falsePositive", determination="clean")

    async def test_assign_to_me(self):
        with mock.patch.object(identity, "_access_token", return_value=types.SimpleNamespace(
                token="t", claims={"oid": "o1", "tid": "t", "preferred_username": "analyst@contoso.com"})):
            preview = await admin_incidents.update_incident("29", assign_to="me")
        self.assertEqual(preview["preview"]["changes"]["assignedTo"]["to"], "analyst@contoso.com")
        with self.assertRaises(InputError):
            await admin_incidents.update_incident("29", assign_to="not a upn")
        with self.assertRaises(InputError):
            await admin_incidents.update_incident("29")

    async def test_comment_runs_immediately(self):
        self.g.on("POST", "/security/incidents/29/comments", {"value": [{"comment": "a"}, {"comment": "b"}]})
        res = await admin_incidents.add_comment("incident", "29", "Isolated pc-01")
        self.assertEqual(res["status"], "done")
        self.assertEqual(self.g.calls[-1].json_body, {"@odata.type": "microsoft.graph.security.alertComment",
                                                      "comment": "Isolated pc-01"})
        self.g.on("POST", "/security/alerts_v2/da1/comments", {"value": []})
        await admin_incidents.add_comment("alert", "da1", "x")
        with self.assertRaises(InputError):
            await admin_incidents.add_comment("incident", "29", "")


class DetectionRuleTests(unittest.IsolatedAsyncioTestCase):
    QUERY = "DeviceProcessEvents | where FileName =~ 'powershell.exe' | project Timestamp, ReportId, DeviceId, DeviceName"

    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: (["Timestamp", "ReportId", "DeviceId", "DeviceName"], [{"Timestamp": "t"}]))
        self.g.on("POST", "/security/rules/detectionRules", lambda p, b: b)
        configure(self.g)

    async def test_create_uses_2026_schema(self):
        preview = await admin_detections.create_detection_rule(
            "Encoded PowerShell", self.QUERY, "Encoded PowerShell", severity="high", tactic="Execution",
            techniques=["t1059.001"])
        self.assertTrue(preview["preview"]["queryValidation"]["valid"])
        self.assertEqual(preview["preview"]["queryValidation"]["warnings"], [])
        self.assertEqual(self.g.paths("POST")[-1], "/security/runHuntingQuery")   # nothing created yet
        await admin_detections.create_detection_rule(
            "Encoded PowerShell", self.QUERY, "Encoded PowerShell", severity="high", tactic="Execution",
            techniques=["t1059.001"], confirmation_token=preview["confirmation_token"])
        body = self.g.calls[-1].json_body
        self.assertEqual(self.g.calls[-1].version, "beta")
        self.assertEqual(body["id"], "encoded-powershell")
        self.assertEqual(body["status"], "enabled")
        self.assertEqual(body["schedule"], {"frequency": "PT1H"})
        self.assertNotIn("isEnabled", body)
        template = body["detectionAction"]["alertTemplate"]
        self.assertEqual(template["tactics"], [{"tactic": "Execution", "techniques": [{"technique": "T1059.001"}]}])
        self.assertEqual(template["entityMappings"], {"hosts": [{"deviceIdColumn": "DeviceId", "nameColumn": "DeviceName"}]})
        for removed in ("category", "mitreTechniques", "impactedAssets"):
            self.assertNotIn(removed, template)

    async def test_missing_columns_are_reported(self):
        self.g.hunting(lambda q: (["Timestamp", "FileName"], []))
        preview = await admin_detections.create_detection_rule("Rule x", "DeviceProcessEvents", "Alert x",
                                                               entities=["device", "file"])
        warnings = " ".join(preview["preview"]["queryValidation"]["warnings"])
        self.assertIn("DeviceId", warnings)
        self.assertIn("SHA1", warnings)
        with self.assertRaises(InputError):
            await admin_detections.create_detection_rule("Rule x", "T", "Alert x", techniques=["T1059"])

    async def test_manage_update_keeps_template(self):
        rule = {"id": "r1", "displayName": "R", "status": "enabled", "schedule": {"frequency": "PT1H"},
                "detectionAction": {"alertTemplate": {"title": "old", "severity": "low", "category": None,
                                                      "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]}},
                                    "incidentConfiguration": {"isExcludedFromIncidentCorrelation": False}}}
        self.g.on("GET", "/security/rules/detectionRules/r1", rule)
        self.g.on("PATCH", "/security/rules/detectionRules/r1", lambda p, b: dict(rule, **b))
        preview = await admin_detections.manage_detection_rule("r1", "update", alert_title="new")
        await admin_detections.manage_detection_rule("r1", "update", alert_title="new",
                                                     confirmation_token=preview["confirmation_token"])
        action = self.g.calls[-1].json_body["detectionAction"]
        self.assertEqual(action["alertTemplate"]["title"], "new")
        self.assertEqual(action["alertTemplate"]["severity"], "low")
        self.assertIn("entityMappings", action["alertTemplate"])
        self.assertNotIn("category", action["alertTemplate"])
        self.assertEqual(action["incidentConfiguration"], {"isExcludedFromIncidentCorrelation": False})
        preview = await admin_detections.manage_detection_rule("r1", "disable")
        await admin_detections.manage_detection_rule("r1", "disable", confirmation_token=preview["confirmation_token"])
        self.assertEqual(self.g.calls[-1].json_body, {"status": "disabled"})
        with self.assertRaises(InputError):
            await admin_detections.manage_detection_rule("r1", "enable", query="T")


class IdentityHealthTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_step(self):
        g = FakeGraph()
        g.on("GET", "/security/identities/healthIssues/i1", {"id": "i1", "status": "open", "displayName": "x"})
        g.on("PATCH", "/security/identities/healthIssues/i1", {"id": "i1", "status": "suppressed"})
        configure(g)
        preview = await admin_identity.update_identity_health_issue("i1", "suppressed")
        self.assertEqual(preview["preview"]["change"]["status"], {"from": "open", "to": "suppressed"})
        await admin_identity.update_identity_health_issue("i1", "suppressed",
                                                          confirmation_token=preview["confirmation_token"])
        self.assertEqual(g.calls[-1].json_body, {"status": "suppressed"})


class ResponseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(device_responder())
        self.mde = FakeGraph()
        self.mde.on("GET", "/api/machineactions", {"value": []})
        for path in ("isolate", "runAntiVirusScan", "StopAndQuarantineFile", "restrictCodeExecution"):
            self.mde.on("POST", f"/api/machines/{MDE1}/{path}", {"id": ACTION1, "type": path, "status": "Pending"})
        configure(self.g, mde=self.mde)

    async def test_scan_runs_immediately(self):
        res = await admin_response.run_device_response("PC-01", "antivirus_scan_quick", comment="alert 1")
        self.assertEqual(res["status"], "done")
        self.assertEqual(res["machineAction"]["id"], ACTION1)
        self.assertEqual(self.mde.calls[-1].json_body, {"Comment": "alert 1 [via Defender XDR MCP]", "ScanType": "Quick"})

    async def test_isolation_two_step(self):
        preview = await admin_response.run_device_response("PC-01", "isolate", comment="incident 29")
        self.assertEqual(preview["status"], "confirmation_required")
        self.assertEqual(self.mde.paths("POST"), [])
        self.assertEqual(preview["preview"]["device"]["DeviceId"], MDE1)
        with self.assertRaises(ConfirmationError):
            await admin_response.run_device_response("PC-01", "isolate", comment="incident 29",
                                                     isolation_type="Selective",
                                                     confirmation_token=preview["confirmation_token"])
        done = await admin_response.run_device_response("PC-01", "isolate", comment="incident 29",
                                                        confirmation_token=preview["confirmation_token"])
        self.assertEqual(done["status"], "done")
        self.assertEqual(self.mde.calls[-1].json_body, {"Comment": "incident 29 [via Defender XDR MCP]",
                                                        "IsolationType": "Full"})

    async def test_validation_and_os_warnings(self):
        with self.assertRaises(InputError):
            await admin_response.run_device_response("PC-01", "stop_and_quarantine_file")
        with self.assertRaises(InputError):
            await admin_response.run_device_response("PC-01", "release_isolation", sha1="a" * 40)
        self.g.hunting(device_responder([dict(DEVICE_ROW, OSPlatform="macOS", SensorHealthState="Inactive")]))
        preview = await admin_response.run_device_response("PC-01", "restrict_app_execution")
        warnings = " ".join(preview["preview"]["warnings"])
        self.assertIn("only supported on Windows", warnings)
        self.assertIn("pending until the device connects", warnings)

    async def test_action_status(self):
        self.mde.on("GET", f"/api/machineactions/{ACTION1}", {"id": ACTION1, "status": "Succeeded"})
        res = await admin_response.get_response_actions(action_id=ACTION1)
        self.assertEqual(res["machineAction"]["status"], "Succeeded")
        self.mde.on("GET", "/api/machineactions", {"value": [
            {"id": "a", "creationDateTimeUtc": "2026-11-01T00:00:00Z"},
            {"id": "b", "creationDateTimeUtc": "2026-11-02T00:00:00Z"}]})
        res = await admin_response.get_response_actions(device=MDE1)
        self.assertEqual([i["id"] for i in res["items"]], ["b", "a"])
        self.assertIn(f"machineId eq '{MDE1}'", self.mde.calls[-1].params["$filter"])


class IndicatorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.mde = FakeGraph()
        self.mde.on("GET", "/api/indicators", {"value": []})
        self.mde.on("POST", "/api/indicators", lambda p, b: dict(b, id="995"))
        configure(self.g, mde=self.mde)

    async def test_add_is_two_step_and_token_survives_time(self):
        preview = await admin_response.manage_indicator("add", indicator="203.0.113.66", title="C2 server")
        self.assertEqual(preview["preview"]["indicator"]["indicatorType"], "IpAddress")
        self.assertEqual(preview["preview"]["indicator"]["action"], "Block")
        self.assertIn("network protection", " ".join(preview["preview"]["warnings"]))
        done = await admin_response.manage_indicator("add", indicator="203.0.113.66", title="C2 server",
                                                     confirmation_token=preview["confirmation_token"])
        body = self.mde.calls[-1].json_body
        self.assertEqual(body["indicatorValue"], "203.0.113.66")
        self.assertTrue(body["expirationTime"].endswith("Z"))
        self.assertEqual(done["indicator"]["id"], "995")

    async def test_file_defaults_and_rules(self):
        preview = await admin_response.manage_indicator("add", indicator="a" * 64)
        self.assertEqual(preview["preview"]["indicator"]["indicatorType"], "FileSha256")
        self.assertEqual(preview["preview"]["indicator"]["action"], "BlockAndRemediate")
        with self.assertRaises(InputError):
            await admin_response.manage_indicator("add", indicator="evil.com", action="BlockAndRemediate")
        with self.assertRaises(InputError):
            await admin_response.manage_indicator("add", indicator="a" * 64, action="Warn")
        with self.assertRaises(InputError):
            await admin_response.manage_indicator("add", indicator="evil.com", action="Audit", generate_alert=False)

    async def test_list_and_delete_by_value(self):
        self.mde.on("GET", "/api/indicators", {"value": [{"id": "7", "indicatorValue": "evil.com"}]})
        res = await admin_response.manage_indicator("list", indicator="evil.com")
        self.assertEqual(res["count"], 1)
        self.assertEqual(self.mde.calls[-1].params["$filter"], "indicatorValue eq 'evil.com'")
        self.mde.on("DELETE", "/api/indicators/7", {})
        preview = await admin_response.manage_indicator("delete", indicator="evil.com")
        await admin_response.manage_indicator("delete", indicator="evil.com",
                                              confirmation_token=preview["confirmation_token"])
        self.assertEqual(self.mde.paths("DELETE"), ["/api/indicators/7"])


if __name__ == "__main__":
    unittest.main()
