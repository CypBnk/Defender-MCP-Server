"""Tools for the daily work of analysts, operators and Defender administrators."""
import unittest
from datetime import datetime, timedelta, timezone

from defender_mcp.errors import ConfirmationError, GraphError, InputError
from defender_mcp.resolve import entra_sid
from defender_mcp.tools import (admin_response, admin_users, devices, endpoint_health, hunts, identity, incidents,
                                threat_intel, users, vulnerabilities)
from helpers import DEVICE_ROW, MDE1, FakeGraph, configure, device_responder

OID = "11111111-2222-3333-4444-555555555555"
ONPREM_SID = "S-1-5-21-1-2-3-1104"
USER = {"id": OID, "displayName": "Max Muster", "userPrincipalName": "max@contoso.com", "mail": "Max.Muster@contoso.com",
        "accountEnabled": True, "userType": "Member", "onPremisesSyncEnabled": False,
        "onPremisesSecurityIdentifier": ONPREM_SID}


def _users_route(user=USER):
    def handler(params, _body):
        assert params["$filter"] == "userPrincipalName eq 'max@contoso.com'", params
        return {"value": [user]}
    return handler


class UserInvestigationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", "/users", _users_route())
        self.g.on("GET", f"/identityProtection/riskyUsers/{OID}", {"riskLevel": "high", "riskState": "atRisk"})
        self.g.on("GET", "/security/alerts_v2/da1", {"id": "da1", "incidentId": "29", "status": "new"})

        def responder(q):
            if q.startswith("let Ids = AlertEvidence"):
                return [{"Timestamp": "2026-11-01T10:00:00Z", "AlertId": "da1", "Title": "Suspicious sign-in",
                         "Severity": "High"}]
            if q.startswith("EntraIdSignInEvents"):
                return [{"SignIns": 40, "Failed": 7, "Countries": ["DE", "NG"]}]
            if q.startswith("DeviceLogonEvents"):
                return [{"DeviceName": "pc-01", "Logons": 3, "AdminLogons": 1}]
            if q.startswith("IdentityInfo"):
                return [{"Department": "Finance", "RiskLevel": "High"}]
            if q.startswith("EmailEvents"):
                return [{"Received": 10, "WithThreats": 2}]
            return []
        self.g.hunting(responder)
        configure(self.g)

    async def test_full_investigation(self):
        res = await users.investigate_user("max@contoso.com", days=3)
        self.assertEqual(res["account"]["id"], OID)
        self.assertEqual(res["risk"]["riskState"], "atRisk")
        self.assertEqual(res["identity"]["Department"], "Finance")
        self.assertEqual(res["alerts"]["incidentIds"], ["29"])
        self.assertEqual(res["alerts"]["items"][0]["IncidentId"], "29")
        self.assertEqual(res["signIns"]["Failed"], 7)
        self.assertEqual(res["devices"][0]["DeviceName"], "pc-01")
        self.assertNotIn("errors", res)
        queries = self.g.queries()
        self.assertTrue(all("ago(3d)" in q or q.startswith("IdentityInfo") for q in queries))
        logon = next(q for q in queries if q.startswith("DeviceLogonEvents"))
        # precise match on the account SIDs: on-premises SID and the Entra SID of the object ID
        self.assertIn(f"AccountSid in~ ('{ONPREM_SID}', '{entra_sid(OID)}')", logon)
        email = next(q for q in queries if q.startswith("EmailEvents"))
        self.assertIn("RecipientEmailAddress in~ ('max.muster@contoso.com', 'max@contoso.com')", email)
        signin = next(q for q in queries if q.startswith("EntraIdSignInEvents"))
        self.assertIn(f"(AccountObjectId =~ '{OID}' or AccountUpn =~ 'max@contoso.com')", signin)

    async def test_works_without_directory_access(self):
        self.g.on("GET", "/users", GraphError(403, "Authorization_RequestDenied", "no"))
        res = await users.investigate_user("max@contoso.com")
        self.assertIn("account", res["errors"])
        self.assertIn("approximate", res["devicesMatch"])
        logon = next(q for q in self.g.queries() if q.startswith("DeviceLogonEvents"))
        self.assertIn("AccountName =~ 'max'", logon)

    async def test_input_and_risk_not_listed(self):
        with self.assertRaises(InputError):
            await users.investigate_user("CONTOSO\\max")
        self.g.on("GET", f"/identityProtection/riskyUsers/{OID}", GraphError(404, "NotFound", "x"))
        res = await users.investigate_user("max@contoso.com")
        self.assertEqual(res["risk"]["riskState"], "none")

    def test_entra_sid(self):
        self.assertEqual(entra_sid("73d664dd-ba04-4bb6-ae7c-2e6a2fa2f1cb"),
                         "S-1-12-1-1943430365-1270266372-1781431470-3421610543")


class ThreatIntelTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        configure(self.g)

    async def test_cve(self):
        self.g.on("GET", "/security/threatIntelligence/vulnerabilities/CVE-2021-44228", {
            "id": "CVE-2021-44228", "priorityScore": 100, "activeExploitsObserved": True, "exploitsAvailable": True,
            "cvss3Summary": {"score": 10.0, "severity": "critical"}, "description": {"content": "Log4j"}})
        res = await threat_intel.get_threat_intelligence(indicator="cve-2021-44228")
        self.assertTrue(res["activeExploitsObserved"])
        self.assertEqual(res["cvss3"]["score"], 10.0)
        self.assertEqual(res["description"], "Log4j")

    async def test_url_host_reputation(self):
        self.g.on("GET", "/security/threatIntelligence/hosts/evil.example", {
            "@odata.type": "#microsoft.graph.security.hostname", "registrar": "X", "firstSeenDateTime": "2020-01-01"})
        self.g.on("GET", "/security/threatIntelligence/hosts/evil.example/reputation", {
            "classification": "malicious", "score": 100, "rules": [{"name": "Intel Article", "severity": "high"}]})
        res = await threat_intel.get_threat_intelligence(indicator="https://evil.example/login?x=1")
        self.assertEqual(res["type"], "hostname")
        self.assertEqual(res["reputation"]["classification"], "malicious")
        self.g.on("GET", "/security/threatIntelligence/hosts/203.0.113.9", GraphError(404, "NotFound", "x"))
        self.g.on("GET", "/security/threatIntelligence/hosts/203.0.113.9/reputation", GraphError(404, "NotFound", "x"))
        with self.assertRaises(Exception) as ctx:
            await threat_intel.get_threat_intelligence(indicator="203.0.113.9")
        self.assertIn("not known", str(ctx.exception))

    async def test_search(self):
        self.g.on("GET", "/security/threatIntelligence/articles", {"value": [{"id": "a1", "title": "Qakbot returns",
                                                                              "summary": {"content": "s"}}]})
        self.g.on("GET", "/security/threatIntelligence/intelProfiles", {"value": [{"id": "p1", "title": "Storm-X",
                                                                                   "kind": "actor"}]})
        res = await threat_intel.get_threat_intelligence(search="Qakbot", max_items=3)
        self.assertEqual(res["articles"][0]["title"], "Qakbot returns")
        self.assertEqual(res["profiles"][0]["kind"], "actor")
        self.assertEqual(self.g.calls[-1].params, {"$search": '"Qakbot"', "$top": "3"})

    async def test_validation(self):
        for kwargs in ({}, {"indicator": "x.example", "search": "y"}, {"search": "two words"},
                       {"indicator": "a" * 64}):
            with self.assertRaises(InputError):
                await threat_intel.get_threat_intelligence(**kwargs)


INC_A = {"id": "1", "displayName": "Phish", "status": "active", "severity": "high", "assignedTo": "a@contoso.com",
         "customTags": [], "createdDateTime": "2026-11-01T08:00:00Z", "lastUpdateDateTime": "2026-11-01T09:00:00Z"}
INC_B = {"id": "2", "displayName": "Ransomware", "status": "active", "severity": "medium", "assignedTo": None,
         "customTags": ["Ransomware"], "systemTags": [], "createdDateTime": "2026-11-02T08:00:00Z"}


class IncidentQueueTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", "/me", {"userPrincipalName": "analyst@contoso.com"})
        self.g.on("GET", "/security/incidents", {"value": [INC_A, INC_B]})
        configure(self.g)

    async def test_me_unassigned_and_tag(self):
        await incidents.list_incidents(assigned_to="me")
        self.assertIn("assignedTo eq 'analyst@contoso.com'", self.g.calls[-1].params["$filter"])
        res = await incidents.list_incidents(unassigned_only=True)
        self.assertEqual([i["id"] for i in res["items"]], ["2"])
        res = await incidents.list_incidents(tag="ransomware")
        self.assertEqual([i["id"] for i in res["items"]], ["2"])
        with self.assertRaises(InputError):
            await incidents.list_incidents(assigned_to="x@contoso.com", unassigned_only=True)

    async def test_statistics(self):
        resolved = [dict(INC_A, id="7", status="resolved", classification="truePositive", determination="phishing",
                         createdDateTime="2026-11-01T00:00:00Z", lastUpdateDateTime="2026-11-01T10:00:00Z"),
                    dict(INC_A, id="8", status="resolved", classification="falsePositive", determination="notMalicious",
                         createdDateTime="2026-11-01T00:00:00Z", lastUpdateDateTime="2026-11-01T02:00:00Z")]

        def handler(params, _body):
            return {"value": resolved} if "status eq 'resolved'" in params["$filter"] else {"value": [INC_A, INC_B]}
        self.g.on("GET", "/security/incidents", handler)
        res = await incidents.get_incident_statistics(days=7)
        self.assertEqual(res["created"]["total"], 2)
        self.assertEqual(res["created"]["perDay"], {"2026-11-01": 1, "2026-11-02": 1})
        self.assertEqual(res["resolved"]["byClassification"], {"truePositive": 1, "falsePositive": 1})
        self.assertEqual(res["resolved"]["timeToResolve"]["medianHours"], 6.0)
        self.assertEqual(res["stillOpenFromPeriod"]["unassigned"], 1)
        self.assertEqual(res["stillOpenFromPeriod"]["oldest"][0]["id"], "1")


AV_ROWS = [
    {"machineId": MDE1, "computerDnsName": "pc-01", "avMode": "0", "avIsSignatureUpToDate": "True",
     "avSignatureUpdateTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "quickScanResult": "Completed",
     "lastSeenTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
    {"machineId": "b" * 40, "computerDnsName": "srv-01", "avMode": "1", "avIsSignatureUpToDate": "False",
     "avSignatureUpdateTime": (datetime.now(timezone.utc) - timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ"),
     "quickScanResult": "Failed"},
]


class AntivirusHealthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(device_responder())
        self.mde = FakeGraph()
        self.mde.on("GET", "/api/deviceavinfo", {"value": AV_ROWS})
        configure(self.g, mde=self.mde)

    async def test_summary(self):
        res = await endpoint_health.get_antivirus_health()
        self.assertEqual(res["devices"], 2)
        self.assertEqual(res["byMode"], {"Active": 1, "Passive": 1})
        self.assertEqual(res["signatureAge"][">7d"], 1)
        self.assertEqual(res["quickScan"]["Failed"], 1)
        self.assertTrue(res["complete"])

    async def test_issue_lists_and_device(self):
        res = await endpoint_health.get_antivirus_health(issue="outdated_signatures", os_kind="windows")
        self.assertEqual(self.mde.calls[-1].params["$filter"], "osKind eq 'windows' and avIsSignatureUpToDate eq 'False'")
        self.assertEqual(res["items"][0]["computerDnsName"], "srv-01")   # oldest signatures first
        res = await endpoint_health.get_antivirus_health(issue="not_active_mode")
        self.assertEqual([i["avMode"] for i in res["items"]], ["Passive"])
        await endpoint_health.get_antivirus_health(device="PC-01")
        self.assertEqual(self.mde.calls[-1].params, {"$filter": f"machineId eq '{MDE1}'"})


class ContainUserTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", "/users", _users_route())
        self.g.on("GET", f"/users/{OID}", USER)
        self.g.on("GET", "/me", {"id": "someone-else"})
        self.g.on("POST", f"/users/{OID}/revokeSignInSessions", {"value": True})
        self.g.on("PATCH", f"/users/{OID}", {})
        self.g.on("GET", f"/identityProtection/riskyUsers/{OID}", {"riskLevel": "medium", "riskState": "atRisk"})
        self.g.on("POST", "/identityProtection/riskyUsers/confirmCompromised", {})
        configure(self.g)

    async def test_revoke_two_step(self):
        preview = await admin_users.contain_user("max@contoso.com", "revoke_sessions")
        self.assertEqual(preview["status"], "confirmation_required")
        self.assertEqual(self.g.paths("POST"), [])
        with self.assertRaises(ConfirmationError):   # token is bound to the action
            await admin_users.contain_user("max@contoso.com", "disable_account",
                                           confirmation_token=preview["confirmation_token"])
        done = await admin_users.contain_user(OID, "revoke_sessions", confirmation_token=preview["confirmation_token"])
        self.assertEqual(done["status"], "done")
        self.assertEqual(self.g.paths("POST"), [f"/users/{OID}/revokeSignInSessions"])

    async def test_disable_rules(self):
        preview = await admin_users.contain_user("max@contoso.com", "disable_account")
        await admin_users.contain_user("max@contoso.com", "disable_account", confirmation_token=preview["confirmation_token"])
        self.assertEqual(self.g.calls[-1].json_body, {"accountEnabled": False})
        with self.assertRaises(InputError):   # already enabled
            await admin_users.contain_user("max@contoso.com", "enable_account")
        self.g.on("GET", "/users", _users_route(dict(USER, onPremisesSyncEnabled=True)))
        with self.assertRaises(InputError):   # synchronized from AD
            await admin_users.contain_user("max@contoso.com", "disable_account")
        self.g.on("GET", "/users", _users_route())
        self.g.on("GET", "/me", {"id": OID})
        with self.assertRaises(InputError):   # own account
            await admin_users.contain_user("max@contoso.com", "disable_account")

    async def test_confirm_compromised_and_403_hint(self):
        preview = await admin_users.contain_user("max@contoso.com", "confirm_compromised")
        self.assertEqual(preview["preview"]["currentRisk"]["riskState"], "atRisk")
        await admin_users.contain_user("max@contoso.com", "confirm_compromised",
                                       confirmation_token=preview["confirmation_token"])
        self.assertEqual(self.g.calls[-1].json_body, {"userIds": [OID]})
        self.g.on("POST", f"/users/{OID}/revokeSignInSessions", GraphError(403, "Authorization_RequestDenied", "no"))
        preview = await admin_users.contain_user("max@contoso.com", "revoke_sessions")
        with self.assertRaises(GraphError) as ctx:
            await admin_users.contain_user("max@contoso.com", "revoke_sessions",
                                           confirmation_token=preview["confirmation_token"])
        self.assertIn("User Administrator", str(ctx.exception))


class DeviceActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(device_responder([dict(DEVICE_ROW, DeviceManualTags=["Tier0"])]))
        self.mde = FakeGraph()
        self.mde.on("GET", "/api/machineactions", {"value": []})
        self.mde.on("POST", f"/api/machines/{MDE1}/tags", lambda p, b: {"id": MDE1, "machineTags": ["Tier0", b["Value"]]})
        self.mde.on("POST", f"/api/machines/{MDE1}/startInvestigation", {"id": "inv1", "state": "Running"})
        configure(self.g, mde=self.mde)

    async def test_tags(self):
        with self.assertRaises(InputError):
            await admin_response.run_device_response("PC-01", "add_tag")
        with self.assertRaises(InputError):
            await admin_response.run_device_response("PC-01", "isolate", tag="x")
        preview = await admin_response.run_device_response("PC-01", "add_tag", tag="Quarantine-Net")
        self.assertEqual(preview["preview"]["currentTags"], ["Tier0"])
        done = await admin_response.run_device_response("PC-01", "add_tag", tag="Quarantine-Net",
                                                        confirmation_token=preview["confirmation_token"])
        self.assertEqual(self.mde.calls[-1].json_body, {"Value": "Quarantine-Net", "Action": "Add"})
        self.assertIn("Quarantine-Net", done["machineTags"])
        preview = await admin_response.run_device_response("PC-01", "remove_tag", tag="unknown")
        self.assertIn("no manual tag", " ".join(preview["preview"]["warnings"]))

    async def test_start_investigation(self):
        preview = await admin_response.run_device_response("PC-01", "start_automated_investigation", comment="inc 29")
        done = await admin_response.run_device_response("PC-01", "start_automated_investigation", comment="inc 29",
                                                        confirmation_token=preview["confirmation_token"])
        self.assertEqual(done["investigation"]["id"], "inv1")
        self.assertEqual(self.mde.calls[-1].json_body, {"Comment": "inc 29 [via Defender XDR MCP]"})


class ExtendedReadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(device_responder())
        configure(self.g)

    async def test_identity_sensors(self):
        self.g.on("GET", "/security/identities/sensors", {"value": [
            {"id": "s1", "displayName": "DC1", "healthStatus": "healthy", "serviceStatus": "running"},
            {"id": "s2", "displayName": "DC2", "healthStatus": "notHealthyHigh", "serviceStatus": "stopped",
             "settings": {"domainControllerDnsNames": ["dc2.contoso.local"]}}]})
        res = await identity.get_identity_health(view="sensors")
        self.assertEqual([i["displayName"] for i in res["items"]], ["DC2", "DC1"])   # unhealthy first
        self.assertEqual(res["byHealthStatus"], {"healthy": 1, "notHealthyHigh": 1})
        self.assertEqual(res["items"][0]["domainControllers"], ["dc2.contoso.local"])

    async def test_device_filters_and_window(self):
        await devices.find_defender_devices(device_group="Servers", tag="Tier0")
        q = self.g.queries()[-1]
        self.assertIn("MachineGroup =~ 'Servers'", q)
        self.assertIn("tostring(DeviceManualTags) has 'Tier0'", q)
        at = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0)
        res = await devices.get_device_activity("PC-01", "processes", around=at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                window_minutes=15)
        q = self.g.queries()[-1]
        start = (at - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertIn(f"| where Timestamp between (datetime({start}) .. datetime(", q)
        self.assertIn("order by Timestamp asc", q)
        self.assertEqual(res["from"], start)
        for bad in ("yesterday", "2020-01-01T00:00:00Z"):
            with self.assertRaises(InputError):
                await devices.get_device_activity("PC-01", "network", around=bad)

    async def test_vulnerability_views(self):
        await vulnerabilities.get_vulnerability_overview("missing_updates", severity="Critical")
        self.assertIn("by RecommendedSecurityUpdate, RecommendedSecurityUpdateId", self.g.queries()[-1])
        self.assertIn("VulnerabilitySeverityLevel in ('Critical')", self.g.queries()[-1])
        await vulnerabilities.get_vulnerability_overview("end_of_support", severity="High")
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("DeviceTvmSoftwareInventory"))
        self.assertNotIn("VulnerabilitySeverityLevel", q)

    async def test_ioc_file_profile(self):
        def responder(q):
            if "invoke FileProfile" in q:
                return [{"SHA256": "a" * 64, "GlobalPrevalence": 3, "Signer": "", "ProfileAvailability": "Available"}]
            return []
        self.g.hunting(responder)
        res = await hunts.hunt_ioc("a" * 64)
        self.assertEqual(res["fileProfile"]["GlobalPrevalence"], 3)
        self.assertIn("invoke FileProfile('SHA256', 1)", next(q for q in self.g.queries() if "FileProfile" in q))
        await hunts.hunt_ioc("b" * 32)   # MD5: no profile lookup
        self.assertEqual(sum("FileProfile" in q for q in self.g.queries()), 1)


if __name__ == "__main__":
    unittest.main()
