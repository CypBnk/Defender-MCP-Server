import unittest

from defender_mcp.errors import AmbiguousError, GraphError, InputError, NotFoundError
from defender_mcp.tools import (cloud_apps, detections, devices, hunting, hunts, identity, incidents, overview, posture,
                                vulnerabilities)
from helpers import AAD1, DEVICE_ROW, HUNT, MDE1, MDE2, SIM1, FakeGraph, configure, device_responder

INCIDENT = {"id": "29", "displayName": "Multi-stage incident", "status": "active", "severity": "high",
            "classification": "unknown", "createdDateTime": "2026-11-01T10:00:00Z", "comments": [],
            "alerts": [{"id": "da1", "title": "Suspicious PowerShell", "severity": "medium", "serviceSource":
                        "microsoftDefenderForEndpoint", "evidence": [
                            {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "pc-01"},
                            {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "203.0.113.9"}]}]}


class IncidentAlertTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        configure(self.g)

    async def test_list_incidents_filters_without_orderby(self):
        self.g.on("GET", "/security/incidents", {"value": [INCIDENT]})
        res = await incidents.list_incidents(status="active", severity="high", assigned_to="soc@contoso.com",
                                             since_hours=24, max_items=200)
        params = self.g.calls[-1].params
        self.assertIn("status eq 'active'", params["$filter"])
        self.assertIn("severity eq 'high'", params["$filter"])
        self.assertIn("assignedTo eq 'soc@contoso.com'", params["$filter"])
        self.assertIn("createdDateTime ge ", params["$filter"])
        self.assertEqual(params["$top"], "50")
        self.assertNotIn("$orderby", params)
        self.assertEqual(res["items"][0]["alertCount"], 1)

    async def test_list_incidents_page_sorted_newest_first(self):
        older = {**INCIDENT, "id": "28", "createdDateTime": "2026-10-01T08:00:00Z"}
        newer = {**INCIDENT, "id": "30", "createdDateTime": "2026-10-30T08:00:00Z"}
        self.g.on("GET", "/security/incidents", {"value": [older, newer]})
        res = await incidents.list_incidents()
        self.assertEqual([i["id"] for i in res["items"]], ["30", "28"])

    async def test_get_incident_with_alerts_and_entities(self):
        self.g.on("GET", "/security/incidents/29", INCIDENT)
        res = await incidents.get_incident("29")
        self.assertEqual(self.g.calls[-1].params, {"$expand": "alerts"})
        self.assertEqual(res["entities"], {"devices": ["pc-01"], "ips": ["203.0.113.9"]})
        self.assertEqual(res["alerts"][0]["title"], "Suspicious PowerShell")
        with self.assertRaises(InputError):
            await incidents.get_incident("29/comments")

    async def test_list_alerts_default_window_and_source(self):
        self.g.on("GET", "/security/alerts_v2", {"value": []})
        await incidents.list_alerts(service_source="microsoftDefenderForIdentity")
        flt = self.g.calls[-1].params["$filter"]
        self.assertIn("createdDateTime ge ", flt)
        self.assertIn("serviceSource eq 'microsoftDefenderForIdentity'", flt)
        self.assertNotIn("$orderby", self.g.calls[-1].params)

    async def test_get_alert_evidence(self):
        self.g.on("GET", "/security/alerts_v2/da637551227677560813_-961444813", {
            "id": "da637551227677560813_-961444813", "title": "x", "description": "d", "evidence": [
                {"@odata.type": "#microsoft.graph.security.fileEvidence",
                 "fileDetails": {"fileName": "evil.exe", "sha1": "ab" * 20}}]})
        res = await incidents.get_alert("da637551227677560813_-961444813")
        self.assertEqual(res["evidence"][0], {"type": "file", "fileName": "evil.exe", "sha1": "ab" * 20})
        with self.assertRaises(InputError):
            await incidents.get_alert("../x")


class HuntingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: [{"ColumnName": "Timestamp", "ColumnType": "datetime"}] if "getschema" in q
                       else [{"A": 1}])
        configure(self.g)

    async def test_run_hunting_query(self):
        res = await hunting.run_hunting_query("DeviceProcessEvents | take 10;", timespan_days=90, max_items=5)
        call = self.g.calls[-1]
        self.assertEqual(call.json_body["Query"], "DeviceProcessEvents | take 10\n| take 6")
        self.assertEqual(call.json_body["Timespan"], "P90D")
        self.assertEqual(res["rows"], [{"A": 1}])
        self.assertNotIn("kql", res)

    async def test_schema(self):
        res = await hunting.get_hunting_schema()
        names = [t["table"] for group in res["tables"].values() for t in group]
        self.assertIn("DeviceTvmSecureConfigurationAssessment", names)   # not the non-existent DeviceTvmSecurityConfigurationAssessment
        self.assertNotIn("DeviceTvmSecurityConfigurationAssessment", names)
        res = await hunting.get_hunting_schema("DeviceInfo")
        self.assertEqual(self.g.queries()[-1], "DeviceInfo\n| getschema\n| project ColumnName, ColumnType")
        self.assertEqual(res["columns"], [{"name": "Timestamp", "type": "datetime"}])
        with self.assertRaises(InputError):
            await hunting.get_hunting_schema("DeviceInfo | take 1")


class PrebuiltHuntTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: [])
        configure(self.g)

    async def test_endpoint_hunt_escapes_filters(self):
        res = await hunts.hunt_endpoint_threats("suspicious_powershell", days=3, device="PC-01",
                                                account="max@contoso.com")
        q = self.g.queries()[-1]
        self.assertIn("ago(3d)", q)
        self.assertIn("(DeviceName =~ 'PC-01' or DeviceName startswith 'PC-01.')", q)
        self.assertIn("AccountUpn =~ 'max@contoso.com'", q)
        self.assertEqual(res["hunt"], "suspicious_powershell")
        self.assertEqual(res["kql"], q)
        with self.assertRaises(InputError):
            await hunts.hunt_endpoint_threats("new_services", device="pc' or 1==1")
        with self.assertRaises(InputError):
            await hunts.hunt_endpoint_threats("new_services", days=90)

    async def test_all_endpoint_hunts_build(self):
        for name in ("suspicious_powershell", "lolbin_downloads", "new_services", "scheduled_tasks",
                     "antivirus_detections", "asr_events", "tampering_attempts", "local_admin_additions"):
            await hunts.hunt_endpoint_threats(name)
        self.assertIn('ActionType == "ServiceInstalled"', self.g.queries()[2])

    async def test_identity_failed_logons_use_action_type(self):
        await hunts.hunt_identity_threats("failed_logons", min_count=3)
        q = self.g.queries()[-1]
        self.assertIn('ActionType == "LogonFailed"', q)   # all failed logons, not only LogonType == "Failed logon"
        self.assertIn("FailedAttempts >= 3", q)
        for name in ("password_spray", "ldap_reconnaissance", "lateral_movement", "group_membership_changes",
                     "identity_alerts"):
            await hunts.hunt_identity_threats(name, account="max@contoso.com")
        self.assertIn('Fields["TO.GROUP"]', self.g.queries()[-2])

    async def test_identity_hunts_with_account(self):
        await hunts.hunt_identity_threats("password_spray", account="max@contoso.com")
        q = self.g.queries()[-1]
        # spraying is counted across all accounts; the account only selects the IPs that also targeted it
        self.assertIn("extend IsTarget = AccountUpn =~ 'max@contoso.com'", q)
        self.assertIn("TargetedAccounts >= 5 and FailedOnAccount > 0", q)
        self.assertLess(q.index("IsTarget"), q.index("summarize"))
        await hunts.hunt_identity_threats("failed_logons", account="max@contoso.com")
        self.assertIn("FailedAttempts >= 1", self.g.queries()[-1])
        await hunts.hunt_identity_threats("lateral_movement")
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("DeviceLogonEvents"))
        self.assertIn("TargetDevices >= 5", q)
        self.assertNotIn("Potential lateral movement path", q)   # LMP data is no longer collected (May 2025)
        await hunts.hunt_identity_threats("lateral_movement", account="max@contoso.com")
        self.assertIn("AccountName =~ 'max'", self.g.queries()[-1])
        self.assertIn("TargetDevices >= 1", self.g.queries()[-1])
        with self.assertRaises(InputError):
            await hunts.hunt_identity_threats("lateral_movement", account=AAD1)

    async def test_email_hunts(self):
        await hunts.hunt_email_threats("phishing", sender="evil.com", recipient="max@contoso.com",
                                       subject_contains="Invoice'")
        q = self.g.queries()[-1]
        self.assertIn("SenderFromDomain =~ 'evil.com'", q)
        self.assertIn("RecipientEmailAddress =~ 'max@contoso.com'", q)
        self.assertIn("Subject contains 'Invoice\\''", q)
        with self.assertRaises(InputError):
            await hunts.hunt_email_threats("message_trace")
        with self.assertRaises(InputError):
            await hunts.hunt_email_threats("url_clicks", sender="a@b.com")
        await hunts.hunt_email_threats("url_clicks", recipient="max@contoso.com")
        # ActionType values are single words (ClickBlocked, ClickBlockedByTenantPolicy): 'has' would never match
        self.assertIn('ActionType contains "Blocked"', self.g.queries()[-1])
        for name in ("threat_summary", "malware", "malicious_attachments", "spoofing"):
            await hunts.hunt_email_threats(name, sender="a@evil.com")
        self.assertIn("SenderFromAddress =~ 'a@evil.com'", self.g.queries()[-1])

    async def test_cloud_hunts(self):
        with self.assertRaises(InputError):
            await hunts.hunt_cloud_app_activity("account_activity")
        with self.assertRaises(InputError):
            await hunts.hunt_cloud_app_activity("account_activity", account="CONTOSO\\max")
        await hunts.hunt_cloud_app_activity("account_activity", account="max@contoso.com")
        self.assertIn("RawEventData.UserId", self.g.queries()[-1])
        for name in ("activity_summary", "oauth_consents", "mass_downloads", "admin_activity", "impossible_travel_alerts"):
            await hunts.hunt_cloud_app_activity(name, application="Microsoft SharePoint Online")

    async def test_ioc_detection_and_union(self):
        self.g.hunting(lambda q: [{"Source": "DeviceNetworkEvents", "Hits": 2}] if "summarize Hits" in q
                       else [{"Timestamp": "t", "Source": "DeviceNetworkEvents", "Entity": "pc-01", "Detail": "x"}])
        res = await hunts.hunt_ioc("203.0.113.5")
        self.assertEqual((res["type"], res["totalHits"]), ("ip", 2))
        self.assertTrue(any(q.startswith("union isfuzzy=true") and "RemoteIP in ('203.0.113.5', '::ffff:203.0.113.5')" in q
                            for q in self.g.queries()))
        self.assertEqual(res["events"][0]["Entity"], "pc-01")
        self.assertEqual((await hunts.hunt_ioc("A" * 64))["type"], "sha256")
        self.assertEqual((await hunts.hunt_ioc("b" * 40))["type"], "sha1")
        self.assertEqual((await hunts.hunt_ioc("evil.example.com"))["type"], "domain")
        res = await hunts.hunt_ioc("http://198.51.100.7/payload.exe")
        self.assertEqual(res["type"], "url")
        self.assertIn("RemoteIP in ('198.51.100.7', '::ffff:198.51.100.7')", self.g.queries()[-1])
        with self.assertRaises(InputError):
            await hunts.hunt_ioc("not a valid indicator")


class DeviceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        configure(self.g)

    async def test_find_defender_devices(self):
        self.g.hunting(lambda q: [dict(DEVICE_ROW, TotalMatches=7)])
        res = await devices.find_defender_devices(name_contains="pc", os_family="windows", sensor_health="impaired",
                                         internet_facing=True, max_items=1)
        q = self.g.queries()[-1]
        self.assertIn("DeviceName contains 'pc'", q)
        self.assertIn('OSPlatform startswith "Windows"', q)
        self.assertIn("IsInternetFacing == true", q)
        self.assertIn("let Total = toscalar(Devices | count)", q)
        self.assertEqual(res["total"], 7)
        self.assertNotIn("TotalMatches", res["items"][0])
        self.g.hunting(lambda q: [{"OSPlatform": "Windows11", "Devices": 5}, {"OSPlatform": "macOS", "Devices": 2}])
        self.assertEqual((await devices.find_defender_devices(summary_only=True))["total"], 7)

    async def test_get_device_resolves_and_reports_sections(self):
        def extra(q):
            if q.startswith("DeviceNetworkInfo"):
                return [{"NetworkAdapterName": "eth0", "IPAddresses": "[...]"}]
            if q.startswith("AlertEvidence"):
                return [{"AlertId": "a1", "Title": "x", "Severity": "High", "Timestamp": "t"}]
            if q.startswith("DeviceTvmSoftwareVulnerabilities"):
                return [{"VulnerabilitySeverityLevel": "Critical", "CVEs": 3}]
            if q.startswith("DeviceInfo"):
                return [{"DeviceId": MDE1, "LoggedOnUsers": "[{\"UserName\":\"max\"}]"}]
            return []
        self.g.hunting(device_responder(extra=extra))
        res = await devices.get_defender_device("PC-01")
        self.assertEqual(res["device"]["DeviceId"], MDE1)
        self.assertEqual(res["alerts30d"]["bySeverity"], {"High": 1})
        self.assertEqual(res["vulnerabilities"], {"Critical": 3})
        self.assertIn("LoggedOnUsers", res["details"])
        self.assertIn("(DeviceName =~ 'PC-01' or DeviceName startswith 'PC-01.')", self.g.queries()[0])
        self.assertIn("machine", res["errors"])   # no Defender for Endpoint API in this test: section error only
        await devices.get_defender_device(AAD1)
        self.assertTrue(any(f"AadDeviceId =~ '{AAD1}'" in q for q in self.g.queries()))

    async def test_ambiguous_and_missing_device(self):
        self.g.hunting(device_responder([DEVICE_ROW, dict(DEVICE_ROW, DeviceId=MDE2, DeviceName="pc-01.lab.local")]))
        with self.assertRaises(AmbiguousError) as ctx:
            await devices.get_defender_device("pc-01")
        self.assertIn(MDE2, str(ctx.exception))
        self.g.hunting(device_responder([]))
        with self.assertRaises(NotFoundError):
            await devices.get_defender_device("ghost")

    async def test_activity_with_device_id_skips_resolution(self):
        self.g.hunting(lambda q: [{"Timestamp": "t", "FileName": "cmd.exe"}])
        res = await devices.get_device_activity(MDE1, "processes", days=2, contains="powershell")
        self.assertEqual(len(self.g.queries()), 1)
        q = self.g.queries()[0]
        self.assertTrue(q.startswith("DeviceProcessEvents"))
        self.assertIn(f"DeviceId =~ '{MDE1}'", q)
        self.assertIn("ProcessCommandLine contains 'powershell'", q)
        self.assertEqual(res["deviceId"], MDE1)
        await devices.get_device_activity(MDE1, "alerts")
        self.assertIn("AlertEvidence", self.g.queries()[-1])

    async def test_exposure_uses_correct_tvm_tables(self):
        self.g.hunting(lambda q: [{"CveId": "CVE-1", "SeverityRank": 4}])
        res = await devices.get_device_exposure(MDE1, "vulnerabilities", severity="Critical")
        self.assertNotIn("SeverityRank", res["rows"][0])
        await devices.get_device_exposure(MDE1, "configuration")
        self.assertIn("DeviceTvmSecureConfigurationAssessment\n", self.g.queries()[-1])
        await devices.get_device_exposure(MDE1, "software")
        self.assertIn("DeviceTvmSoftwareInventory", self.g.queries()[-1])


class VulnerabilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: [{"CveId": "CVE-2024-21412", "VulnerabilitySeverityLevel": "High",
                                   "VulnerabilityDescription": "d"}] if "KB" in q.split("\n")[0]
                       else [{"DeviceName": "pc-01", "TotalDevices": 4}])
        configure(self.g)

    async def test_overview_views(self):
        for view in ("top_cves", "vulnerable_software", "exposed_devices", "misconfigurations"):
            await vulnerabilities.get_vulnerability_overview(view, severity="Critical", exploit_available_only=True)
        self.assertNotIn("VulnerabilitySeverityLevel", self.g.queries()[-1])   # misconfigurations ignore severity
        self.assertIn("IsExploitAvailable == true", self.g.queries()[0])
        await vulnerabilities.get_vulnerability_overview("exposed_devices", severity="High")
        self.assertIn("VulnerabilitySeverityLevel in ('High', 'Critical')", self.g.queries()[-1])   # minimum severity

    async def test_cve(self):
        res = await vulnerabilities.get_cve_exposure("cve-2024-21412")
        self.assertEqual(res["cve"], "CVE-2024-21412")
        self.assertEqual(res["affectedDevices"], 4)
        self.assertEqual(res["details"]["VulnerabilitySeverityLevel"], "High")
        with self.assertRaises(InputError):
            await vulnerabilities.get_cve_exposure("CVE-2024-1' or 1==1")


class PostureTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        configure(self.g)

    async def test_secure_score_improvements(self):
        self.g.on("GET", "/security/secureScores", {"value": [
            {"createdDateTime": "2026-11-01T00:00:00Z", "currentScore": 50, "maxScore": 100,
             "controlScores": [{"controlName": "MFA", "controlCategory": "Identity", "score": 2},
                               {"controlName": "ASR", "controlCategory": "Device", "score": 0}]},
            {"createdDateTime": "2026-10-31T00:00:00Z", "currentScore": 40, "maxScore": 100}]})
        self.g.on("GET", "/security/secureScoreControlProfiles", {"value": [
            {"id": "MFA", "title": "Require MFA", "maxScore": 10, "controlCategory": "Identity",
             "remediation": "<p>Enable <b>MFA</b></p>"},
            {"id": "ASR", "title": "Enable ASR", "maxScore": 5, "controlCategory": "Device"}]})
        res = await posture.get_secure_score(history_days=2)
        self.assertEqual(res["current"]["percentage"], 50.0)
        self.assertEqual([i["id"] for i in res["topImprovements"]], ["MFA", "ASR"])
        self.assertEqual(res["topImprovements"][0]["possibleGain"], 8.0)
        self.assertEqual(res["topImprovements"][0]["remediation"], "Enable MFA")
        self.assertEqual(len(res["trend"]), 2)
        res = await posture.get_secure_score(category="Device")
        self.assertEqual([i["id"] for i in res["topImprovements"]], ["ASR"])

    async def test_simulations(self):
        self.g.on("GET", "/security/attackSimulation/simulations", {"value": [{"id": SIM1, "displayName": "Q4",
                                                                              "createdBy": {"email": "a@b.c"}}]})
        res = await posture.list_attack_simulations(status="succeeded")
        self.assertEqual(self.g.calls[-1].params["$orderby"], "launchDateTime desc")
        self.assertEqual(res["items"][0]["createdBy"], "a@b.c")
        self.g.on("GET", f"/security/attackSimulation/simulations/{SIM1}", {"id": SIM1, "displayName": "Q4"})
        self.g.on("GET", f"/security/attackSimulation/simulations/{SIM1}/report/overview",
                  {"resolvedTargetsCount": 10, "simulationEventsContent": {"compromisedRate": 20.0}})
        res = await posture.list_attack_simulations(simulation_id=SIM1)
        self.assertEqual(res["overview"]["resolvedTargetsCount"], 10)


class IdentityCloudDetectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        configure(self.g)

    async def test_identity_health(self):
        self.g.on("GET", "/security/identities/healthIssues", {"value": [
            {"id": "i1", "status": "open", "severity": "high", "createdDateTime": "2026-10-02"},
            {"id": "i2", "status": "closed", "severity": "low", "createdDateTime": "2026-10-01"},
            {"id": "i3", "status": "open", "severity": "medium", "createdDateTime": "2026-10-03"}]})
        res = await identity.get_identity_health()
        self.assertEqual([i["id"] for i in res["items"]], ["i3", "i1"])
        self.assertEqual(res["bySeverity"], {"high": 1, "medium": 1})
        self.g.on("GET", "/security/identities/healthIssues/i1", {"id": "i1", "recommendations": ["Fix auditing"]})
        res = await identity.get_identity_health(issue_id="i1")
        self.assertEqual(res["recommendations"], ["Fix auditing"])

    async def test_cloud_discovery(self):
        # filters run in the tool (aggregatedAppsDetails has no $orderby); the risk field is riskScore
        self.g.on("GET", "/security/dataDiscovery/cloudAppDiscovery/uploadedStreams", {"value": [{"id": "s1",
                                                                                                "displayName": "MDE"}]})
        res = await cloud_apps.get_cloud_app_discovery(view="streams")
        self.assertEqual(res["items"][0]["id"], "s1")
        path = ("/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/s1/"
                "microsoft.graph.security.aggregatedAppsDetails(period=duration'P90D')")
        self.g.on("GET", path, {"value": [{"id": "1", "displayName": "Dropbox", "riskScore": 3, "category": "cloudStorage",
                                           "domains": list("abcdefg")},
                                          {"id": "2", "displayName": "Box", "riskScore": 9, "category": "cloudStorage"}]})
        res = await cloud_apps.get_cloud_app_discovery(view="apps", stream_id="s1", period="P90D", max_risk_score=4,
                                                       category="Cloud storage")
        self.assertEqual([a["name"] for a in res["items"]], ["Dropbox"])
        self.assertEqual(len(res["items"][0]["domains"]), 5)
        self.assertEqual(self.g.calls[-1].version, "beta")

    async def test_detection_rules(self):
        rule = {"id": "office-encoded-powershell", "displayName": "Encoded PS", "status": "enabled",
                "schedule": {"frequency": "PT1H"}, "queryCondition": {"queryText": "DeviceProcessEvents"},
                "detectionAction": {"alertTemplate": {"title": "t", "severity": "high",
                                                      "tactics": [{"tactic": "Execution"}]}}}
        self.g.on("GET", "/security/rules/detectionRules", {"value": [rule]})
        res = await detections.list_detection_rules(status="enabled", name_contains="PS")
        self.assertEqual(self.g.calls[-1].params["$filter"], "contains(displayName,'PS') and status eq 'enabled'")
        self.assertEqual(res["items"][0]["frequency"], "PT1H")
        self.assertEqual(res["items"][0]["tactics"], ["Execution"])
        self.g.on("GET", "/security/rules/detectionRules/office-encoded-powershell", rule)
        res = await detections.get_detection_rule("office-encoded-powershell")
        self.assertEqual(res["query"], "DeviceProcessEvents")


class OverviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_sections_and_errors(self):
        g = FakeGraph()
        configure(g)
        g.on("GET", "/me", {"displayName": "Analyst", "userPrincipalName": "a@contoso.com", "id": "u"})
        by_status = {
            "status eq 'active'": {"value": [{"id": "1", "severity": "high", "status": "active"}]},
            "status eq 'inProgress'": {"value": [{"id": "2", "severity": "low", "status": "inProgress",
                                                  "assignedTo": "x"}]},
            "status eq 'awaitingAction'": GraphError(400, "BadRequest", "unsupported"),
        }
        g.on("GET", "/security/incidents", lambda params, _body: by_status[params["$filter"]])
        g.on("GET", "/security/secureScores", {"value": [{"currentScore": 30, "maxScore": 60}]})
        g.on("GET", "/security/identities/healthIssues", GraphError(403, "Forbidden", "no role"))

        def responder(q):
            if "by ServiceSource" in q:
                return [{"ServiceSource": "Microsoft Defender for Endpoint", "Alerts": 4, "High": 1}]
            if "by OnboardingStatus" in q:
                return [{"OnboardingStatus": "Onboarded", "SensorHealthState": "Active", "Devices": 9}]
            return []
        g.hunting(responder)
        res = await overview.get_security_overview(days=3)
        self.assertEqual(res["openIncidents"]["bySeverity"]["high"], 1)
        self.assertEqual(res["openIncidents"]["unassigned"], 1)
        self.assertEqual(res["openIncidents"]["byStatus"], {"active": 1, "inProgress": 1})
        self.assertEqual(res["openIncidents"]["statusesNotRead"], ["awaitingAction"])
        self.assertEqual(res["alerts"]["total"], 4)
        self.assertEqual(res["devices"]["total"], 9)
        self.assertEqual(res["secureScore"]["percentage"], 50.0)
        self.assertIn("identityHealth", res["errors"])
        self.assertTrue(all("ago(3d)" in q for q in g.queries() if q.startswith("AlertInfo")))
        self.assertTrue(any(c.path == HUNT for c in g.calls))


if __name__ == "__main__":
    unittest.main()
