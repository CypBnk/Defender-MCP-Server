"""Coverage of a systematic comparison with the advanced hunting schema (Learn 10/2026),
the Defender portal areas and the Graph APIs (identity inventory and risks, AD account actions via Defender for
Identity, submissions, attack disruption, email/Teams/SharePoint hunts, OAuth apps, baselines, extensions,
certificates)."""
import unittest

from defender_mcp.errors import GraphError, InputError, NotFoundError
from defender_mcp.tools import (admin_response, admin_submissions, admin_users, devices, hunting, hunts, identity_risk,
                                users, vulnerabilities)
from helpers import FakeGraph, configure, device_responder

OID = "11111111-2222-3333-4444-555555555555"
SID = "S-1-5-21-1-2-3-1104"
USER = {"id": OID, "displayName": "Max Muster", "userPrincipalName": "max@contoso.com", "accountEnabled": True,
        "userType": "Member", "onPremisesSyncEnabled": True, "onPremisesSecurityIdentifier": SID}
IDENTITY = {"id": "00104216-0539-4838-88b1-55baafdc296b", "displayName": "Max Muster", "domain": "corp.contoso.com",
            "onPremisesSecurityIdentifier": SID, "isEnabled": True,
            "accounts": [{"provider": "EntraID", "identifier": "69dfa3ea"},
                         {"provider": "ActiveDirectory", "identifier": "256db173-930a-4991-9061-0d51a9a93ba5"}]}
# Learn "Data tables in the advanced hunting schema" (10/28/2026) without the retired AAD*EventsBeta tables
LEARN_TABLES = """AgentsInfo AlertEvidence AlertInfo BehaviorEntities BehaviorInfo CallActivityEvents CampaignInfo
CloudAppEvents CloudAuditEvents CloudDnsEvents CloudKeyVaultEvents CloudPolicyEnforcementEvents CloudProcessEvents
CloudStorageAggregatedEvents DataSecurityBehaviors DataSecurityEvents DeviceBaselineComplianceAssessment
DeviceBaselineComplianceAssessmentKB DeviceBaselineComplianceProfiles DeviceEvents DeviceFileCertificateInfo
DeviceFileEvents DeviceImageLoadEvents DeviceInfo DeviceLogonEvents DeviceNetworkEvents DeviceNetworkInfo
DeviceProcessEvents DeviceRegistryEvents DeviceTvmBrowserExtensions DeviceTvmBrowserExtensionsKB DeviceTvmCertificateInfo
DeviceTvmHardwareFirmware DeviceTvmInfoGathering DeviceTvmInfoGatheringKB DeviceTvmSecureConfigurationAssessment
DeviceTvmSecureConfigurationAssessmentKB DeviceTvmSoftwareEvidenceBeta DeviceTvmSoftwareInventory
DeviceTvmSoftwareVulnerabilities DeviceTvmSoftwareVulnerabilitiesKB DisruptionAndResponseEvents EmailAttachmentInfo
EmailEvents EmailPostDeliveryEvents EmailUrlInfo EntraIdSignInEvents EntraIdSpnSignInEvents ExposureGraphEdges
ExposureGraphNodes FileMaliciousContentInfo GraphAPIAuditEvents IdentityAccountInfo IdentityDirectoryEvents
IdentityEvents IdentityInfo IdentityLogonEvents IdentityQueryEvents MessageContents MessageEvents
MessagePostDeliveryEvents MessageUrlInfo OAuthAppInfo UrlClickEvents""".split()


class CatalogTests(unittest.TestCase):
    def test_catalog_covers_every_advanced_hunting_table(self):
        known = {t for items in hunting.TABLES.values() for t, _ in items}
        self.assertEqual(sorted(set(LEARN_TABLES) - known), [])


class HuntTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: [])
        configure(self.g)

    async def test_email_teams_and_collaboration_hunts(self):
        await hunts.hunt_email_threats("post_delivery", recipient="max@contoso.com")
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("EmailPostDeliveryEvents"))
        self.assertIn("| where RecipientEmailAddress =~ 'max@contoso.com'", q)
        self.assertIn("on NetworkMessageId, RecipientEmailAddress", q)
        await hunts.hunt_email_threats("campaigns", sender="evil.example")
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("CampaignInfo"))
        self.assertIn("SenderFromAddress endswith '@evil.example'", q)
        self.assertIn("by CampaignId, CampaignName, CampaignType, CampaignSubtype", q)
        await hunts.hunt_email_threats("teams_threats", sender="evil.example", recipient="max@contoso.com")
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("MessageEvents"))
        self.assertIn("SenderEmailAddress endswith '@evil.example'", q)
        self.assertIn("tostring(RecipientDetails) contains 'max@contoso.com'", q)
        await hunts.hunt_email_threats("collaboration_files", recipient="max@contoso.com")
        self.assertIn("FileOwnerUpn =~ 'max@contoso.com' or LastModifyingAccountUpn =~", self.g.queries()[-1])
        with self.assertRaises(InputError):
            await hunts.hunt_email_threats("collaboration_files", sender="x@y.com")

    async def test_oauth_app_inventory(self):
        await hunts.hunt_cloud_app_activity("oauth_apps", application="Mail")
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("OAuthAppInfo\n| summarize arg_max(Timestamp, *) by OAuthAppId"))
        self.assertIn("| where AppName contains 'Mail'", q)
        self.assertIn('countof(tolower(tostring(Permissions)), \'"privilegelevel":"high"\')', q)
        with self.assertRaises(InputError):
            await hunts.hunt_cloud_app_activity("oauth_apps", account="max@contoso.com")

    async def test_attack_disruption_needs_no_endpoint_api(self):
        self.g.hunting(lambda q: [{"ActionType": "ContainedUserLogonBlocked", "Events": 3}] if "summarize" in q else
                       [{"ActionType": "ContainedUserLogonBlocked", "SourceUserName": "max"}])
        res = await admin_response.get_response_actions(kind="attack_disruption", device="PC-01")
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("DisruptionAndResponseEvents"))
        self.assertIn("TargetDeviceName =~ 'PC-01' or TargetDeviceName startswith 'PC-01.'", q)
        self.assertEqual(res["summary"][0]["Events"], 3)
        self.assertEqual(res["events"][0]["SourceUserName"], "max")


class IdentityInventoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_filters_and_summary(self):
        g = FakeGraph()
        g.hunting(lambda q: [{"DisplayName": "Max", "Privileged": True}])
        configure(g)
        res = await users.find_identities(source="Active Directory", privileged_only=True, status="Enabled",
                                          without_mfa=True, name_contains="max")
        q = g.queries()[-1]
        self.assertIn("| summarize arg_max(Timestamp, *) by AccountId", q)
        self.assertIn('contains "ActiveDirectory" and not(IsCloudAccount)', q)
        self.assertIn("| where Privileged", q)
        self.assertIn("| where IsCloudAccount and MfaMethods == 0", q)
        self.assertIn('| where AccountStatus != "Deleted"', q)
        self.assertEqual(res["count"], 1)
        await users.find_identities(summary_only=True)
        self.assertIn("by SourceProvider, Type", g.queries()[-1])
        # 'Entra' / 'Azure AD' select the cloud accounts; 'Active Directory' must not match 'AzureActiveDirectory'
        await users.find_identities(source="Azure AD")
        q = g.queries()[-1]
        self.assertIn("| where IsCloudAccount\n", q + "\n")
        self.assertNotIn("replace_string(SourceProvider", q)
        await users.find_identities(source="Okta")
        self.assertIn('| where replace_string(SourceProvider, " ", "") contains \'Okta\'', g.queries()[-1])


class IdentityRiskTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()

        def risky(params, _body):
            state = params["$filter"].split("'")[1]
            return {"value": [{"id": "u1", "userPrincipalName": "a@contoso.com", "riskLevel": "medium", "riskState": state,
                               "riskLastUpdatedDateTime": "2026-11-01T00:00:00Z"},
                              {"id": "u2", "userPrincipalName": "b@contoso.com", "riskLevel": "high", "riskState": state,
                               "riskLastUpdatedDateTime": "2026-10-01T00:00:00Z"}] if state == "atRisk" else []}
        self.g.on("GET", "/identityProtection/riskyUsers", risky)
        self.g.on("GET", "/identityProtection/riskDetections", {"value": [
            {"userPrincipalName": "a@contoso.com", "riskEventType": "passwordSpray", "riskLevel": "high",
             "riskState": "atRisk", "detectedDateTime": "2026-11-02T08:00:00Z", "location": {"city": "Kyiv",
                                                                                          "countryOrRegion": "UA"}},
            {"userPrincipalName": "a@contoso.com", "riskEventType": "anonymizedIPAddress", "riskLevel": "low",
             "riskState": "atRisk", "detectedDateTime": "2026-11-02T09:00:00Z"}]})
        configure(self.g)

    async def test_users_detections(self):
        res = await identity_risk.get_identity_risks()
        self.assertEqual([i["id"] for i in res["items"]], ["u2", "u1"])   # high first
        filters = sorted(c.params["$filter"] for c in self.g.calls if c.path == "/identityProtection/riskyUsers")
        self.assertEqual(filters, ["riskState eq 'atRisk'", "riskState eq 'confirmedCompromised'"])
        res = await identity_risk.get_identity_risks(min_risk_level="high")
        self.assertEqual(res["total"], 1)
        res = await identity_risk.get_identity_risks("detections", user="a@contoso.com", days=3)
        params = self.g.calls[-1].params
        self.assertIn("detectedDateTime ge ", params["$filter"])
        self.assertIn("userPrincipalName eq 'a@contoso.com'", params["$filter"])
        self.assertEqual(params["$top"], "500")
        self.assertEqual(res["byType"], {"passwordSpray": 1, "anonymizedIPAddress": 1})
        self.assertEqual(res["items"][0]["location"], "Kyiv, UA")
        with self.assertRaises(InputError):
            await identity_risk.get_identity_risks("users", user="a@contoso.com")


class AdAccountActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", "/users", {"value": [USER]})
        self.g.on("GET", f"/users/{OID}", USER)
        self.g.on("GET", "/me", {"id": "someone-else", "onPremisesSecurityIdentifier": "S-1-5-21-9-9-9-500"})
        self.g.on("GET", "/security/identities/identityAccounts", {"value": [IDENTITY]})
        self.g.on("POST", f"/security/identities/identityAccounts/{IDENTITY['id']}/invokeAction",
                  {"value": {"correlationId": "c-1", "action": "disable"}})
        configure(self.g)

    async def test_disable_ad_account_two_step(self):
        preview = await admin_users.contain_user("max@contoso.com", "disable_ad_account")
        self.assertEqual(preview["status"], "confirmation_required")
        self.assertEqual(preview["preview"]["identity"]["domain"], "corp.contoso.com")
        lookup = next(c for c in self.g.calls if c.path == "/security/identities/identityAccounts")
        self.assertEqual(lookup.params["$filter"], f"onPremisesSecurityIdentifier eq '{SID}'")
        done = await admin_users.contain_user("max@contoso.com", "disable_ad_account",
                                              confirmation_token=preview["confirmation_token"])
        self.assertEqual(done["status"], "done")
        self.assertEqual(self.g.calls[-1].json_body, {"accountId": "256db173-930a-4991-9061-0d51a9a93ba5",
                                                      "action": "disable", "identityProvider": "activeDirectory"})
        preview = await admin_users.contain_user(SID, "force_password_reset")   # on-premises SID works too
        await admin_users.contain_user(SID, "force_password_reset", confirmation_token=preview["confirmation_token"])
        self.assertEqual(self.g.calls[-1].json_body["action"], "forcePasswordReset")

    async def test_rules(self):
        with self.assertRaises(InputError):   # already enabled
            await admin_users.contain_user("max@contoso.com", "enable_ad_account")
        with self.assertRaises(InputError) as ctx:   # synchronized account: Entra disable points to the AD action
            await admin_users.contain_user("max@contoso.com", "disable_account")
        self.assertIn("disable_ad_account", str(ctx.exception))
        self.g.on("GET", "/me", {"id": "x", "onPremisesSecurityIdentifier": SID})
        with self.assertRaises(InputError):   # own account
            await admin_users.contain_user("max@contoso.com", "disable_ad_account")
        self.g.on("GET", "/security/identities/identityAccounts", {"value": []})
        with self.assertRaises(NotFoundError):
            await admin_users.contain_user("max@contoso.com", "disable_ad_account")
        self.g.on("GET", "/users", {"value": [dict(USER, onPremisesSecurityIdentifier=None)]})
        with self.assertRaises(InputError):   # cloud-only account
            await admin_users.contain_user("max@contoso.com", "disable_ad_account")


class SubmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", "/security/threatSubmission/emailThreats", {"value": [
            {"id": "e1", "contentType": "email", "category": "phishing", "source": "user", "status": "succeeded",
             "createdDateTime": "2099-01-02T00:00:00Z", "result": {"detail": "allowedByPolicy"},
             "createdBy": {"user": {"email": "max@contoso.com"}}, "subject": "Invoice"}]})
        self.g.on("GET", "/security/threatSubmission/urlThreats", GraphError(400, "BadRequest", "filter not supported"))
        self.g.on("GET", "/security/threatSubmission/fileThreats", {"value": []})
        self.g.on("POST", "/security/threatSubmission/urlThreats", {"id": "u1", "status": "running", "category": "phishing",
                                                                    "webUrl": "https://evil.example/login"})
        configure(self.g)

    async def test_list_and_submit_url(self):
        res = await admin_submissions.manage_submissions("list", source="user")
        self.assertEqual([i["id"] for i in res["items"]], ["e1"])
        self.assertEqual(res["items"][0]["submittedBy"], "max@contoso.com")
        self.assertEqual(res["byVerdict"], {"allowedByPolicy": 1})
        self.assertIn("url", res["errors"])   # URL list failed even without $filter: reported, the rest is shown
        email_call = next(c for c in self.g.calls if c.path.endswith("emailThreats"))
        self.assertEqual(email_call.version, "beta")
        self.assertIn("createdDateTime ge ", email_call.params["$filter"])
        preview = await admin_submissions.manage_submissions("submit_url", url="https://evil.example/login",
                                                             category="phishing")
        self.assertEqual(preview["status"], "confirmation_required")
        done = await admin_submissions.manage_submissions("submit_url", url="https://evil.example/login",
                                                          category="phishing",
                                                          confirmation_token=preview["confirmation_token"])
        self.assertEqual(done["status"], "done")
        self.assertEqual(self.g.calls[-1].json_body, {"@odata.type": "#microsoft.graph.urlThreatSubmission",
                                                      "category": "phishing", "webUrl": "https://evil.example/login"})
        with self.assertRaises(InputError):
            await admin_submissions.manage_submissions("submit_url", url="https://evil.example/login")


class PostureViewTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(device_responder(extra=lambda q: [{"ProfileName": "CIS Windows 11", "CompliancePercent": 71.5}]
                                        if q.startswith("DeviceBaselineComplianceAssessment") else []))
        configure(self.g)

    async def test_overview_views(self):
        res = await vulnerabilities.get_vulnerability_overview("security_baselines")
        self.assertEqual(res["profiles"][0]["ProfileName"], "CIS Windows 11")
        queries = self.g.queries()
        self.assertTrue(any("| where IsApplicable == true and IsExempt != true\n" in q for q in queries))
        self.assertTrue(any("ConfigurationName = take_any(ConfigurationName)" in q for q in queries))
        # only assessed checks count (IsCompliant null = not assessed), no division by zero
        self.assertTrue(any("Checks = countif(isnotnull(IsCompliant))" in q and "iff(Checks > 0" in q for q in queries))
        await vulnerabilities.get_vulnerability_overview("browser_extensions", severity="High")
        self.assertIn("| where RiskRank >= 3", self.g.queries()[-1])
        await vulnerabilities.get_vulnerability_overview("certificates")
        q = self.g.queries()[-1]
        self.assertIn("Expires = todatetime(ExpirationDate)", q)
        self.assertIn('| where Status in ("expired", "expires within 30 days") or Weak', q)
        self.assertIn('(toint(KeySize) < 2048 and SignatureAlgorithm !contains "ecdsa")', q)   # ECC P-256 is not weak
        with self.assertRaises(InputError):
            await vulnerabilities.get_vulnerability_overview("certificates", software="x")

    async def test_device_views(self):
        for view, table in (("browser_extensions", "DeviceTvmBrowserExtensions"),
                            ("certificates", "DeviceTvmCertificateInfo"),
                            ("security_baselines", "DeviceBaselineComplianceAssessment")):
            await devices.get_device_exposure("PC-01", view=view)
            q = self.g.queries()[-1]
            self.assertTrue(q.startswith(table), view)
            self.assertIn("| where DeviceId =~ '", q)
        with self.assertRaises(InputError):
            await devices.get_device_exposure("PC-01", view="certificates", software="x")


if __name__ == "__main__":
    unittest.main()
