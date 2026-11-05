"""Cloud Discovery evaluation (summary, apps, app, streams) and sanction_cloud_apps (undocumented Defender
for Cloud Apps endpoint, OBO or legacy API token)."""
import unittest

from defender_mcp import runtime
from defender_mcp.errors import ConfirmationError, GraphError, InputError, NotFoundError
from defender_mcp.graph.client import MdcaClient
from defender_mcp.settings import Secret, Settings, SettingsError
from defender_mcp.tools import admin_cloud_apps, cloud_apps
from helpers import FakeGraph, FakeHttp, FakeResponse, configure, env, make_settings

STREAMS = "/security/dataDiscovery/cloudAppDiscovery/uploadedStreams"
MDE = {"id": "93b60b3e-3a28-bf33-2d73-3cb0199c5f7a", "displayName": "Defender-managed endpoints",
       "logDataProvider": "microsoftDefenderForEndpoint", "lastDataReceivedDateTime": "2026-11-01T00:00:00Z"}
FW = {"id": "5d3a0c1f9e1b2c0012345678", "displayName": "Palo Alto", "logDataProvider": "paloAlto",
      "lastDataReceivedDateTime": "2026-11-02T00:00:00Z"}


def path(sid=MDE["id"], period="P30D"):
    return f"{STREAMS}/{sid}/microsoft.graph.security.aggregatedAppsDetails(period=duration'{period}')"


def app(i, name, score, tags=(), users=10, category="cloudStorage", upload=100, domains=("x.com",)):
    return {"id": str(i), "displayName": name, "riskScore": score, "tags": list(tags), "userCount": users,
            "category": category, "uploadNetworkTrafficInBytes": upload, "downloadNetworkTrafficInBytes": 50,
            "transactionCount": users * 3, "ipAddressCount": 2, "lastSeenDateTime": "2026-11-01T00:00:00Z",
            "domains": list(domains)}


APPS = [app(11627, "Dropbox", 6, users=40, upload=9000, domains=("dropbox.com", "dropboxapi.com")),
        app(10489, "Box", 9, tags=["Sanctioned"], users=80),
        app(20001, "WeTransfer", 2, tags=["Unsanctioned"], users=5, category="contentSharing"),
        app(20002, "ChatGPT", 4, users=120, category="generativeAi", upload=500),
        app(20003, "Some MCP Server", None, users=3, category="mcpServer"),
        app(20004, "OldTool", 1, tags=["Unsanctioned"], users=0, category="productivity")]
APPS[5]["transactionCount"] = 0


def pages(apps, size):
    """Responder that serves apps in pages via $top/$skip (no nextLink)."""
    def responder(params, _body):
        skip = int(params.get("$skip", 0))
        return {"value": apps[skip:skip + size]}
    return responder


class SummaryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", STREAMS, {"value": [FW, MDE]})
        self.g.on("GET", path(), pages(APPS, 4))
        configure(self.g)

    async def test_summary_defaults_to_mde_stream_and_evaluates(self):
        res = await cloud_apps.get_cloud_app_discovery()
        self.assertEqual(res["view"], "summary")
        self.assertEqual(res["stream"]["id"], MDE["id"])                  # Defender for Endpoint stream preferred
        self.assertEqual(res["otherStreams"][0]["displayName"], "Palo Alto")
        self.assertEqual(res["apps"], 6)                                   # two pages via $skip
        gets = [c for c in self.g.calls if c.path == path()]
        self.assertEqual(gets[0].params, {"$top": "500"})
        self.assertEqual(gets[1].params, {"$top": "500", "$skip": "4"})
        self.assertEqual(res["byTag"], {"untagged": 3, "Unsanctioned": 2, "Sanctioned": 1})
        self.assertEqual(res["byRiskBand"], {"high": 2, "medium": 2, "low": 1, "unscored": 1})
        self.assertEqual([a["name"] for a in res["unsanctionedInUse"]["top"]], ["WeTransfer"])   # OldTool: no use
        self.assertEqual([a["name"] for a in res["reviewCandidates"]["top"]], ["ChatGPT", "Dropbox"])
        self.assertEqual(res["reviewCandidates"]["maxRiskScore"], 6)
        self.assertEqual({a["name"] for a in res["aiApps"]["top"]}, {"ChatGPT", "Some MCP Server"})
        self.assertEqual(res["topByUsers"][0]["name"], "ChatGPT")
        self.assertEqual(res["topByUpload"][0]["name"], "Dropbox")
        self.assertEqual(res["topCategories"][0], {"category": "cloudStorage", "apps": 2, "users": 120,
                                                    "uploadBytes": 9100})
        self.assertEqual(res["traffic"]["transactions"], sum(a["transactionCount"] for a in APPS))

    async def test_threshold_and_explicit_stream(self):
        self.g.on("GET", path(FW["id"], "P7D"), {"value": APPS[:2]})
        res = await cloud_apps.get_cloud_app_discovery(stream_id=FW["id"], period="P7D", max_risk_score=5)
        self.assertEqual(res["stream"], {"id": FW["id"]})
        self.assertEqual(res["reviewCandidates"]["count"], 0)              # Dropbox (6) above threshold 5
        self.assertNotIn(STREAMS, self.g.paths("GET"))                     # no stream listing needed

    async def test_no_streams(self):
        self.g.on("GET", STREAMS, {"value": []})
        with self.assertRaises(NotFoundError):
            await cloud_apps.get_cloud_app_discovery()

    async def test_streams_view(self):
        res = await cloud_apps.get_cloud_app_discovery(view="streams")
        self.assertEqual(res["total"], 2)
        self.assertTrue(res["items"][1]["isDefenderForEndpoint"])
        self.assertEqual(self.g.calls[-1].params, {})                       # the method supports no OData options


class PagingTests(unittest.IsolatedAsyncioTestCase):
    async def test_next_link_top_fallback_repeat_and_limit(self):
        g = FakeGraph()
        configure(g)
        link = f"https://graph.microsoft.com/beta{path()}?$skiptoken=p2"

        def responder(params, _body):
            if params.get("$skiptoken") == "p2":
                return {"value": APPS[3:]}
            if "$top" in params:
                return GraphError(400, "BadRequest", "top not supported")
            return {"value": APPS[:3], "@odata.nextLink": link}
        g.on("GET", path(), responder)
        apps, complete = await cloud_apps.all_apps(MDE["id"], "P30D")
        self.assertEqual((len(apps), complete), (6, True))
        self.assertEqual(g.calls[1].params, {})                             # retried without $top
        g.on("GET", path(), lambda params, _b: {"value": APPS[:2]})          # $skip ignored: same page again
        apps, complete = await cloud_apps.all_apps(MDE["id"], "P30D")
        self.assertEqual((len(apps), complete), (2, True))                  # short first page: all apps read
        full = [app(i, f"a{i}", 5) for i in range(500)]
        g.on("GET", path(), lambda params, _b: {"value": full})              # full page repeated: more may exist
        apps, complete = await cloud_apps.all_apps(MDE["id"], "P30D")
        self.assertEqual((len(apps), complete), (500, False))
        configure(g, settings=make_settings(scan_limit=100))
        g.on("GET", path(), pages([app(i, f"a{i}", 5) for i in range(150)], 60))
        apps, complete = await cloud_apps.all_apps(MDE["id"], "P30D")
        self.assertEqual((len(apps), complete), (100, False))


class AppsViewTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", STREAMS, {"value": [MDE]})
        self.g.on("GET", path(), {"value": APPS})
        configure(self.g)

    async def names(self, **kwargs):
        res = await cloud_apps.get_cloud_app_discovery(view="apps", **kwargs)
        return [a["name"] for a in res["items"]]

    async def test_filters_and_sorting(self):
        self.assertEqual(await self.names(category="Cloud storage"), ["Box", "Dropbox"])
        self.assertEqual(await self.names(category="ai"), ["ChatGPT", "Some MCP Server"])
        self.assertEqual(await self.names(category="AI - MCP Server"), ["Some MCP Server"])
        self.assertEqual(await self.names(tag="untagged", sort_by="name"), ["ChatGPT", "Dropbox", "Some MCP Server"])
        self.assertEqual(await self.names(tag="unsanctioned", sort_by="risk"), ["OldTool", "WeTransfer"])
        self.assertEqual(await self.names(max_risk_score=4, sort_by="risk"), ["OldTool", "WeTransfer", "ChatGPT"])
        self.assertEqual(await self.names(name_contains="dropboxapi"), ["Dropbox"])   # matches a domain
        self.assertEqual((await self.names(sort_by="upload"))[0], "Dropbox")
        with self.assertRaises(InputError):
            await self.names(category="toaster")

    async def test_cursor_pages_through_the_filtered_list(self):
        res = await cloud_apps.get_cloud_app_discovery(view="apps", tag="untagged", max_items=2)
        self.assertEqual([a["name"] for a in res["items"]], ["ChatGPT", "Dropbox"])
        self.assertTrue(res["truncated"])
        nxt = await cloud_apps.get_cloud_app_discovery(cursor=res["cursor"], max_items=2)
        self.assertEqual([a["name"] for a in nxt["items"]], ["Some MCP Server"])
        self.assertEqual(nxt["stream"], {"id": MDE["id"]})                 # the cursor keeps the resolved stream
        self.assertEqual(res["items"][1]["domains"], ["dropbox.com", "dropboxapi.com"])
        self.assertEqual(res["items"][1]["riskScore"], 6)


class AppViewTests(unittest.IsolatedAsyncioTestCase):
    async def test_detail_with_attributes_users_and_devices(self):
        g = FakeGraph()
        g.on("GET", STREAMS, {"value": [MDE]})
        base = f"{path()}/11627"
        g.on("GET", base, {**APPS[0], "deviceCount": 7})
        g.on("GET", f"{base}/appInfo", {"vendor": "Dropbox", "founded": 2007, "headquarters": "unknown",
                                        "isMultiFactorAuthentication": "true", "isSupportsSaml": "false",
                                        "encryptionProtocol": "tls1_2", "dataAtRestEncryptionMethod": "notSupported",
                                        "isSoc2Compliant": "true", "isIso27001Compliant": "true",
                                        "isHipaaCompliant": "false", "pciDssVersion": "v3_2_1",
                                        "fedRampLevel": "notSupported", "isGdprRightToErasure": "true",
                                        "isGdprReportDataBreaches": "false", "isGdprRightToAccess": "unknown",
                                        "isHttpSecurityHeadersXFrameOptions": "true",
                                        "isHttpSecurityHeadersXXssProtection": "false", "isDmca": "true"})
        g.on("GET", f"{base}/users", {"value": [{"userIdentifier": "max@contoso.com"}]})
        g.on("GET", f"{base}/ipAddresses", {"value": [{"ipAddress": "10.0.0.1"}, {"ipAddress": "10.0.0.2"}]})
        g.on("GET", f"{base}/devices", {"value": [{"name": "PC-01"}]})
        configure(g)
        res = await cloud_apps.get_cloud_app_discovery(app_id="11627")
        self.assertEqual(res["view"], "app")
        self.assertEqual(res["riskBand"], "medium")
        info = res["appInfo"]
        self.assertEqual(info["general"], {"vendor": "Dropbox", "founded": 2007})          # unknown dropped
        self.assertEqual(info["security"], {"multiFactorAuthentication": True, "supportsSaml": False,
                                            "dataAtRestEncryptionMethod": "notSupported",    # no encryption at rest
                                            "encryptionProtocol": "tls1_2"})
        self.assertEqual(info["certifications"], ["SOC 2", "ISO 27001", "PCI DSS (v3_2_1)"])
        self.assertEqual(info["gdpr"], {"yes": 1, "no": ["ReportDataBreaches"], "unknown": 1})
        self.assertEqual(info["httpSecurityHeaders"], "1 of 2 present")
        self.assertEqual(info["legal"], {"dmca": True})
        self.assertEqual(res["users"]["items"], ["max@contoso.com"])
        self.assertEqual(res["ipAddresses"]["count"], 2)
        self.assertEqual(res["devices"]["items"], ["PC-01"])
        self.assertIn("sanction_cloud_apps(app_ids=['11627']", res["next_steps"])

    async def test_not_found_and_devices_of_log_streams(self):
        g = FakeGraph()
        g.on("GET", STREAMS, {"value": [FW]})
        configure(g)
        with self.assertRaises(NotFoundError):
            await cloud_apps.get_cloud_app_discovery(view="app", app_id="99999")
        base = f"{path(FW['id'])}/10489"
        g.on("GET", base, APPS[1])
        g.on("GET", f"{base}/appInfo", {})
        g.on("GET", f"{base}/users", {"value": []})
        g.on("GET", f"{base}/ipAddresses", {"value": []})
        g.on("GET", f"{base}/devices", GraphError(400, "BadRequest", "not an endpoint stream"))
        res = await cloud_apps.get_cloud_app_discovery(view="app", app_id="10489")
        self.assertNotIn("errors", res)                                     # no device data for log streams
        with self.assertRaises(InputError):
            await cloud_apps.get_cloud_app_discovery(view="app")


class SanctionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.on("GET", STREAMS, {"value": [MDE]})
        self.tags = {"11627": [], "28375": ["Sanctioned"]}
        for aid, name in (("11627", "Dropbox"), ("28375", "Microsoft Teams")):
            self.g.on("GET", f"{path(period='P90D')}/{aid}",
                      lambda _p, _b, aid=aid, name=name: {**app(aid, name, 6), "tags": list(self.tags[aid])})
        self.g.on("GET", f"{path(period='P90D')}/55555", GraphError(404, "NotFound", "no app"))
        self.mdca = FakeGraph()

        def set_sanctioned(aid):
            def handler(_params, body):
                self.tags[aid] = ["Sanctioned"] if body["sanction"] else ["Unsanctioned"]
                return {}
            return handler
        for aid in self.tags:
            self.mdca.on("POST", admin_cloud_apps.ENDPOINT.format(app_id=aid), set_sanctioned(aid))
        configure(self.g, mdca=self.mdca)

    async def test_two_step_unsanction_and_verify(self):
        res = await admin_cloud_apps.sanction_cloud_apps(["11627", "28375"], "Unsanctioned")
        self.assertEqual(res["status"], "confirmation_required")
        rows = {r["id"]: r for r in res["preview"]["apps"]}
        self.assertEqual(rows["11627"]["change"], "untagged -> Unsanctioned")
        self.assertEqual(rows["28375"]["change"], "Sanctioned -> Unsanctioned")
        warnings = " ".join(res["preview"]["warnings"])
        self.assertIn("Undocumented", warnings)
        self.assertIn("Microsoft Teams is a Microsoft service", warnings)
        self.assertIn("block indicators", res["preview"]["effect"])
        self.assertEqual(self.mdca.calls, [])                               # nothing changed by the preview
        done = await admin_cloud_apps.sanction_cloud_apps(["11627", "28375"], "Unsanctioned",
                                                          confirmation_token=res["confirmation_token"])
        self.assertEqual(done["status"], "done")
        self.assertEqual(done["outcome"], "verified")
        self.assertEqual([c.json_body for c in self.mdca.calls], [{"sanction": False}, {"sanction": False}])
        self.assertEqual(self.mdca.calls[0].path, "/cas/api/v1/discovery/discovery_app/11627/set_sanctioned/")
        self.assertEqual(done["results"][1]["before"], ["Sanctioned"])
        self.assertEqual(done["results"][1]["tagsNow"], ["Unsanctioned"])
        with self.assertRaises(ConfirmationError):                          # token bound to the arguments
            await admin_cloud_apps.sanction_cloud_apps(["11627"], "Sanctioned",
                                                       confirmation_token=res["confirmation_token"])

    async def test_no_change_missing_and_invalid(self):
        res = await admin_cloud_apps.sanction_cloud_apps(["28375"], "Sanctioned")
        self.assertEqual(res["status"], "no_change")
        with self.assertRaises(NotFoundError):
            await admin_cloud_apps.sanction_cloud_apps(["11627", "55555"], "Sanctioned")
        for bad in (["Dropbox"], [], [str(i) for i in range(11)]):
            with self.assertRaises(InputError):
                await admin_cloud_apps.sanction_cloud_apps(bad, "Sanctioned")
        self.assertEqual(admin_cloud_apps.app_ids_arg(["11627", "11627", 28375]), ["11627", "28375"])

    async def test_rejected_and_unverified(self):
        self.mdca.on("POST", admin_cloud_apps.ENDPOINT.format(app_id="11627"),
                     GraphError(403, "Forbidden", "not allowed", service="Defender for Cloud Apps API"))
        res = await admin_cloud_apps.sanction_cloud_apps(["11627"], "Sanctioned")
        done = await admin_cloud_apps.sanction_cloud_apps(["11627"], "Sanctioned",
                                                          confirmation_token=res["confirmation_token"])
        self.assertEqual(done["outcome"], "failed")
        self.assertFalse(done["results"][0]["accepted"])
        self.assertEqual(done["results"][0]["state"], "unchanged")          # read back: still untagged
        self.assertIn("403", done["results"][0]["error"])
        self.assertTrue(done["hint"].startswith("No app was changed."))
        self.mdca.on("POST", admin_cloud_apps.ENDPOINT.format(app_id="11627"), {})   # accepted, Graph lags behind
        res = await admin_cloud_apps.sanction_cloud_apps(["11627"], "Sanctioned")
        done = await admin_cloud_apps.sanction_cloud_apps(["11627"], "Sanctioned",
                                                          confirmation_token=res["confirmation_token"])
        self.assertEqual(done["outcome"], "accepted")
        self.assertEqual(done["results"][0]["state"], "pending")
        self.assertIn("lag", done["notes"][0])

    async def test_partial_unknown_and_applied_despite_error(self):
        self.mdca.on("POST", admin_cloud_apps.ENDPOINT.format(app_id="28375"),
                     GraphError(403, "Forbidden", "not allowed", service="Defender for Cloud Apps API"))
        res = await admin_cloud_apps.sanction_cloud_apps(["11627", "28375"], "Unsanctioned")
        done = await admin_cloud_apps.sanction_cloud_apps(["11627", "28375"], "Unsanctioned",
                                                          confirmation_token=res["confirmation_token"])
        self.assertEqual(done["outcome"], "partial")                        # one set, one rejected
        self.assertEqual([r["state"] for r in done["results"]], ["done", "unchanged"])
        self.assertNotIn("No app was changed", done["hint"])

        def timeout_but_applied(_params, _body):                            # 504, but the tag was set
            self.tags["28375"] = ["Unsanctioned"]
            return GraphError(504, "GatewayTimeout", "timeout", service="Defender for Cloud Apps API")
        self.tags["11627"] = []
        self.mdca.on("POST", admin_cloud_apps.ENDPOINT.format(app_id="28375"), timeout_but_applied)
        self.tags["28375"] = ["Sanctioned"]
        res = await admin_cloud_apps.sanction_cloud_apps(["28375"], "Unsanctioned")
        done = await admin_cloud_apps.sanction_cloud_apps(["28375"], "Unsanctioned",
                                                          confirmation_token=res["confirmation_token"])
        self.assertEqual(done["outcome"], "verified")
        self.assertIn("reported an error", done["notes"][0])

        self.tags["28375"] = ["Sanctioned"]
        posted = {"done": False}

        def post_fails(_params, _body):
            posted["done"] = True
            return GraphError(500, "Internal", "boom", service="Defender for Cloud Apps API")

        def detail(_params, _body):                                         # Graph fails only for the read-back
            if posted["done"]:
                return GraphError(503, "Unavailable", "graph down")
            return {**app("28375", "Microsoft Teams", 6), "tags": list(self.tags["28375"])}
        self.mdca.on("POST", admin_cloud_apps.ENDPOINT.format(app_id="28375"), post_fails)
        self.g.on("GET", f"{path(period='P90D')}/28375", detail)
        res = await admin_cloud_apps.sanction_cloud_apps(["28375"], "Unsanctioned")
        done = await admin_cloud_apps.sanction_cloud_apps(["28375"], "Unsanctioned",
                                                          confirmation_token=res["confirmation_token"])
        self.assertEqual(done["outcome"], "failed")
        self.assertEqual(done["results"][0]["state"], "unknown")
        self.assertIn("check the portal", done["notes"][0])
        self.assertIn("verifyError", done)
        self.assertFalse(done["hint"].startswith("No app was changed"))     # not confirmed by a read-back

    async def test_not_configured_and_token_mode(self):
        configure(self.g)                                                   # no MDCA client
        with self.assertRaises(InputError) as ctx:
            await admin_cloud_apps.sanction_cloud_apps(["11627"], "Sanctioned")
        self.assertIn("MDCA_API_URL", str(ctx.exception))
        self.assertEqual(self.g.calls, [])                                  # fails before any lookup
        configure(self.g, mdca=self.mdca, settings=make_settings(mdca_api_url="https://c.eu2.portal.cloudappsecurity.com",
                                                                   mdca_auth="token", mdca_api_token=Secret("t" * 64)))
        res = await admin_cloud_apps.sanction_cloud_apps(["11627"], "Sanctioned")
        self.assertIn("API token", " ".join(res["preview"]["warnings"]))


async def _tok():
    return "tok"


class MdcaClientAndSettingsTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_url_scheme_and_paths(self):
        http = FakeHttp([FakeResponse(200, {}), FakeResponse(403, {"detail": "nope"})])
        settings = make_settings(mdca_api_url="https://contoso.eu2.portal.cloudappsecurity.com")
        c = MdcaClient(settings, _tok, auth_scheme="Token", http=http)
        await c.post("/cas/api/v1/discovery/discovery_app/11627/set_sanctioned/", json_body={"sanction": True})
        req = http.requests[0]
        self.assertEqual(req["url"], "https://contoso.eu2.portal.cloudappsecurity.com/cas/api/v1/discovery/"
                                     "discovery_app/11627/set_sanctioned/")
        self.assertEqual(req["headers"]["Authorization"].split(" ")[0], "Token")
        self.assertEqual(req["json"], {"sanction": True})
        self.assertNotIn("Prefer", req["headers"])
        with self.assertRaises(GraphError) as ctx:
            await c.post("/cas/api/v1/discovery/discovery_app/11627/set_sanctioned/", json_body={"sanction": True})
        self.assertIn("Cloud App Security Administrator", str(ctx.exception))
        with self.assertRaises(InputError):
            await c.get("/api/v1/alerts/")                                  # only /cas/api/...
        bearer = MdcaClient(settings, _tok, http=FakeHttp([FakeResponse(200, {})]))
        self.assertEqual(bearer.auth_scheme, "Bearer")

    def test_settings(self):
        s = Settings.from_env(env(MDCA_API_URL="Contoso.EU2.portal.cloudappsecurity.com/api/"), dotenv=False)
        self.assertEqual(s.mdca_api_url, "https://contoso.eu2.portal.cloudappsecurity.com")
        s = Settings.from_env(env(MDCA_API_URL="https://contoso.eu2.portal.cloudappsecurity.com/cas/api"), dotenv=False)
        self.assertEqual(s.mdca_api_url, "https://contoso.eu2.portal.cloudappsecurity.com")
        self.assertEqual(s.mdca_auth, "obo")
        for bad in (dict(MDCA_API_URL="https://evil.example.com"), dict(MDCA_AUTH="cookie"),
                    dict(MDCA_API_URL="https://c.portal.cloudappsecurity.com", MDCA_AUTH="token")):
            with self.assertRaises(SettingsError):
                Settings.from_env(env(**bad), dotenv=False)
        s = Settings.from_env(env(MDCA_API_URL="https://c.portal.cloudappsecurity.us", MDCA_AUTH="token",
                                  MDCA_API_TOKEN="t" * 64), dotenv=False)
        self.assertEqual(s.describe()["mdca_api_token"], "set")

    def test_runtime_without_client(self):
        configure(FakeGraph())
        with self.assertRaises(InputError):
            runtime.mdca()


if __name__ == "__main__":
    unittest.main()
