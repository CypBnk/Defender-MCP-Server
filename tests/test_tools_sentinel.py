"""Microsoft Sentinel MCP tools in the Defender MCP server (ISOC / Sentinel workspace, entity analysis,
exposure graph)."""
import unittest

from defender_mcp import workspaces
from defender_mcp.errors import GraphError, InputError
from defender_mcp.settings import Settings, SettingsError
from defender_mcp.tools import analysis, exposure, hunting, sentinel, users
from helpers import HUNT, FakeGraph, configure, env, make_settings

WS1 = "aaaaaaaa-1111-2222-3333-444444444444"
WS2 = "bbbbbbbb-1111-2222-3333-444444444444"
PRIMARY = "cccccccc-1111-2222-3333-444444444444"
MISSING = GraphError(400, "BadRequest", "Failed to resolve table or column expression named 'X'")


def workspace_graph(responder):
    """FakeGraph whose hunting handler also sees the workspaceId of the request."""
    g = FakeGraph()

    def handler(_params, body):
        result = responder(body["Query"], body.get("workspaceId"))
        if isinstance(result, BaseException):
            return result
        columns = list(result[0].keys()) if result else []
        return {"schema": [{"name": c, "type": "String"} for c in columns], "results": result}
    g.on("POST", HUNT, handler)
    return g


class WorkspaceSettingsTests(unittest.TestCase):
    def test_parse_and_validate(self):
        s = Settings.from_env(env(SENTINEL_WORKSPACES=f"soc-ws={WS1.upper()}; {WS2}"), dotenv=False)
        self.assertEqual(s.sentinel_workspaces, (("soc-ws", WS1), (WS2, WS2)))
        for bad in ("soc-ws=not-a-guid", f"soc-ws={WS1},SOC-WS={WS2}", f"bad_name!={WS1}"):
            with self.assertRaises(SettingsError, msg=bad):
                Settings.from_env(env(SENTINEL_WORKSPACES=bad), dotenv=False)

    def test_resolve(self):
        configure(FakeGraph(), settings=make_settings(sentinel_workspaces=(("soc-ws", WS1),)))
        self.assertIsNone(workspaces.resolve(None))
        self.assertEqual(workspaces.resolve("SOC-WS"), WS1)
        self.assertEqual(workspaces.resolve(WS2.upper()), WS2)
        with self.assertRaises(InputError):
            workspaces.resolve("other")


class HuntingWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_query_schema_and_custom_hunt_target_the_workspace(self):
        g = workspace_graph(lambda q, ws: [{"DataType": "SigninLogs", "Plan": "Analytics", "MB": 12.5}]
                            if q.startswith("Usage") else [{"TenantId": ws or PRIMARY}])
        configure(g, settings=make_settings(sentinel_workspaces=(("soc-ws", WS1),)))
        res = await hunting.run_hunting_query("SigninLogs | take 1", workspace="soc-ws", timespan_days=90)
        body = g.calls[-1].json_body
        self.assertEqual((body["workspaceId"], body["Timespan"]), (WS1, "P90D"))
        self.assertEqual(res["workspaceId"], WS1)
        self.assertIn("primary workspace", res["workspaceNote"])
        await hunting.run_hunting_query("DeviceInfo | take 1")
        self.assertNotIn("workspaceId", g.calls[-1].json_body)   # default: the user's primary workspace
        res = await hunting.get_hunting_schema(search="sign-in failures")
        self.assertIn("SigninLogs", [t["table"] for items in res["tables"].values() for t in items])
        self.assertEqual(res["workspaceTables"][0], {"table": "SigninLogs", "plan": "Analytics", "mb30d": 12.5,
                                                     "lastIngestion": None})
        usage_q = g.queries()[-1]
        self.assertIn("DataType contains 'sign' or DataType contains 'failures'", usage_q)
        await hunting.get_hunting_schema(table="SigninLogs", workspace=WS2)
        self.assertEqual(g.calls[-1].json_body["workspaceId"], WS2)
        await hunting.run_custom_hunt("rdp_logons_from_internet", workspace="soc-ws")
        self.assertEqual(g.calls[-1].json_body["workspaceId"], WS1)

    async def test_schema_without_workspace(self):
        g = workspace_graph(lambda q, ws: MISSING)
        configure(g)
        res = await hunting.get_hunting_schema(search="watchlist")
        self.assertEqual(res["workspaceTables"], [])
        self.assertIn("No Microsoft Sentinel / ISOC workspace answered", res["workspaceNote"])
        self.assertIn("Watchlist", [t["table"] for items in res["tables"].values() for t in items])


class ListWorkspacesTests(unittest.IsolatedAsyncioTestCase):
    async def test_primary_configured_and_fallback(self):
        def responder(q, ws):
            if ws == WS2:   # not accessible: the service silently answers from the primary workspace
                return [{"WorkspaceId": PRIMARY, "TablesWithData": 3}]
            return [{"WorkspaceId": ws or PRIMARY, "TablesWithData": 7, "IngestedMB": 120.5,
                     "LastIngestion": "2026-11-02T12:00:00Z"}]
        configure(workspace_graph(responder),
                  settings=make_settings(sentinel_workspaces=(("isoc-main", PRIMARY), ("old-ws", WS2))))
        res = await sentinel.list_sentinel_workspaces()
        self.assertEqual(res["primary"]["name"], "isoc-main")
        self.assertEqual(res["primary"]["workspaceId"], PRIMARY)
        by_name = {w["name"]: w for w in res["configured"]}
        self.assertTrue(by_name["isoc-main"]["reachable"])
        self.assertFalse(by_name["old-ws"]["reachable"])
        self.assertEqual(by_name["old-ws"]["answeredBy"], PRIMARY)

    async def test_no_workspace(self):
        configure(workspace_graph(lambda q, ws: MISSING))
        res = await sentinel.list_sentinel_workspaces()
        self.assertFalse(res["primary"]["reachable"])
        self.assertIn("No Microsoft Sentinel / ISOC workspace answered", res["primary"]["note"])


class ExposureGraphTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: [{"TargetName": "sql-01", "TargetCriticality": 0, "Hops": 2,
                                   "EdgeLabels": ["Can Authenticate As", "has permissions to"]}])
        configure(self.g)

    def test_selectors(self):
        self.assertEqual(exposure.condition("category:Device+critical", "t"),
                         "(t.Categories has 'device' and set_has_element(t.Categories, 'device')) and "
                         "(isnotnull(t.Criticality) and t.Criticality < 4)")
        self.assertEqual(exposure.condition("pc-01", "s"),
                         "(s.NodeId == 'pc-01' or s.NodeName =~ 'pc-01' or s.NodeName startswith 'pc-01.')")
        self.assertEqual(exposure.condition("label:user"), "NodeLabel =~ 'user'")
        with self.assertRaises(InputError):
            exposure.condition("a+b+c+d")

    async def test_context_and_find(self):
        res = await exposure.find_exposure_nodes()
        self.assertEqual(sorted(k for k in res if k in ("nodeLabels", "edgeLabels", "categories")),
                         ["categories", "edgeLabels", "nodeLabels"])
        await exposure.find_exposure_nodes(search="sql", critical_only=True, internet_facing_only=True)
        q = self.g.queries()[-1]
        self.assertIn("(NodeName contains 'sql' or NodeId == 'sql') and (isnotnull(Criticality) and Criticality < 4) "
                      "and InternetFacing == true", q)
        await exposure.find_exposure_nodes(category="identity")
        self.assertIn("(Categories has 'identity' and set_has_element(Categories, 'identity'))", self.g.queries()[-1])
        self.assertIn("Criticality = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)", q)

    async def test_views(self):
        res = await exposure.explore_exposure_graph("blast_radius", source="pc-01")
        q = self.g.queries()[-1]
        self.assertIn("| make-graph SourceNodeId --> TargetNodeId with Nodes on NodeId", q)
        self.assertIn("| graph-match cycles=none (s)-[e*1..3]->(t)", q)
        self.assertIn("where (s.NodeId == 'pc-01' or s.NodeName =~ 'pc-01' or s.NodeName startswith 'pc-01.') and "
                      "(isnotnull(t.Criticality) and t.Criticality < 4)", q)
        self.assertIn("EdgeLabels = map(e, EdgeLabel), Via = map(e, TargetNodeName)", q)
        self.assertIn("arg_min(Hops, EdgeLabels, Via) by TargetId", q)
        self.assertEqual((res["view"], res["targets"], res["count"]), ("blast_radius", "critical", 1))
        await exposure.explore_exposure_graph("perimeter", target="sql-01", source="internet", max_hops=4,
                                              edge_labels="Can Authenticate As, CanRemoteInteractiveLogonTo")
        q = self.g.queries()[-1]
        self.assertIn("| where EdgeLabel in~ ('Can Authenticate As', 'CanRemoteInteractiveLogonTo')", q)
        self.assertIn("(s)-[e*1..4]->(t)", q)
        self.assertIn("(t.NodeId == 'sql-01' or t.NodeName =~ 'sql-01' or t.NodeName startswith 'sql-01.') and "
                      "s.InternetFacing == true", q)
        self.assertIn("order by SourceInternetFacing desc, SourceRCE desc, Hops asc", q)
        await exposure.explore_exposure_graph("neighbors", source="pc-01")
        self.assertTrue(any("where SourceNodeId in (N)" in q for q in self.g.queries()))
        for bad in ({"view": "paths", "source": "a"}, {"view": "blast_radius"}, {"view": "perimeter"},
                    {"view": "neighbors", "source": "critical"}, {"view": "paths", "source": "a", "target": "b",
                                                                   "max_hops": 5},
                    {"view": "paths", "source": "a", "target": "b", "edge_labels": ",".join("x" * 11)}):
            with self.assertRaises(InputError, msg=str(bad)):
                await exposure.explore_exposure_graph(**bad)


class AnalyzeIndicatorTests(unittest.IsolatedAsyncioTestCase):
    def _configure(self, responder, reputation=None):
        g = workspace_graph(responder)
        if reputation is not None:   # an exception means: host unknown to Microsoft Threat Intelligence
            host = reputation if isinstance(reputation, BaseException) else {"id": "evil.example"}
            g.on("GET", "/security/threatIntelligence/hosts/evil.example", host)
            g.on("GET", "/security/threatIntelligence/hosts/evil.example/reputation", reputation)
        configure(g)
        return g

    async def test_malicious_url_with_own_ti_and_watchlist(self):
        def responder(q, ws):
            if q.startswith("ThreatIntelIndicators"):
                return [{"Id": "i1", "ObservableKey": "url:value", "ObservableValue": "https://evil.example/login",
                         "Active": True, "Confidence": 80, "SourceSystem": "MISP"}]
            if q.startswith("Watchlist"):
                return [{"WatchlistAlias": "blocked_domains", "SearchKey": "evil.example"}]
            if "summarize Hits = count(), DistinctEntities" in q:
                return [{"Source": "UrlClickEvents", "Hits": 3}]
            return []
        g = self._configure(responder, {"classification": "malicious", "score": 100})
        res = await analysis.analyze_indicator("https://evil.example/login")
        a = res["assessment"]
        self.assertEqual((a["level"], a["verdict"]), ("high", "malicious"))
        self.assertTrue(any("Microsoft Threat Intelligence: malicious" in r for r in a["reasons"]))
        self.assertTrue(any("Active indicator in your threat intelligence: MISP" in r for r in a["reasons"]))
        self.assertIn("On watchlist 'blocked_domains'.", a["context"])
        self.assertEqual(a["exposure"]["bySource"], {"UrlClickEvents": 3})
        ti_q = next(q for q in g.queries() if q.startswith("ThreatIntelIndicators"))
        self.assertIn("(ObservableValue =~ 'https://evil.example/login' or (ObservableKey == 'domain-name:value' and "
                      "ObservableValue =~ 'evil.example'))", ti_q)
        self.assertIn("| summarize arg_max(TimeGenerated, *) by Id", ti_q)
        wl_q = next(q for q in g.queries() if q.startswith("Watchlist"))
        self.assertIn('_DTItemStatus !startswith "Delete"', wl_q)
        self.assertIn("| where _DTItemType == 'watchlist-item'\n| summarize arg_max(_DTTimestamp, *) by _DTItemId", wl_q)

    async def test_hash_without_workspace_tables(self):
        def responder(q, ws):
            if q.startswith(("ThreatIntelIndicators", "Watchlist")):
                return MISSING
            if "invoke FileProfile" in q:
                return [{"SHA1": "a" * 40, "ThreatName": "Trojan:Win32/Test", "GlobalPrevalence": 2}]
            return []
        g = self._configure(responder)
        res = await analysis.analyze_indicator("b" * 64)
        self.assertEqual(res["assessment"]["level"], "high")
        self.assertEqual(res["notAvailable"], ["ownThreatIntel", "watchlists"])
        self.assertNotIn("errors", res)
        self.assertNotIn("microsoftThreatIntel", res)   # host reputation only for IPs, domains, URLs
        self.assertFalse(any(c.path.startswith("/security/threatIntelligence") for c in g.calls))

    async def test_ip_matches_cidr_indicators(self):
        g = self._configure(lambda q, ws: [])
        await analysis.analyze_indicator("203.0.113.7")
        ti_q = next(q for q in g.queries() if q.startswith("ThreatIntelIndicators"))
        self.assertIn("(ObservableValue == '203.0.113.7' or (ObservableValue contains \"/\" and "
                      "ipv4_is_in_range('203.0.113.7', ObservableValue)))", ti_q)

    async def test_unknown_domain(self):
        self._configure(lambda q, ws: [], reputation=GraphError(404, "NotFound", "not found"))
        res = await analysis.analyze_indicator("evil.example")
        self.assertEqual((res["assessment"]["level"], res["assessment"]["verdict"]), ("none", "no known threat"))
        self.assertEqual(res["microsoftThreatIntel"], {"host": "evil.example", "known": False})


class InvestigateUserUebaTests(unittest.IsolatedAsyncioTestCase):
    USER = {"id": "11111111-2222-3333-4444-555555555555", "userPrincipalName": "alice@contoso.com",
            "mail": "alice@contoso.com", "accountEnabled": True}

    def _configure(self, responder, risk):
        g = workspace_graph(responder)
        g.on("GET", "/users", {"value": [self.USER]})
        g.on("GET", f"/users/{self.USER['userPrincipalName']}", self.USER)
        g.on("GET", f"/identityProtection/riskyUsers/{self.USER['id']}", risk)
        configure(g)
        return g

    async def test_ueba_raises_assessment(self):
        def responder(q, ws):
            if q.startswith("BehaviorAnalytics"):
                return [{"Activities": 12, "MaxPriority": 8, "HighPriority": 2}]
            if q.startswith("Anomalies"):
                return [{"Anomalies": 1, "Templates": ["UEBA Anomalous Sign-in"]}]
            if q.startswith("AADUserRiskEvents"):
                return MISSING
            return []
        g = self._configure(responder, {"riskLevel": "none", "riskState": "none"})
        res = await users.investigate_user("alice@contoso.com")
        a = res["assessment"]
        self.assertEqual(a["level"], "high")
        self.assertIn("UEBA investigation priority 8/10.", a["reasons"])
        self.assertIn("1 UEBA anomaly(ies): UEBA Anomalous Sign-in.", a["reasons"])
        self.assertEqual(res["ueba"]["MaxPriority"], 8)
        self.assertIn("riskDetections", res["notAvailable"])
        self.assertTrue(any("InvestigationPriority >= 3" in q for q in g.queries()))

    async def test_no_signals(self):
        self._configure(lambda q, ws: [], {"riskLevel": "none", "riskState": "none"})
        res = await users.investigate_user("alice@contoso.com")
        self.assertEqual((res["assessment"]["level"], res["assessment"]["verdict"]),
                         ("none", "no risk signals in the available data"))
        self.assertNotIn("ueba", res)   # empty workspace summaries are left out

    async def test_confirmed_compromised(self):
        self._configure(lambda q, ws: [], {"riskLevel": "high", "riskState": "confirmedCompromised"})
        res = await users.investigate_user("alice@contoso.com")
        self.assertEqual(res["assessment"]["level"], "high")
        self.assertIn("Entra ID Protection: confirmed compromised.", res["assessment"]["reasons"])


if __name__ == "__main__":
    unittest.main()
