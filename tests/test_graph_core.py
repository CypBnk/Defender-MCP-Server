import asyncio
import unittest

from defender_mcp.auth.obo import OboTokenProvider
from defender_mcp.confirm import Confirmer
from defender_mcp.errors import AuthError, ConfirmationError, GraphError, InputError
from defender_mcp.graph.client import GraphClient, MdeClient, template_path, validate_path
from defender_mcp.graph.paging import encode_cursor, get_paged, paginate_list, read_list_cursor
from defender_mcp.shaping import compact, evidence_item, summarize_entities
from helpers import MDE1, FakeGraph, FakeHttp, FakeResponse, TimeoutException, TransportError, configure, jwt, make_settings

INC = "/security/incidents/29"


async def _token():
    return "graph-token"


class PathGuardTests(unittest.TestCase):
    def test_rejects_injection(self):
        for bad in (f"{INC}/comments?x=/y", "/a/../b", "/a/%2e%2e/b", "/a/%2Fb", "/a b", "/a#b", "/a\\b",
                    "//graph.microsoft.com/x", "relative"):
            with self.assertRaises(InputError, msg=bad):
                validate_path(bad)

    def test_accepts_api_paths(self):
        for ok in ("/security/alerts_v2/da637551227677560813_-961444813", "/security/runHuntingQuery",
                   "/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/abc/"
                   "microsoft.graph.security.aggregatedAppsDetails(period=duration'P30D')",
                   f"/api/machines/{MDE1}/isolate"):
            self.assertEqual(validate_path(ok), ok)

    def test_template_path_hides_ids(self):
        self.assertEqual(template_path(f"/api/machines/{MDE1}/isolate"), "/api/machines/{id}/isolate")
        self.assertEqual(template_path("/users/a@b.com"), "/users/{upn}")


class GraphClientTests(unittest.IsolatedAsyncioTestCase):
    def client(self, responses, cls=GraphClient, **settings):
        self.sleeps = []

        async def sleep(seconds):
            self.sleeps.append(seconds)
        self.http = FakeHttp(responses)
        return cls(make_settings(**settings), _token, http=self.http, sleep=sleep)

    async def test_retry_after_on_429(self):
        g = self.client([FakeResponse(429, {"error": {"code": "TooMany"}}, {"Retry-After": "2"}),
                         FakeResponse(200, {"value": [1]})])
        self.assertEqual(await g.get("/security/incidents"), {"value": [1]})
        self.assertEqual(self.sleeps, [2.0])
        self.assertEqual(self.http.requests[0]["headers"]["Authorization"], "Bearer graph-token")
        self.assertNotIn("ConsistencyLevel", self.http.requests[0]["headers"])
        self.assertEqual(self.http.requests[0]["headers"]["Prefer"], "include-unknown-enum-members")

    async def test_action_not_retried_on_503(self):
        g = self.client([FakeResponse(503, {"error": {"code": "ServiceUnavailable", "message": "busy"}})])
        with self.assertRaises(GraphError) as ctx:
            await g.post(f"{INC}/comments", json_body={"comment": "x"})
        self.assertEqual(ctx.exception.status, 503)
        self.assertEqual(len(self.http.requests), 1)

    async def test_hunting_post_is_retried_and_uses_timeout_and_utf8(self):
        g = self.client([FakeResponse(503, {"error": {"code": "x"}}), FakeResponse(200, {"results": []})])
        await g.post("/security/runHuntingQuery", json_body={"Query": "T | take 1"}, idempotent=True, timeout=90)
        self.assertEqual(len(self.http.requests), 2)
        self.assertEqual(self.http.requests[0]["timeout"], 90)
        self.assertIn("charset=utf-8", self.http.requests[0]["headers"]["Content-Type"])

    async def test_hunting_timeout_not_retried_and_waits_capped(self):
        g = self.client([TimeoutException("slow"), FakeResponse(200, {"results": []})])
        with self.assertRaises(GraphError) as ctx:
            await g.post("/security/runHuntingQuery", json_body={"Query": "T"}, idempotent=True, timeout=90)
        self.assertEqual(len(self.http.requests), 1)
        self.assertIn("narrow the time window", str(ctx.exception))
        g = self.client([FakeResponse(429, {"error": {"code": "TooMany"}}, {"Retry-After": "60"}),
                         FakeResponse(429, {"error": {"code": "TooMany"}}, {"Retry-After": "60"})])
        with self.assertRaises(GraphError) as ctx:
            await g.post("/security/runHuntingQuery", json_body={"Query": "T"}, idempotent=True, timeout=90)
        self.assertEqual(ctx.exception.status, 429)
        self.assertEqual(self.sleeps, [5.0])  # one retry, wait capped
        g = self.client([FakeResponse(504, {"error": {"code": "GatewayTimeout"}}), FakeResponse(200, {"results": []})])
        with self.assertRaises(GraphError):
            await g.post("/security/runHuntingQuery", json_body={"Query": "T"}, idempotent=True, timeout=90)
        self.assertEqual(len(self.http.requests), 1)

    async def test_get_retried_on_transport_error(self):
        g = self.client([TransportError("reset"), FakeResponse(200, {"ok": True})])
        self.assertEqual(await g.get("/security/secureScores"), {"ok": True})
        self.assertEqual(len(self.sleeps), 1)

    async def test_timeout_message(self):
        g = self.client([TimeoutException("slow")], graph_max_retries=0)
        with self.assertRaises(GraphError) as ctx:
            await g.get("/security/incidents")
        self.assertIn("timed out", str(ctx.exception))

    async def test_error_mapping(self):
        body = {"error": {"code": "Forbidden", "message": "Insufficient privileges - Operation ID: 1",
                          "innerError": {"request-id": "rid-1"}}}
        g = self.client([FakeResponse(403, body)])
        with self.assertRaises(GraphError) as ctx:
            await g.get("/security/incidents")
        text = str(ctx.exception)
        self.assertIn("Insufficient privileges", text)
        self.assertIn("rid-1", text)
        self.assertIn("Security Reader", text)
        self.assertTrue(text.startswith("Graph 403"))

    async def test_bad_version(self):
        g = self.client([])
        with self.assertRaises(InputError):
            await g.get("/security/incidents", version="v2")

    async def test_mde_client_url_and_errors(self):
        g = self.client([FakeResponse(201, {"id": "a1", "status": "Pending"}),
                         FakeResponse(400, {"error": {"code": "ActiveRequestAlreadyExists", "message": "pending"}})],
                        cls=MdeClient, mde_api_host="eu.api.security.microsoft.com")
        res = await g.post(f"/api/machines/{MDE1}/isolate", json_body={"Comment": "x"})
        self.assertEqual(res["status"], "Pending")
        self.assertEqual(self.http.requests[0]["url"], f"https://eu.api.security.microsoft.com/api/machines/{MDE1}/isolate")
        self.assertNotIn("Prefer", self.http.requests[0]["headers"])
        with self.assertRaises(GraphError) as ctx:
            await g.post(f"/api/machines/{MDE1}/isolate", json_body={"Comment": "x"})
        self.assertTrue(str(ctx.exception).startswith("Defender API 400 ActiveRequestAlreadyExists"))
        self.assertIn("already pending", str(ctx.exception))
        with self.assertRaises(InputError):
            await g.get("/security/incidents")  # only /api/... on the Defender API


class OboTests(unittest.IsolatedAsyncioTestCase):
    def provider(self, responses, now=1000.0, scope=None):
        self.now = now
        self.http = FakeHttp(responses)
        return OboTokenProvider(make_settings(), scope=scope, assertion_source=lambda: "user-token", http=self.http,
                                clock=lambda: self.now)

    async def test_cache_and_single_exchange_under_concurrency(self):
        token = jwt({"scp": "User.Read", "oid": "x"})
        p = self.provider([FakeResponse(200, {"access_token": token, "expires_in": 3600})])
        results = await asyncio.gather(*(p() for _ in range(5)))
        self.assertTrue(all(r == token for r in results))
        self.assertEqual(len(self.http.requests), 1)
        data = self.http.requests[0]["data"]
        self.assertEqual(data["requested_token_use"], "on_behalf_of")
        self.assertEqual(data["scope"], "https://graph.microsoft.com/.default")

    async def test_mde_scope(self):
        token = jwt({"scp": "Machine.Isolate", "oid": "x"})
        p = self.provider([FakeResponse(200, {"access_token": token, "expires_in": 3600})],
                          scope="https://api.securitycenter.microsoft.com/.default")
        await p()
        self.assertEqual(self.http.requests[0]["data"]["scope"], "https://api.securitycenter.microsoft.com/.default")

    async def test_refresh_before_expiry(self):
        t1, t2 = jwt({"scp": "a", "n": 1}), jwt({"scp": "a", "n": 2})
        p = self.provider([FakeResponse(200, {"access_token": t1, "expires_in": 600}),
                           FakeResponse(200, {"access_token": t2, "expires_in": 600})])
        self.assertEqual(await p(), t1)
        self.now += 400  # inside the 300 s refresh margin
        self.assertEqual(await p(), t2)

    async def test_rejects_app_only_token(self):
        p = self.provider([FakeResponse(200, {"access_token": jwt({"roles": ["X.Read.All"]}), "expires_in": 3600})])
        with self.assertRaises(AuthError) as ctx:
            await p()
        self.assertIn("app-only", str(ctx.exception))

    async def test_consent_and_missing_service_principal_are_explained(self):
        p = self.provider([FakeResponse(400, {"error": "invalid_grant", "error_codes": [65001],
                                              "error_description": "AADSTS65001: not consented"})])
        with self.assertRaises(AuthError) as ctx:
            await p()
        self.assertIn("Admin consent", str(ctx.exception))
        p = self.provider([FakeResponse(400, {"error": "invalid_request", "error_codes": [650052],
                                              "error_description": "AADSTS650052: lacks a service principal"})])
        with self.assertRaises(AuthError) as ctx:
            await p()
        self.assertIn("WindowsDefenderATP", str(ctx.exception))


class PagingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.graph = FakeGraph()
        configure(self.graph)

    async def test_resume_inside_page_and_across_next_link(self):
        page2 = "https://graph.microsoft.com/v1.0/things?$skiptoken=abc"
        self.graph.on("GET", "/things", lambda p, b: (
            {"value": [{"id": i} for i in range(3, 5)]} if p.get("$skiptoken") == "abc"
            else {"value": [{"id": i} for i in range(0, 3)], "@odata.nextLink": page2}))
        seen, cursor = [], None
        while True:
            res = await get_paged("/things", tool="t", max_items=2, cursor=cursor)
            seen += [i["id"] for i in res["items"]]
            cursor = res["cursor"]
            if not cursor:
                break
        self.assertEqual(seen, [0, 1, 2, 3, 4])

    async def test_top_cap(self):
        self.graph.on("GET", "/security/incidents", {"value": []})
        await get_paged("/security/incidents", tool="t", max_items=300, use_top=True, top_cap=50, version="v1.0")
        self.assertEqual(self.graph.calls[-1].params["$top"], "50")

    async def test_cursor_is_signed_and_bound_to_tool(self):
        self.graph.on("GET", "/things", {"value": [{"id": i} for i in range(5)]})
        res = await get_paged("/things", tool="t", max_items=1)
        with self.assertRaises(InputError):
            await get_paged("", tool="other", cursor=res["cursor"])
        raw, sig = res["cursor"].split(".")
        with self.assertRaises(InputError):
            await get_paged("", tool="t", cursor=raw[:-2] + "AA." + sig)
        self.assertTrue(encode_cursor({"k": "g", "t": "t", "p": "/users", "q": {}, "v": "v1.0", "o": 0}))

    async def test_response_budget(self):
        configure(self.graph, make_settings(max_response_bytes=10_000))
        self.graph.on("GET", "/big", {"value": [{"id": i, "blob": "x" * 3000} for i in range(10)]})
        res = await get_paged("/big", tool="t", max_items=50)
        self.assertLess(res["count"], 10)
        self.assertTrue(res["truncated"])

    async def test_next_link_host_checked(self):
        self.graph.on("GET", "/things", {"value": [], "@odata.nextLink": "https://evil.example.com/v1.0/x"})
        with self.assertRaises(InputError):
            await get_paged("/things", tool="t")

    async def test_list_cursor_roundtrip(self):
        res = paginate_list([{"n": i} for i in range(7)], tool="lt", args={"q": "a"}, max_items=3)
        self.assertEqual(read_list_cursor(res["cursor"], "lt"), ({"q": "a"}, 3))
        self.assertEqual(res["total"], 7)


class ConfirmerTests(unittest.TestCase):
    def test_flow(self):
        now = [1000.0]
        c = Confirmer(b"k" * 32, 300, lambda: now[0])
        token = c.issue("device.isolate", MDE1, {"Comment": "x"}, "user-1")
        c.verify(token, "device.isolate", MDE1, {"Comment": "x"}, "user-1")
        for args in (("device.isolate", MDE1, {"Comment": "y"}, "user-1"),
                     ("device.release_isolation", MDE1, {"Comment": "x"}, "user-1"),
                     ("device.isolate", MDE1, {"Comment": "x"}, "user-2")):
            with self.assertRaises(ConfirmationError):
                c.verify(token, *args)
        now[0] += 301
        with self.assertRaises(ConfirmationError):
            c.verify(token, "device.isolate", MDE1, {"Comment": "x"}, "user-1")
        with self.assertRaises(ConfirmationError):
            c.verify("garbage", "device.isolate", MDE1, {}, "user-1")


class ShapingTests(unittest.TestCase):
    def test_compact(self):
        out = compact({"@odata.context": "x", "@odata.type": "#microsoft.graph.security.incident", "a": None,
                       "b": [], "c": {"d": ""}, "e": "v", "f@odata.navigationLink": "x"})
        self.assertEqual(out, {"odataType": "incident", "e": "v"})

    def test_evidence_and_entities(self):
        evidence = [
            {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "pc-01", "mdeDeviceId": MDE1,
             "verdict": "suspicious", "detailedRoles": ["PrimaryDevice"], "riskScore": "high"},
            {"@odata.type": "#microsoft.graph.security.processEvidence", "processCommandLine": "powershell -enc AAAA",
             "imageFile": {"fileName": "powershell.exe", "sha1": "eb42"}, "userAccount": {"accountName": "max"}},
            {"@odata.type": "#microsoft.graph.security.userEvidence",
             "userAccount": {"accountName": "max", "domainName": "CONTOSO"}},
            {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "203.0.113.5"},
            {"@odata.type": "#microsoft.graph.security.kubernetesPodEvidence", "name": "pod-1", "tags": []},
        ]
        items = [evidence_item(e) for e in evidence]
        self.assertEqual(items[0]["type"], "device")
        self.assertEqual(items[0]["roles"], ["PrimaryDevice"])
        self.assertEqual(items[1]["image"]["fileName"], "powershell.exe")
        self.assertEqual(items[4]["type"], "kubernetesPod")
        entities = summarize_entities(evidence)
        self.assertEqual(entities["devices"], ["pc-01"])
        self.assertEqual(entities["users"], ["CONTOSO\\max"])
        self.assertEqual(entities["ips"], ["203.0.113.5"])
        self.assertEqual(entities["files"], [{"name": "powershell.exe", "sha1": "eb42"}])


if __name__ == "__main__":
    unittest.main()
