"""Runs against the real fastmcp package (CI). Skipped when fastmcp is not installed."""
import unittest

from helpers import DEVICE_ROW, MDE2, FakeGraph, device_responder, make_settings
try:
    import fastmcp  # noqa: F401
    from fastmcp import Client
except ImportError:  # pragma: no cover
    Client = None


def _get(obj, *names):
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


@unittest.skipIf(Client is None, "fastmcp not installed")
class FastMCPIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from defender_mcp import runtime
        from defender_mcp.app import create_server

        self.mcp = create_server(make_settings(log_format="text", log_level="WARNING"))
        self.graph = FakeGraph()
        runtime.get().graph = self.graph

    async def test_tool_list_schema_and_annotations(self):
        from defender_mcp.tools.registry import specs_for

        async with Client(self.mcp) as client:
            tools = await client.list_tools()
        self.assertEqual({t.name for t in tools}, {s.name for s in specs_for("read")})
        find = next(t for t in tools if t.name == "find_defender_devices")
        schema = _get(find, "input_schema", "inputSchema")
        self.assertIn("description", schema["properties"]["name_contains"])
        self.assertIn("sensor_health", schema["properties"])
        self.assertTrue(_get(find.annotations, "read_only_hint", "readOnlyHint"))
        hunt = next(t for t in tools if t.name == "hunt_endpoint_threats")
        self.assertIn("enum", str(_get(hunt, "input_schema", "inputSchema")["properties"]["hunt"]))

    async def test_call_tool_and_error_passthrough(self):
        from fastmcp.exceptions import ToolError

        self.graph.on("GET", "/me", {"displayName": "Analyst", "userPrincipalName": "a@contoso.com", "id": "x"})
        self.graph.on("GET", "/security/incidents", {"value": [{"id": "1", "severity": "high"}]})
        self.graph.on("GET", "/security/secureScores", {"value": [{"currentScore": 10, "maxScore": 20}]})
        self.graph.on("GET", "/security/identities/healthIssues", {"value": []})
        self.graph.hunting(device_responder([DEVICE_ROW, dict(DEVICE_ROW, DeviceId=MDE2)]))
        async with Client(self.mcp) as client:
            result = await client.call_tool("get_security_overview", {})
            data = _get(result, "data") or _get(result, "structured_content", "structuredContent")
            self.assertEqual(data["openIncidents"]["bySeverity"]["high"], 1)
            with self.assertRaises(ToolError) as ctx:
                await client.call_tool("get_defender_device", {"device": "pc-01"})
        self.assertIn("matches 2 devices", str(ctx.exception))  # ToolError text survives mask_error_details


if __name__ == "__main__":
    unittest.main()
