"""AI agent inventory (Defender portal Assets > AI agents, advanced hunting table AgentsInfo)."""
import unittest

from defender_mcp.errors import GraphError
from defender_mcp.tools import agents, hunting
from helpers import FakeGraph, configure

MISSING = GraphError(400, "BadRequest", "Failed to resolve table or column expression named 'AgentsInfo'")
CLOUD = {"AgentId": "a1", "AgentKey": "a1", "AgentName": "HR Helpdesk", "Platform": "Copilot Studio",
         "LifecycleStatus": "Active", "PublishedStatus": "Published", "Instructions": "You are the HR helpdesk."}
LOCAL = {"AgentKey": "l1", "AgentName": "Claude Code", "Platform": "LocalAgents", "LifecycleStatus": "Active",
         "Device": "pc-01", "Account": "max", "AutoApprove": "true", "TrustedProcess": "true"}


class FindAgentsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        self.g.hunting(lambda q: [dict(CLOUD, AgentId="a1")])
        configure(self.g)

    async def test_latest_snapshot_and_robust_columns(self):
        res = await agents.find_ai_agents()
        q = self.g.queries()[-1]
        self.assertTrue(q.startswith("AgentsInfo\n| summarize arg_max(Timestamp, *) by AgentId"))
        self.assertIn('AgentName = tostring(column_ifexists("AgentName", column_ifexists("Name", "")))', q)
        self.assertIn("AgentKey = tostring(AgentId)", q)
        self.assertIn('| where LifecycleStatus !in~ ("Deleted", "Uninstalled")', q)
        self.assertIn("ToolCount = array_length(DeclaredTools)", q)
        self.assertEqual(res["count"], 1)
        self.assertIn("risk level", res["riskNote"])

    async def test_filters(self):
        await agents.find_ai_agents(platform="local", device="PC-01", risky_only=True, include_removed=True)
        q = self.g.queries()[-1]
        self.assertIn('| where Platform == "LocalAgents"', q)
        self.assertIn("| where Device =~ 'PC-01' or Device startswith 'PC-01.'", q)
        self.assertIn('| where AutoApprove =~ "true" or TrustedProcess =~ "false"', q)
        self.assertNotIn("LifecycleStatus !in~", q)
        await agents.find_ai_agents(platform="Copilot Studio", account="max@contoso.com", mcp_server="defender-mcp",
                                    name_contains="help")
        q = self.g.queries()[-1]
        self.assertIn("| where Platform contains 'Copilot Studio'", q)
        self.assertIn("| where Account =~ 'max@contoso.com' or tostring(Owners) contains 'max@contoso.com'", q)
        self.assertIn("tostring(McpServers) contains 'defender-mcp' or tostring(DeclaredTools) contains", q)
        self.assertIn("| where AgentName contains 'help'", q)

    async def test_summary_empty_and_missing_table(self):
        await agents.find_ai_agents(summary_only=True)
        self.assertIn("by Platform, LifecycleStatus", self.g.queries()[-1])
        self.g.hunting(lambda q: [])
        res = await agents.find_ai_agents()
        self.assertIn("security for AI agents", res["hint"])
        self.g.hunting(lambda q: MISSING)
        res = await agents.find_ai_agents()
        self.assertEqual((res["count"], res["hint"]), (0, agents.MISSING_HINT))

    async def test_schema_lists_agents_table(self):
        self.g.hunting(lambda q: [])
        res = await hunting.get_hunting_schema(search="agent")
        self.assertIn("AgentsInfo", [t["table"] for items in res["tables"].values() for t in items])


class GetAgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_details_and_exposure(self):
        g = FakeGraph()

        def responder(q):
            if q.startswith("AgentsInfo"):
                return [dict(CLOUD, LocalMeta=None)]
            if q.startswith("let AgentNode"):
                return [{"AgentNodeId": "node-7", "Direction": "outgoing", "EdgeLabel": "uses",
                         "OtherLabel": "mcp/server", "Count": 2}]
            return []
        g.hunting(responder)
        configure(g)
        res = await agents.get_ai_agent("HR Helpdesk")
        self.assertTrue(res["found"])
        self.assertEqual(res["details"]["AgentId"], "a1")
        self.assertNotIn("AgentKey", res["details"])
        self.assertEqual(res["agentNodeId"], "node-7")
        self.assertIn("explore_exposure_graph(view='blast_radius', source='node-7')", res["next_steps"])
        self.assertIn("instructions", res["note"])
        q = g.queries()[0]
        self.assertIn("| where AgentKey =~ 'HR Helpdesk' or AgentName =~ 'HR Helpdesk' or tostring(EntraAgentId)", q)
        rel_q = g.queries()[-1]
        self.assertIn("| where tostring(NodeProperties.rawData.aiAgentMetadata.id) == 'a1'", rel_q)
        self.assertIn('| where NodeLabel == "ai-agent"', rel_q)

    async def test_ambiguous_missing_and_unknown(self):
        g = FakeGraph()
        g.hunting(lambda q: [LOCAL, dict(LOCAL, AgentKey="l2", Device="pc-02")])
        configure(g)
        res = await agents.get_ai_agent("Claude Code")
        self.assertEqual(res["count"], 2)
        self.assertIn("AgentKey", res["hint"])
        g.hunting(lambda q: [])
        self.assertFalse((await agents.get_ai_agent("ghost"))["found"])
        g.hunting(lambda q: MISSING)
        res = await agents.get_ai_agent("x")
        self.assertEqual((res["found"], res["hint"]), (False, agents.MISSING_HINT))


if __name__ == "__main__":
    unittest.main()
