"""AI agent inventory: the agents shown in the Defender portal under Assets > AI agents.

Source is the advanced hunting table AgentsInfo (successor of AIAgentsInfo, which was retired on 1 July 2026): cloud
agents (Copilot Studio, Microsoft Foundry, Microsoft 365, AWS Bedrock, GCP Vertex AI ...) and local AI agents that
Defender for Endpoint discovered on devices (Platform 'LocalAgents'). The table keeps snapshots, so every query takes
the latest record per AgentId. The portal's risk level and risk indicators are not part of the table; the tools
report the documented configuration signals instead (local agents: auto-approve, untrusted host process)."""
from __future__ import annotations

from typing import Annotated, Optional

from .. import kql
from ..errors import DefenderToolError, InputError
from ..scopes import THREAT_HUNTING_READ
from ..shaping import UNTRUSTED_NOTE
from ..util import gather_sections
from .analysis import unavailable
from .common import MaxItems
from .registry import read_tool

# Learn documents the display name both as AgentName (table reference) and as Name (local-agent queries), and
# AgentId both as string and as guid: read whichever name exists and compare AgentId as text.
_LATEST = "\n".join([
    "AgentsInfo",
    "| summarize arg_max(Timestamp, *) by AgentId",
    '| extend AgentName = tostring(column_ifexists("AgentName", column_ifexists("Name", ""))), '
    "AgentKey = tostring(AgentId), LocalMeta = RawAgentInfo.localAgentMetadata",
    # columns documented only in the table reference: tolerate their absence instead of failing the query
    '| extend Owners = column_ifexists("Owners", dynamic(null)), SharedWith = column_ifexists("SharedWith", dynamic(null)), '
    'EntraAgentId = tostring(column_ifexists("EntraAgentId", "")), SourceAgentId = tostring(column_ifexists("SourceAgentId", "")), '
    'Availability = tostring(column_ifexists("Availability", "")), Model = tostring(column_ifexists("Model", "")), '
    'DeclaredDataSources = column_ifexists("DeclaredDataSources", dynamic(null)), '
    'ConnectedAgents = column_ifexists("ConnectedAgents", dynamic(null)), '
    'CreatedDateTime = column_ifexists("CreatedDateTime", datetime(null))',
    "| extend Vendor = tostring(LocalMeta.vendor), Process = tostring(LocalMeta.relatedProcess), "
    "Device = tostring(LocalMeta.deviceName), Account = tostring(LocalMeta.accountName), "
    "AutoApprove = tostring(LocalMeta.autoApprove), TrustedProcess = tostring(LocalMeta.trustedProcess)",
])
_ACTIVE = '| where LifecycleStatus !in~ ("Deleted", "Uninstalled")'
_RISKY = '| where AutoApprove =~ "true" or TrustedProcess =~ "false"'
# trustedProcess / autoApprove are documented as the strings "true" / "false", not booleans
_HINTS = ('| extend ConfigurationRisk = case(AutoApprove =~ "true" and TrustedProcess =~ "false", '
          '"acts without approval in an untrusted host process", AutoApprove =~ "true", "acts without approval", '
          'TrustedProcess =~ "false", "untrusted host process", "")')
EMPTY_HINT = ("No AI agents in the inventory. Cloud agents need 'security for AI agents' (Microsoft 365 connector / "
              "Microsoft Agent 365) in the Defender portal; local agents need Defender for Endpoint Plan 2 with "
              "Defender Antivirus in active mode and appear once Defender has observed agent activity.")
MISSING_HINT = ("The AgentsInfo table is not available: security for AI agents is not enabled in this tenant, or you "
                "cannot read it.")
RISK_NOTE = ("The portal's risk level and risk indicators (Microsoft 365 E7 / Agent 365) are not in advanced hunting; "
             "ConfigurationRisk shows the documented local-agent signals (auto-approve, untrusted host process).")


def _lit(value: Optional[str], name: str, max_len: int = 200) -> str:
    return kql.kql_str(value, name, max_len)


def _filters(name_contains, platform, device, account, mcp_server, risky_only) -> list[str]:
    out = []
    if name_contains:
        out.append(f"| where AgentName contains {_lit(name_contains, 'name_contains')}")
    if platform:
        p = str(platform).strip()
        out.append('| where Platform == "LocalAgents"' if p.lower() in ("local", "localagents", "endpoint", "endpoints")
                   else f"| where Platform contains {_lit(p, 'platform', 100)}")
    if device:
        name = kql.device_name(device)
        out.append(f"| where Device =~ {kql.kql_str(name)} or Device startswith {kql.kql_str(name + '.')}")
    if account:
        a = _lit(account, "account")
        out.append(f"| where Account =~ {a} or tostring(Owners) contains {a} or tostring(SharedWith) contains {a}")
    if mcp_server:
        m = _lit(mcp_server, "mcp_server", 300)
        out.append(f"| where tostring(McpServers) contains {m} or tostring(DeclaredTools) contains {m} or "
                   f"tostring(LocalMeta.localMcps) contains {m}")
    if risky_only:
        out.append(_RISKY)
    return out


@read_tool(scopes=(THREAT_HUNTING_READ,), title="AI agents (inventory)")
async def find_ai_agents(
    name_contains: Annotated[Optional[str], "Part of the agent name."] = None,
    platform: Annotated[Optional[str], "Part of the platform name, e.g. 'Copilot Studio', 'Foundry', 'Bedrock'; "
                                       "'local' = local AI agents discovered on devices."] = None,
    device: Annotated[Optional[str], "Local agents on this device (name or FQDN)."] = None,
    account: Annotated[Optional[str], "Local agents running under this account, or cloud agents owned by or shared "
                                      "with this user (UPN or name)."] = None,
    mcp_server: Annotated[Optional[str], "Only agents using an MCP server or tool whose name or URL contains this "
                                         "text."] = None,
    risky_only: Annotated[bool, "Only local agents that act without approval or run in an untrusted host process."] = False,
    include_removed: Annotated[bool, "Also agents that are deleted or uninstalled."] = False,
    summary_only: Annotated[bool, "Counts per platform and status instead of the list."] = False,
    max_items: MaxItems = 50,
) -> dict:
    """AI agent inventory of Microsoft Defender (portal: Assets > AI agents): agents built with Copilot Studio,
    Microsoft Foundry, Microsoft 365 and other platforms (e.g. AWS Bedrock, GCP Vertex AI), and local AI agents
    that Defender for Endpoint discovered on devices (e.g. coding assistants). Per agent: platform, version, publish
    and lifecycle status, availability, model, owners, number of tools, MCP servers, data sources and connected
    agents, Entra agent ID; for local agents vendor, host process, device, account and configuration risk
    (auto-approve, untrusted host process). Use get_ai_agent for one agent's full configuration and attack surface."""
    filters = _filters(name_contains, platform, device, account, mcp_server, risky_only)
    base = [_LATEST, *([] if include_removed else [_ACTIVE]), *filters, _HINTS]
    if summary_only:
        query = "\n".join(base + [
            '| summarize Agents = count(), Published = countif(PublishedStatus =~ "Published"), '
            "WithMcpServers = countif(array_length(McpServers) > 0), "
            "WithConfigurationRisk = countif(isnotempty(ConfigurationRisk)), "
            "Devices = dcountif(Device, isnotempty(Device)) by Platform, LifecycleStatus",
            "| order by Agents desc"])
    else:
        query = "\n".join(base + [
            "| project AgentId = AgentKey, AgentName, Platform, Version, PublishedStatus, LifecycleStatus, "
            "Availability, Model, Owners, ToolCount = array_length(DeclaredTools), "
            "McpServerCount = array_length(McpServers), DataSourceCount = array_length(DeclaredDataSources), "
            "ConnectedAgentCount = array_length(ConnectedAgents), EntraAgentId, Vendor, Process, Device, Account, "
            "AutoApprove, TrustedProcess, ConfigurationRisk, CreatedDateTime, LastUpdatedDateTime",
            "| order by Platform asc, AgentName asc, Device asc"])
    ok, errors = await gather_sections({"agents": kql.hunt(query, max_items=max_items, max_str=300)})
    if "agents" not in ok:
        real, missing = unavailable(errors)
        if missing:
            return {"count": 0, "items": [], "hint": MISSING_HINT}
        raise DefenderToolError(next(iter(real.values())))
    result = ok["agents"]
    if not result.get("count") and not filters:
        result["hint"] = EMPTY_HINT
    result["riskNote"] = RISK_NOTE
    return result


@read_tool(scopes=(THREAT_HUNTING_READ,), title="AI agent details")
async def get_ai_agent(
    agent: Annotated[str, "AgentId, agent name, Entra agent ID or platform agent ID (from find_ai_agents)."],
) -> dict:
    """Full configuration of one AI agent from the Defender AI agent inventory: description, instructions (system
    prompt), model, owners and sharing, channels, authentication and permissions, declared tools, MCP servers, data
    sources, connected agents, triggers, guardrails and endpoints; for local agents vendor, host process,
    auto-approve, device, account and local MCP servers. Also the agent's relations in the exposure graph (runs on
    device, uses MCP server, used by user, can authenticate as) - the starting point for
    explore_exposure_graph(view='blast_radius', source=<agentNodeId>)."""
    value = str(agent or "").strip()
    if not value:
        raise InputError("agent must not be empty.")
    lit = _lit(value, "agent", 300)
    query = "\n".join([
        _LATEST,
        f"| where AgentKey =~ {lit} or AgentName =~ {lit} or tostring(EntraAgentId) =~ {lit} or "
        f"tostring(SourceAgentId) =~ {lit}",
        _HINTS, "| order by LifecycleStatus asc, LastUpdatedDateTime desc", "| take 11"])
    try:
        rows = await kql.rows(query)
    except DefenderToolError as exc:
        if unavailable({"agent": str(exc)})[1]:
            return {"agent": value, "found": False, "hint": MISSING_HINT}
        raise
    if not rows:
        return {"agent": value, "found": False, "hint": "No agent with this ID or name; use find_ai_agents."}
    if len(rows) > 1:
        keys = ("AgentKey", "AgentName", "Platform", "LifecycleStatus", "Device", "Account", "Version")
        matches = kql.shape_rows([{k: r.get(k) for k in keys} for r in rows], limit=10, max_str=200)[0]
        return {"agent": value, "found": True, "matches": matches, "count": len(matches),
                "hint": "Several agents match (a local agent has one entry per device and account): call "
                        "get_ai_agent with the AgentKey."}
    row = rows[0]
    agent_id = str(row.get("AgentKey") or row.get("AgentId") or "")
    details = {k: v for k, v in row.items() if k not in ("LocalMeta", "AgentKey")}
    details["AgentId"] = agent_id
    out: dict = {"agent": value, "found": True, "details": kql.shape_rows([details], limit=1, max_str=2000)[0][0]}
    relations = "\n".join([
        "let AgentNode = ExposureGraphNodes",
        '| where NodeLabel == "ai-agent"',
        f"| where tostring(NodeProperties.rawData.aiAgentMetadata.id) == {kql.kql_str(agent_id, 'agent')}",
        "| project NodeId;",
        "union",
        "  (ExposureGraphEdges | where SourceNodeId in (AgentNode) | project AgentNodeId = SourceNodeId, "
        'Direction = "outgoing", EdgeLabel, OtherName = TargetNodeName, OtherLabel = TargetNodeLabel),',
        "  (ExposureGraphEdges | where TargetNodeId in (AgentNode) | project AgentNodeId = TargetNodeId, "
        'Direction = "incoming", EdgeLabel, OtherName = SourceNodeName, OtherLabel = SourceNodeLabel)',
        "| summarize Count = count(), Examples = make_set(OtherName, 10) by AgentNodeId, Direction, EdgeLabel, "
        "OtherLabel",
        "| order by Direction asc, Count desc",
        "| take 30"])
    ok, errors = await gather_sections({"exposureGraph": kql.rows(relations)})
    if "exposureGraph" in ok:
        rel = kql.shape_rows(ok["exposureGraph"], limit=30, max_str=400)[0]
        out["exposureGraph"] = rel
        node_ids = sorted({str(r["AgentNodeId"]) for r in rel if r.get("AgentNodeId")})
        if node_ids:
            out["agentNodeId"] = node_ids[0]
            out["next_steps"] = (f"explore_exposure_graph(view='blast_radius', source='{node_ids[0]}') shows what "
                                 "the agent can reach; find_ai_agents(mcp_server=...) finds other agents that use the "
                                 "same MCP server.")
    else:
        real, missing = unavailable(errors)
        if real:
            out["errors"] = real
        if missing:
            out["notAvailable"] = missing
    out["note"] = UNTRUSTED_NOTE + " This includes the agent's instructions and tool descriptions."
    return out
