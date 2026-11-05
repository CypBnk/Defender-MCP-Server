"""Advanced hunting: free KQL and schema discovery. With
Microsoft Sentinel or the Integrated SOC (ISOC) in the Defender portal the same API also reaches the tables of the
SIEM workspace; these tools cover the data exploration tools of the Sentinel MCP server (search_tables,
query_lake for the analytics tier, custom MCP tools)."""
from __future__ import annotations

import json
import re
from typing import Annotated, Optional

from .. import custom_hunts, kql, runtime, workspaces
from ..errors import InputError
from ..graph.odata import clamp_int
from ..scopes import THREAT_HUNTING_READ
from ..util import gather_sections
from .common import MaxItems, Workspace
from .registry import read_tool

MAX_SCHEMA_TABLES = 5

# Curated list (Microsoft Learn "Data tables in the advanced hunting schema", 10/2026). Availability depends on
# the licensed and deployed Defender workloads; get_hunting_schema(table=...) shows the real columns.
TABLES: dict[str, list[tuple[str, str]]] = {
    "Alerts": [
        ("AlertInfo", "Alerts from all Defender products with severity, category and MITRE techniques"),
        ("AlertEvidence", "Files, IPs, URLs, users and devices associated with alerts (join on AlertId)"),
    ],
    "Defender for Endpoint": [
        ("DeviceInfo", "Device information incl. OS, onboarding, sensor health, exposure level"),
        ("DeviceNetworkInfo", "Network adapters, IP and MAC addresses, connected networks"),
        ("DeviceProcessEvents", "Process creation events"),
        ("DeviceNetworkEvents", "Network connections"),
        ("DeviceFileEvents", "File creation, modification and other file system events"),
        ("DeviceRegistryEvents", "Registry changes"),
        ("DeviceLogonEvents", "Sign-ins and other authentication events on devices"),
        ("DeviceImageLoadEvents", "DLL loading events"),
        ("DeviceEvents", "Security control events (antivirus, ASR, exploit protection, services, tasks ...)"),
        ("DeviceFileCertificateInfo", "Certificates of signed files"),
        ("DisruptionAndResponseEvents", "Automatic attack disruption and predictive shielding events (contained "
                                        "users blocked, policies applied)"),
    ],
    "Vulnerability Management": [
        ("DeviceTvmSoftwareInventory", "Installed software incl. end-of-support status"),
        ("DeviceTvmSoftwareVulnerabilities", "Vulnerabilities (CVEs) per device and software"),
        ("DeviceTvmSoftwareVulnerabilitiesKB", "CVE knowledge base (CVSS, exploit available, description)"),
        ("DeviceTvmSecureConfigurationAssessment", "Security configuration assessment per device"),
        ("DeviceTvmSecureConfigurationAssessmentKB", "Configuration knowledge base (name, risk, benchmarks)"),
        ("DeviceTvmInfoGathering", "Assessment events (configuration and attack surface states)"),
        ("DeviceTvmInfoGatheringKB", "Metadata of the assessment events in DeviceTvmInfoGathering"),
        ("DeviceTvmBrowserExtensions", "Browser extensions on devices with risk level (preview)"),
        ("DeviceTvmBrowserExtensionsKB", "Browser extension details and requested permissions (preview)"),
        ("DeviceTvmCertificateInfo", "Certificates on devices: expiry, key size, algorithm (preview)"),
        ("DeviceTvmHardwareFirmware", "Hardware and firmware"),
        ("DeviceTvmSoftwareEvidenceBeta", "Where a software was detected on a device (registry, file path)"),
        ("DeviceBaselineComplianceAssessment", "Security baseline compliance per device and configuration (CIS, "
                                               "STIG; preview)"),
        ("DeviceBaselineComplianceAssessmentKB", "Baseline configurations: name, rationale, remediation (preview)"),
        ("DeviceBaselineComplianceProfiles", "Baseline profiles: benchmark, version, level (preview)"),
    ],
    "Defender for Office 365": [
        ("EmailEvents", "Email delivery and filtering events"),
        ("EmailAttachmentInfo", "Email attachments incl. hashes and threats"),
        ("EmailUrlInfo", "URLs in emails"),
        ("EmailPostDeliveryEvents", "Post-delivery actions (ZAP, manual remediation)"),
        ("UrlClickEvents", "Safe Links clicks (email, Teams, Office apps)"),
        ("CampaignInfo", "Email campaigns identified by Defender for Office 365 (preview)"),
        ("FileMaliciousContentInfo", "Malicious files in SharePoint Online, OneDrive and Teams (preview)"),
        ("MessageEvents", "Teams messages at delivery (external chats, internal messages with URLs) with threats"),
        ("MessagePostDeliveryEvents", "Security events after delivery of a Teams message (e.g. ZAP)"),
        ("MessageUrlInfo", "URLs in Teams messages"),
        ("MessageContents", "Teams message snippets and metadata"),
        ("CallActivityEvents", "Activities during Microsoft Teams calls"),
    ],
    "Defender for Identity / Entra ID": [
        ("IdentityInfo", "Account information"),
        ("IdentityLogonEvents", "Authentication events (Active Directory and Microsoft online services)"),
        ("IdentityDirectoryEvents", "Domain controller events (group changes, password changes, ...)"),
        ("IdentityQueryEvents", "LDAP, DNS and SAMR queries against Active Directory"),
        ("EntraIdSignInEvents", "Entra ID interactive and non-interactive sign-ins"),
        ("EntraIdSpnSignInEvents", "Entra ID service principal and managed identity sign-ins"),
        ("IdentityAccountInfo", "Accounts from all identity providers (Entra ID, AD, Okta ...) linked to identities: "
                                "status, roles, MFA, criticality, Defender risk"),
        ("IdentityEvents", "Identity events from other cloud identity providers (preview)"),
        ("GraphAPIAuditEvents", "Microsoft Graph API requests in the tenant (app and user)"),
    ],
    "Defender for Cloud Apps": [
        ("CloudAppEvents", "Activities in Office 365 and other connected cloud apps"),
        ("OAuthAppInfo", "OAuth applications (app governance): privilege level, permissions, publisher, last use"),
        ("BehaviorInfo", "Behaviors from Defender for Cloud Apps and UEBA (preview)"),
        ("BehaviorEntities", "Entities involved in BehaviorInfo behaviors (preview)"),
    ],
    "Defender for Cloud": [
        ("CloudAuditEvents", "Audit events of protected cloud platforms (Azure, AWS, GCP)"),
        ("CloudProcessEvents", "Process events in cloud workloads and containers (preview)"),
        ("CloudDnsEvents", "DNS activity of cloud infrastructure"),
        ("CloudKeyVaultEvents", "Operations on Azure Key Vault (preview)"),
        ("CloudStorageAggregatedEvents", "Cloud storage activity (preview)"),
        ("CloudPolicyEnforcementEvents", "Security gating / policy enforcement decisions (preview)"),
    ],
    "Microsoft Purview": [
        ("DataSecurityEvents", "User activities violating Purview policies (DLP, insider risk; preview)"),
        ("DataSecurityBehaviors", "Suspicious user behaviors from Purview insider risk (preview)"),
    ],
    "Microsoft Sentinel / ISOC workspace": [
        ("SecurityIncident", "Incidents of the SIEM workspace with status, owner and classification"),
        ("SecurityAlert", "Alerts from analytics rules and connected products"),
        ("SigninLogs", "Entra ID interactive sign-ins (Entra ID connector)"),
        ("AADNonInteractiveUserSignInLogs", "Entra ID non-interactive user sign-ins (Entra ID connector)"),
        ("AuditLogs", "Entra ID audit log: changes to users, groups, roles and applications"),
        ("AADUserRiskEvents", "Entra ID Protection risk detections per user"),
        ("AADRiskyUsers", "Entra ID Protection risky users"),
        ("BehaviorAnalytics", "UEBA: user activities with investigation priority 0-10 and insights"),
        ("Anomalies", "UEBA and analytics anomalies with score, tactics and techniques"),
        ("ThreatIntelIndicators", "Threat intelligence indicators (STIX) from the TI platform and feeds"),
        ("ThreatIntelObjects", "Threat intelligence objects (STIX threat actors, attack patterns, relationships)"),
        ("Watchlist", "Watchlist items; read one list with _GetWatchlist('alias')"),
        ("AzureActivity", "Azure Resource Manager activity log"),
        ("OfficeActivity", "Office 365 audit log (Exchange, SharePoint, Teams)"),
        ("SecurityEvent", "Windows security events from servers (Azure Monitor Agent)"),
        ("Syslog", "Linux syslog"),
        ("CommonSecurityLog", "CEF logs from firewalls, proxies and other network appliances"),
        ("MicrosoftGraphActivityLogs", "Microsoft Graph API requests in the tenant"),
        ("SentinelHealth", "Health of data connectors, analytics rules and automation"),
        ("Usage", "Ingested volume per table (shows which tables receive data, incl. custom _CL tables)"),
    ],
    "AI agents": [
        ("AgentsInfo", "AI agent inventory (Assets > AI agents): Copilot Studio, Foundry, Microsoft 365 and other "
                       "platforms, local agents on devices (Platform 'LocalAgents'); snapshots - use "
                       "summarize arg_max(Timestamp, *) by AgentId"),
    ],
    "Exposure Management": [
        ("ExposureGraphNodes", "Assets and identities of the enterprise exposure graph (devices, users, cloud "
                               "resources, AI agents with NodeLabel 'ai-agent') with criticality and properties"),
        ("ExposureGraphEdges", "Relationships between exposure graph nodes, e.g. 'can authenticate to', 'routes "
                               "traffic to'; attack paths and blast radius via make-graph / graph-match (preview)"),
    ],
}


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Advanced hunting (KQL)")
async def run_hunting_query(
    query: Annotated[str, "KQL query against the advanced hunting schema, e.g. "
                          "\"DeviceProcessEvents | where Timestamp > ago(1d) | summarize count() by FileName | top 10 by count_\"."],
    timespan_days: Annotated[Optional[int], "Look-back window enforced by the service in days (1-180, default 30). "
                                            "If the query has its own time filter, the shorter window applies; "
                                            "set it for workspace data older than 30 days."] = None,
    workspace: Workspace = None,
    max_items: MaxItems = 50,
) -> dict:
    """Run a read-only KQL query in advanced hunting and return the rows (cut to max_items and the response size
    limit; long values are shortened). Covers the Defender XDR tables and, with Microsoft Sentinel or the
    Integrated SOC (ISOC) in the Defender portal, the tables of the SIEM workspace (e.g. SigninLogs, AuditLogs,
    BehaviorAnalytics, ThreatIntelIndicators, SecurityEvent, custom _CL tables; TimeGenerated instead of
    Timestamp). workspace selects another connected workspace. Prefer summarize/top/project over raw events and
    check table and column names first with get_hunting_schema. The prebuilt hunts and run_custom_hunt cover
    common questions without writing KQL."""
    q = kql.validate_query(query)
    span = clamp_int(timespan_days, 1, kql.MAX_TIMESPAN_DAYS, "timespan_days") if timespan_days else None
    wid = workspaces.resolve(workspace)
    result = await kql.hunt(q, max_items=max_items, timespan_days=span, include_query=False, workspace_id=wid)
    if wid:
        result.update({"workspaceId": wid, "workspaceNote": workspaces.FALLBACK_NOTE})
    return result


def _words(search: str) -> list[str]:
    needle = str(search).strip().lower()
    if not 1 < len(needle) <= 60:
        raise InputError("search must have 2-60 characters.")
    words = [w for w in re.findall(r"[a-z0-9]+", needle) if len(w) >= 3][:5]
    return words or [needle]


async def _workspace_tables(words: Optional[list[str]], workspace_id: Optional[str]) -> list:
    """Tables of the SIEM workspace that received data in the last 30 days (Usage), optionally by keyword."""
    match = " or ".join(f"DataType contains {kql.kql_str(w)}" for w in words) if words else None
    rows = await kql.rows("\n".join(x for x in [
        "Usage", "| where TimeGenerated > ago(30d)", f"| where {match}" if match else None,
        '| extend Plan = tostring(column_ifexists("Plan", ""))',
        "| summarize MB = round(sum(Quantity), 1), LastIngestion = max(EndTime) by DataType, Plan",
        "| order by MB desc", "| take 50"] if x), workspace_id=workspace_id)
    return [{"table": r.get("DataType"), "plan": r.get("Plan") or None, "mb30d": r.get("MB"),
             "lastIngestion": r.get("LastIngestion")} for r in rows if r.get("DataType")]


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Advanced hunting schema")
async def get_hunting_schema(
    table: Annotated[Optional[str], "Table name, or up to 5 names separated by commas, e.g. 'DeviceProcessEvents, "
                                    "DeviceNetworkEvents'. Omit to list the tables."] = None,
    search: Annotated[Optional[str], "Keywords to find tables by name or description, e.g. 'sign-in', 'email', "
                                     "'firewall', 'watchlist', 'okta'."] = None,
    workspace: Workspace = None,
) -> dict:
    """Advanced hunting schema for Defender XDR and the Microsoft Sentinel / ISOC workspace. Without arguments:
    the tables grouped by product with a short description. search='keywords': matching tables from that list plus
    the workspace tables that received data in the last 30 days (also custom _CL tables, with volume and plan).
    With table (one or up to 5 names): their real columns and types (via getschema), so KQL for
    run_hunting_query, run_custom_hunt or a custom detection rule uses existing, correctly spelled columns."""
    wid = workspaces.resolve(workspace)
    if not table:
        groups = TABLES
        words = _words(search) if search else None
        if words:
            groups = {g: [(t, d) for t, d in items if any(w in f"{g} {t} {d}".lower() for w in words)]
                      for g, items in TABLES.items()}
            groups = {g: items for g, items in groups.items() if items}
        out: dict = {
            "tables": {group: [{"table": t, "description": d} for t, d in items] for group, items in groups.items()},
            "hint": "Call get_hunting_schema(table='<name>') for the columns. Tables of products, connectors or "
                    "workspaces that are not deployed are empty or missing; data-lake-tier tables are not "
                    "available in advanced hunting.",
        }
        if words or wid:
            ok, errors = await gather_sections({"workspace": _workspace_tables(words, wid)})
            if "workspace" in ok:
                out["workspaceTables"] = ok["workspace"]
            else:
                out["workspaceTables"] = []
                out["workspaceNote"] = ("No Microsoft Sentinel / ISOC workspace answered (none connected or no read "
                                        f"access): {errors.get('workspace', '')}"[:400])
        if words and not groups and not out.get("workspaceTables"):
            out["hint"] = "No table matches; try another keyword or list all tables without search."
        return out
    names = [kql.table_name(n) for n in str(table).split(",") if n.strip()]
    if not names or len(names) > MAX_SCHEMA_TABLES:
        raise InputError(f"table takes 1-{MAX_SCHEMA_TABLES} table names.")

    async def columns(name: str) -> list:
        rows = await kql.rows(f"{name}\n| getschema\n| project ColumnName, ColumnType", workspace_id=wid)
        return [{"name": r.get("ColumnName"), "type": r.get("ColumnType")} for r in rows if r.get("ColumnName")]

    if len(names) == 1:
        cols = await columns(names[0])
        return {"table": names[0], "columns": cols, "count": len(cols)}
    ok, errors = await gather_sections({n: columns(n) for n in names})
    out = {"tables": {n: {"columns": ok[n], "count": len(ok[n])} for n in names if n in ok}}
    if errors:
        out["errors"] = errors
    return out


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Custom hunts (own saved KQL)")
async def run_custom_hunt(
    name: Annotated[Optional[str], "Custom hunt to run; omit to list the available hunts with their parameters."] = None,
    parameters: Annotated[Optional[str], "Parameter values as a JSON object, e.g. {\"device\": \"pc-01\", "
                                         "\"days\": 7}."] = None,
    workspace: Workspace = None,
    max_items: MaxItems = 50,
) -> dict:
    """Run one of the organization's own saved hunting queries (custom hunts maintained by the Defender
    administrators), with typed and validated parameters; without name: list the available custom hunts with
    purpose and parameters. Prefer a matching custom hunt over writing new KQL. Results include the executed
    KQL ('kql')."""
    catalog = custom_hunts.load_catalog(runtime.settings().custom_hunts_file)
    if not name:
        return {"hunts": [custom_hunts.describe(h) for h in catalog.values()], "count": len(catalog),
                "hint": "Call run_custom_hunt(name=..., parameters='{...}')." if catalog else
                        "No custom hunts are configured (custom_hunts.json)."}
    hunt = catalog.get(str(name).strip())
    if not hunt:
        raise InputError(f"Unknown custom hunt {str(name)[:60]!r}. Available: {', '.join(catalog) or 'none'}.")
    values: dict = {}
    if parameters:
        try:
            values = json.loads(parameters)
        except json.JSONDecodeError:
            raise InputError('parameters must be a JSON object, e.g. {"device": "pc-01", "days": 7}.') from None
        if not isinstance(values, dict) or not all(isinstance(v, (str, int, float, bool)) or v is None
                                                   for v in values.values()):
            raise InputError("parameters must be a JSON object with text or number values.")
    query = custom_hunts.render(hunt, values)
    wid = workspaces.resolve(workspace)
    result = await kql.hunt(query, max_items=max_items, hunt=hunt["name"], workspace_id=wid)
    if wid:
        result.update({"workspaceId": wid, "workspaceNote": workspaces.FALLBACK_NOTE})
    return result
