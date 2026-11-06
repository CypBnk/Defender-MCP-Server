# Defender XDR MCP Server

MCP server for Microsoft Defender XDR, running on Azure Container Apps and used by a Copilot Studio agent. It covers
the daily work of **security analysts** (incident queue, investigation of devices, users and indicators, hunting,
threat intelligence), **operators** (responses on devices and user accounts, indicators) and **Defender
administrators** (sensor and antivirus health, vulnerabilities, Defender for Identity, detection rules, AI agents)
and can be used **standalone**. For the **Integrated SOC (ISOC) in Microsoft Defender**, which does not include the
Microsoft Sentinel MCP Server, it takes over that server's tools as far as public APIs allow: queries and table
search in the SIEM workspace, analysis of users and indicators with an assessment, attack paths in the exposure
graph, see [Sentinel MCP Server and ISOC](#sentinel-mcp-server-and-isoc).

Users sign in **directly at Entra ID** (Copilot Studio, OAuth 2.0 "Manual"). The server only validates the token
and calls Microsoft Graph and the Defender for Endpoint API **on behalf of the user** (on-behalf-of). Entra roles,
Defender RBAC and device groups therefore apply unchanged. The server runs in its own resource group with its own
app registrations and secrets and can be combined with other MCP servers in the same agent.

## License and disclaimer

License: Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party components and their
licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

- **Not a Microsoft product.** The project is not developed, supported or reviewed by Microsoft. Microsoft,
  Microsoft Defender, Microsoft Sentinel, Microsoft Entra, Microsoft Graph, Copilot Studio and Azure are trademarks
  of the Microsoft group of companies.
- **No warranty and no support.** The software is provided as is (sections 7 and 8 of the license). There is no
  committed support, no maintenance commitment and no liability for damages arising from its use.
- **Use at your own responsibility.** The admin tools can isolate devices, disable accounts, set indicators and
  block apps. Some tools use beta APIs of Microsoft Graph, `sanction_cloud_apps` an undocumented endpoint; Microsoft
  can change both at any time. Test in a test environment before production use and grant permissions
  deliberately. Data protection, works council co-determination and operation in your own tenant are the
  responsibility of the respective operator.

## Architecture

```
Copilot Studio ──OAuth 2.0 (Manual, client app)──▶ Entra ID ──▶ Access token (aud = server app)
      │
      └── POST /mcp + bearer token ──▶ Token validation (signature, tenant, scope, delegated, client app)
                                  └──▶ Middleware: errors → audit → rate limit [→ cache]
                                       └──▶ Tool ─┬─▶ GraphClient ─▶ graph.microsoft.com
                                                  │      Incidents, alerts, Advanced Hunting, Secure Score,
                                                  │      custom detections, MDI health and sensors, Cloud
                                                  │      Discovery, Threat Intelligence, users, ID Protection
                                                  │      (OBO token for Graph)
                                                  └─▶ MdeClient ──▶ api.security.microsoft.com
                                                         Antivirus health, device risk, remediation
                                                         tasks, response actions, tags,
                                                         investigations, indicators
                                                         (OBO token for WindowsDefenderATP)
```

```
src/defender_mcp/
  settings.py        single place for environment variables (validated at startup)
  app.py             create_server()/create_app(): auth, middleware, tools, health
  auth/              provider.py (Entra token validation), obo.py (token exchange per resource), identity.py
  graph/             client.py (GraphClient, MdeClient), paging.py (cursor, size budget), odata.py (validation)
  kql.py             KQL building blocks: escaping, validation of IP/domain/URL/hash/CVE/account/device, execution,
                     row limit, consistent column names
  resolve.py         resolve devices (name, Defender or Entra device ID, via DeviceInfo) and users (UPN, object ID,
                     via Graph)
  shaping.py         compact output, truncation, summarizing evidence and entities
  confirm.py         two-step confirmation
  workspaces.py      Sentinel/ISOC workspaces: resolve name or ID (SENTINEL_WORKSPACES), note on the fallback
  custom_hunts.py    load and validate the catalog of custom hunts; custom_hunts.json: bundled catalog
  middleware.py      audit, rate limit key, middleware chain
  tools/             38 read tools, 12 admin tools (registry.py: tools and required permissions)
```

## Tool catalog

### Read tools (38)

| Area | Tool | Content |
|---|---|---|
| Overview | `get_security_overview` | Open incidents (active, in progress, awaiting action) by severity and status, alerts by product and severity with the most frequent titles, device onboarding and sensor health, Secure Score, open MDI health issues; also a connection test |
| Incidents and alerts | `list_incidents` | Incident queue: filter by status, severity, period, owner (including `me`), unassigned only, tag, classification, determination (e.g. malware, phishing), part of the name; optionally with the alerts per incident (title, severity, MITRE, entities) in one call |
| | `get_incident` | Details with alerts, affected entities, comments |
| | `list_alerts`, `get_alert` | all products (alerts_v2), filter also by product; details with full evidence (processes, files, IPs, URLs, mails, accounts) |
| | `get_incident_statistics` | SOC report for a period (shift handover, week): created per day, by severity and status, resolved by classification/determination, time to resolve (median, P90), open and unassigned, top assignees |
| Investigation | `investigate_user` | one user account across everything, with an assessment (`assessment`: level, verdict, reasons): account status, Entra ID Protection risk and risk detections, identity (department, roles, MDI tags), alerts with incident IDs, sign-ins (failures, countries, risky, single-factor), devices used, email threats and Safe Links clicks, cloud app activity; from the Sentinel/ISOC workspace UEBA (investigation priority, insights) and anomalies |
| | `analyze_indicator` | Verdict on a URL, domain, IP or hash (malicious, suspicious …) with reasons: Microsoft Threat Intelligence, own threat intelligence (`ThreatIntelIndicators`) and watchlists of the workspace, file reputation, alerts and occurrences in the organization |
| | `get_identity_risks` | Entra ID Protection for the whole tenant: risky users (at risk or confirmed compromised), risk detections of the last days (type, level, IP, location; summarized by type, level and user) or risky service principals, highest risk first |
| | `find_identities` | Identity inventory as in the portal under Assets > Identities: accounts from Entra ID, Active Directory and other providers (e.g. Okta) with type, status, department, privileged roles (assigned and eligible), MDI tags, MFA methods, criticality and Defender risk; filters such as privileged, guests, without MFA |
| | `hunt_ioc` | an IP, domain, URL or hash (SHA256/SHA1/MD5) across devices, identities, cloud apps, email and alert evidence: hits per source with the number of affected entities, affected devices, related alerts (not for MD5), timeline; for SHA1/SHA256 also the file profile (global prevalence, signature, detection name). A SHA256 is also searched via the SHA1 from the file profile, because many tables only fill the SHA1; IPv4 addresses also in the form `::ffff:a.b.c.d` |
| | `get_threat_intelligence` | Microsoft Threat Intelligence: reputation of an IP, domain or URL, information about a CVE (active exploitation, exploits, priority), search in threat articles and actor profiles |
| Advanced Hunting | `run_hunting_query` | own KQL query, read-only, row limit and time limit; Defender tables and tables of the Sentinel/ISOC workspace (`workspace`, period up to 180 days) |
| | `get_hunting_schema` | all tables of the Advanced Hunting schema (as of Learn 10/2026, a test checks the list) by product including Sentinel/ISOC tables, keyword search also over the tables that receive data in the workspace (with volume and plan, including custom `_CL` tables), columns of up to five tables |
| | `list_sentinel_workspaces` | reachable Sentinel/ISOC workspaces: primary workspace and configured ones, each with workspace ID, tables with data and last ingestion |
| | `run_custom_hunt` | the team's own saved queries from a catalog with validated parameters; without a name: show the catalog (see [Custom hunts](#custom-hunts-run_custom_hunt)) |
| Exposure graph | `find_exposure_nodes` | Context of the exposure graph (node types, relationship types, categories) or nodes by name, type, category, criticality, internet exposure |
| AI agents | `find_ai_agents` | AI agent inventory as in the portal under Assets > AI agents: Copilot Studio, Microsoft Foundry, Microsoft 365 and other platforms (e.g. AWS Bedrock, GCP Vertex AI) plus local agents on devices (e.g. coding assistants); filter by name, platform, device, account/owner, MCP server, risky configuration (acts without approval, untrusted host process); summary |
| | `get_ai_agent` | one agent in full: description, instructions (system prompt), model, owners and sharing, authentication and permissions, tools, MCP servers, data sources, connected agents, triggers, guardrails, endpoints; relationships in the exposure graph (runs on, uses, is used by) as the starting point for the blast radius |
| | `explore_exposure_graph` | Attack paths: neighbors of a node, blast radius (what is reachable from a compromised node, default: critical assets), perimeter (who reaches an asset, internet-exposed first), paths between two nodes |
| Predefined hunts | `hunt_endpoint_threats` | suspicious PowerShell, LOLBin downloads, new services, scheduled tasks, AV detections, ASR events, tampering attempts, new local administrators |
| | `hunt_identity_threats` | failed sign-ins, password spray, LDAP reconnaissance, lateral movement (accounts with network/RDP logons on many devices), AD group changes, identity alerts |
| | `hunt_email_threats` | daily overview, phishing, malware, malicious attachments, Safe Links clicks, spoofing, message trace, post-delivery actions (ZAP, manual remediation), campaigns (recipients, delivered, still in the inbox), Teams messages with threats, malicious files in SharePoint, OneDrive and Teams |
| | `hunt_cloud_app_activity` | activities per app, activities of an account, OAuth consents, mass downloads, admin activities, impossible travel alerts, OAuth app inventory from App Governance (permission level, risk, verified publisher, admin consent, unused apps) |
| Devices | `find_defender_devices` | Search by name, operating system, onboarding, sensor health, exposure, risk level, internet exposure, "not seen since", device group, tag; summary. Also: which device had an internal IP address at a point in time (`ip_address`, `seen_at`) |
| | `get_defender_device` | Details (OS, sensor, exposure, risk level and health, device group, tags, IPs) with alerts, vulnerabilities and the signed-in users of the last 30 days (count, local admin logons) |
| | `get_device_activity` | Timeline: processes, network, logons, files, registry, events or alerts; last days or a time window around a point in time (e.g. ±30 min. around an alert) |
| | `get_device_exposure` | Vulnerabilities (minimum severity selectable), software, security configuration, security baselines (CIS, STIG with current and expected value), browser extensions with risk or certificates (expiry, weak keys) of the device; vulnerabilities and software also for one product (`software`) |
| | `get_antivirus_health` | Health of Microsoft Defender Antivirus: mode (active, passive, EDR block), currency of signatures, engine and platform, signature age, scan results; devices with a specific problem or the details of one device |
| Vulnerabilities | `get_vulnerability_overview` | Top CVEs, vulnerable software, exposed devices (each with minimum severity and "only with exploit"), missing security updates, unsupported software, misconfigurations, security baselines (compliance per profile and the most frequently failed checks), browser extensions by risk, expired, soon-to-expire or weak certificates; CVE views can be restricted to one product (`software`, e.g. "chrome" or "Google Chrome": every word must occur in vendor or product) |
| | `get_cve_exposure` | one CVE: CVSS, exploit, affected software and devices |
| | `get_remediation_tasks` | Remediation tasks from Defender Vulnerability Management: status, priority, due date, progress (remediated/affected devices), overdue first; details with the devices still affected |
| Posture | `get_secure_score` | current value, history, comparison, improvement actions |
| | `list_attack_simulations` | attack simulations (Defender for Office 365) with report |
| Defender for Identity | `get_identity_health` | health issues (open, closed, suppressed) or sensor inventory with health, service status, version and update status |
| Defender for Cloud Apps | `get_cloud_app_discovery` | Evaluation of the Cloud Discovery report for 7, 30 or 90 days: summary (apps by risk, tag and category, traffic, unsanctioned apps still in use, untagged risky apps awaiting a decision, AI and MCP apps, top apps by users and upload), filtered and sorted app lists, one app in detail (security, compliance and GDPR attributes, users, IP addresses, devices) and the data sources. Default is the Defender for Endpoint stream |
| Custom detections | `list_detection_rules`, `get_detection_rule` | Rules with status, frequency, alert title and severity, MITRE tactics, last change; details with KQL and alert template |

### Admin tools (12)

| Tool | Action | Execution |
|---|---|---|
| `update_incident` | Status, classification, determination, owner (including `me`), severity, tags, closing comment | two steps |
| `update_alert` | Status, classification, determination, owner | two steps |
| `add_comment` | Comment on an incident or alert | immediate |
| `create_detection_rule` | Custom detection from KQL (e.g. the `kql` of a hunt), frequency, alert template, MITRE tactic, entities. The preview runs the query once and reports missing required columns | two steps |
| `manage_detection_rule` | Enable, disable, change or delete a rule | two steps |
| `update_identity_health_issue` | Close, suppress or reopen a health issue | two steps |
| `run_device_response` | Isolate / release, restrict / unrestrict app execution, collect investigation package, stop and quarantine file (SHA1), start automated investigation, add / remove device tag. The preview shows the device, impact, existing tags and running actions | two steps; antivirus scan (quick/full) immediate |
| `get_response_actions` | Status of response actions (of a device or an action), of automated investigations (AIR: running, pending approval, by device or status, details of an investigation) or of automatic attack disruption (blocked sign-ins of contained users, terminated sessions, applied policies) | immediate, read-only |
| `sanction_cloud_apps` | Tag discovered apps as Sanctioned or Unsanctioned (up to 10 per call): preview with current tag, risk, users and impact, then verification of the new tag through Graph. **Undocumented API** (the call the Defender portal makes), requires `MDCA_API_URL`; see "Sanctioning apps" | two steps |
| `manage_submissions` | Submissions to Microsoft (Actions & submissions > Submissions): list email, URL and file submissions including user-reported messages with Microsoft's verdict; submit a URL as phishing, malware or spam or as wrongly blocked (notJunk) | listing immediate, submitting two steps |
| `manage_indicator` | List, create (Block, Warn, Audit, Allow …, with expiry date) or delete indicators (IP, domain, URL, hash, certificate) | listing immediate, otherwise two steps |
| `contain_user` | Contain a compromised account: revoke all sessions, disable / enable the Entra account, confirm compromised or dismiss risk in Entra ID Protection; disable, enable or force a password reset for the **on-premises Active Directory account** (also synchronized ones) through Defender for Identity (input UPN or SID). Your own account is protected | two steps |

`get_response_actions` is an admin tool because it needs a Defender for Endpoint API permission that is only granted
with `-GrantWritePermissions`.

### Deliberately not included or not possible through the API

| Task | Reason | Alternative |
|---|---|---|
| Remove emails from mailboxes (soft/hard delete, junk, move back to inbox) | The Graph API `analyzedEmails/remediate` supports **no delegated permissions**, only an application permission. It would contradict the "on behalf of the user only" principle | Defender portal (Explorer, "Take action" in Advanced Hunting) or your own automation with an application permission and approval |
| Approve pending actions in the Action center, control automated investigations | no public API (the status can be read with `get_response_actions`) | Defender portal (Action center) |
| Release quarantined mails, Tenant Allow/Block List, Defender for Office 365 policies | no Graph API (Exchange Online PowerShell) | Defender portal / PowerShell |
| AV, ASR and EDR policies, exclusions | managed through Intune or Security Settings Management, not through the Defender API | Intune / Defender portal |
| Alert suppression, device groups, roles, automation levels | no public API | Defender portal (Settings) |
| Live Response, offboarding, downloading investigation packages | deliberately left out (script execution or forensic data in the chat) | Defender portal |
| Report an email to Microsoft | The submission needs the message itself (Graph message URL of the mailbox or .eml content), which the agent does not have; `manage_submissions` submits URLs | Defender portal (Submissions), report button in Outlook |
| Search the Purview audit log | asynchronous API with run times above the Copilot Studio tool time limit; `hunt_cloud_app_activity` (CloudAppEvents) returns the Microsoft 365 activities of the last 30 days | Purview portal (Audit) |
| Other Defender for Cloud Apps actions (suspend user, tag Monitored, custom app tags, remove tag), App Governance policies | no documented API; `sanction_cloud_apps` sets Sanctioned and Unsanctioned through an undocumented endpoint | Defender portal (Cloud apps) |

**Example requests to the agent**
- "Show me my open incidents and all unassigned ones with high severity." → `list_incidents`
- "What do we know about max@contoso.com? Is the account compromised?" → `investigate_user`
- "What happened on PC-0815 15 minutes before and after the alert?" → `get_alert`, then `get_device_activity(around=…)`
- "Is the domain evil.example known to be malicious, and does it show up in our environment?" → `get_threat_intelligence`, `hunt_ioc`
- "Which devices have outdated antivirus signatures?" → `get_antivirus_health(issue="outdated_signatures")`
- "Which security updates would close the most critical CVEs?" → `get_vulnerability_overview(view="missing_updates")`
- "Isolate PC-0815 and disable max@contoso.com." → `run_device_response`, `contain_user` (each preview, then execution)
- "How did the week go in the SOC?" → `get_incident_statistics(days=7)`
- "Which device had the IP 10.20.4.17 yesterday at 2:10 pm?" → `find_defender_devices(ip_address=…, seen_at=…)`
- "Which remediation tasks are overdue?" → `get_remediation_tasks`
- "Which automated investigations are pending approval?" → `get_response_actions(kind="investigations", state="PendingApproval")`
- "Which custom hunts are there?" → `run_custom_hunt()`
- "Is https://login-contoso.example/ malicious, and who clicked on it?" → `analyze_indicator`
- "Is alice@contoso.com compromised?" → `investigate_user` (assessment with UEBA)
- "Which users are currently risky, and which risk detections were there today?" → `get_identity_risks`, `get_identity_risks(view="detections", days=1)`
- "Which privileged accounts have no MFA?" → `find_identities(privileged_only=True, without_mfa=True)`
- "Disable the AD account of max@contoso.com." → `contain_user(action="disable_ad_account")` (preview, then execution)
- "Which mails did ZAP remove today, and which campaigns are running?" → `hunt_email_threats(hunt="post_delivery")`, `hunt_email_threats(hunt="campaigns")`
- "What did users report as phishing?" → `manage_submissions(operation="list", source="user")`
- "What did automatic attack disruption block?" → `get_response_actions(kind="attack_disruption")`
- "Which OAuth apps have high privileges and are not used?" → `hunt_cloud_app_activity(hunt="oauth_apps")`
- "How well do our devices meet the CIS baseline? Which certificates are expiring?" → `get_vulnerability_overview(view="security_baselines" / "certificates")`
- "Which AI agents do we have, and which of them use MCP servers?" → `find_ai_agents`
- "Evaluate the Cloud Discovery report of the last 30 days." → `get_cloud_app_discovery()`
- "Which AI apps and MCP servers do our employees use?" → `get_cloud_app_discovery(view="apps", category="ai")`
- "Who uses Dropbox, and how secure is the app?" → `get_cloud_app_discovery(view="app", app_id="11627")`
- "Mark Dropbox as Unsanctioned." → `sanction_cloud_apps(app_ids=["11627"], status="Unsanctioned")` (preview, then execution)
- "Which local AI agents act without approval?" → `find_ai_agents(platform="local", risky_only=True)`
- "What is the HR Helpdesk agent allowed to do, and what can it reach?" → `get_ai_agent`, then `explore_exposure_graph(view="blast_radius", source=<agentNodeId>)`
- "What can an attacker reach from PC-0815?" → `explore_exposure_graph(view="blast_radius", source="PC-0815")`
- "Who can reach our critical SQL servers?" → `find_exposure_nodes`, then `explore_exposure_graph(view="perimeter", target=...)`
- "Show the failed sign-ins of the last 90 days from SigninLogs." → `get_hunting_schema(search=...)`, `run_hunting_query(..., timespan_days=90)`

## Custom hunts (`run_custom_hunt`)

The team's proven KQL queries can be provided as **custom hunts**, comparable to the "custom tools" of the Sentinel
MCP Server. The agent calls them through a single tool with a name and parameters; `run_custom_hunt()` without a
name shows the catalog with purpose and parameters. If a custom hunt fits, the agent uses it instead of writing KQL
itself.

The catalog is the file `src/defender_mcp/custom_hunts.json` (two examples are included):

```json
[
  {
    "name": "process_runs_on_device",
    "description": "Every start of one program on one device with command line, account and parent process.",
    "query": "DeviceProcessEvents\n| where Timestamp > ago({{days}}d)\n| where DeviceId =~ {{device}} or DeviceName =~ {{device}}\n| where FileName =~ {{file_name}}",
    "parameters": {
      "device": {"type": "device", "required": true, "description": "Device name or Defender device ID."},
      "file_name": {"type": "string", "required": true, "description": "Program file name, e.g. powershell.exe."},
      "days": {"type": "days", "default": 3, "description": "Look-back window in days (1-30)."}
    }
  }
]
```

Rules:
- `name`: lowercase letters, digits and underscores, starts with a letter (3–41 characters). The agent reads
  `description` (10–600 characters) to choose the right hunt: describe what the hunt finds, preferably in English
  like the other tool descriptions. At most 50 hunts.
- The server replaces placeholders `{{name}}` with validated and escaped KQL values. **Do not put quotes around
  placeholders** (`FileName =~ {{file_name}}`, not `'{{file_name}}'`). Every parameter must occur in the query and
  every placeholder must be defined.
- Types: `string` (text up to 500 characters), `upn`, `account`, `ip`, `domain`, `url`, `sha1`, `sha256`, `md5`,
  `device` (device name or Defender device ID), `int`, `days` (1–30), `datetime` (ISO 8601, converted to UTC). Per
  parameter optionally `required: true` or a `default` that must match the type.
- Row limit (`max_items`), time limit and permissions apply as for `run_hunting_query`: every user only sees data of
  their device groups and roles. The result contains the executed KQL (`kql`).
- The server validates the catalog at startup. If it is invalid, the server does not start; the message names the
  hunt, field and reason (container app log).

Rolling out changes: test the query in the portal under Advanced Hunting first, adjust the file and run
`./deploy.ps1`; the script builds a new image that contains the catalog. Alternatively, `CUSTOM_HUNTS_FILE` points to
your own file, e.g. on a mounted volume.

## Sentinel MCP Server and ISOC

The **Integrated SOC (ISOC) in Microsoft Defender** (preview) brings SIEM capabilities into the Defender portal; data
from additional sources, UEBA, threat intelligence and watchlists reside in an **ISOC workspace** (a Log Analytics
workspace in your own subscription). ISOC does not include the Microsoft Sentinel MCP Server. This server takes over
its tools as far as public APIs with delegated permissions allow. The basis is Advanced Hunting (`runHuntingQuery`):
in the Defender portal it also reaches the tables of the SIEM workspace, without a parameter the user's primary
workspace, with `workspaceId` another one. No new app permissions are needed for this.

| Sentinel MCP (collection) | Tool | Here |
|---|---|---|
| Data exploration | `list_sentinel_workspaces` | `list_sentinel_workspaces` |
| | `search_tables` | `get_hunting_schema(search=...)`: table catalog and the tables that receive data in the workspace, then `get_hunting_schema(table=...)` |
| | `query_lake` | `run_hunting_query(workspace=..., timespan_days=...)` for the analytics tier; not for data that is only in the data lake tier (see below) |
| | `analyze_user_entity`, `get_entity_analysis` | `investigate_user`: facts plus a rule-based assessment, immediate instead of asynchronous |
| | `analyze_url_entity` | `analyze_indicator`, also for domains, IPs and hashes |
| | Graph tools (`find_blastradius`, `find_walkable_paths`, `find_exposure_perimeter`, `find_connected_nodes`, `find_nodes`, `get_graph_context`) | `explore_exposure_graph` (views `blast_radius`, `paths`, `perimeter`, `neighbors`) and `find_exposure_nodes` on the exposure graph |
| Triage | all 27 tools | covered (e.g. `find_defender_devices(ip_address=...)`, `get_remediation_tasks`, `get_response_actions(kind="investigations")`) |
| Custom tools | saved KQL as a tool | `run_custom_hunt` |
| Security Copilot agent creation | – | not included (building Security Copilot agents, no public API) |

**Differences to be aware of**
- **Assessments without Security Copilot:** the entity analyzer of the Sentinel MCP lets AI decide and consumes
  Security Compute Units. Here, fixed queries collect the signals, and a disclosed rule yields level and verdict
  (`assessment.level`, `verdict`, `reasons`, `basis`). The agent phrases the verdict; the reasons can be verified.
  Watchlist hits only count as context, because a watchlist can also be an allow list.
- **Data lake tier:** Advanced Hunting only reaches the analytics tier. For data that is only in the data lake there
  is a KQL API (`api.securityplatform.microsoft.com`) whose token scope for delegated calls Microsoft does not
  document; it is therefore not built in. An ISOC environment without a data lake is not affected.
- **Graph:** the graph tools of the Sentinel MCP work on Sentinel graphs (exposure, hunting, data risk) with separate
  billing. Here it is the exposure graph of Exposure Management through the Advanced Hunting tables
  `ExposureGraphNodes`/`ExposureGraphEdges` (no additional cost). The hunting and data risk graphs have no public
  query interface for custom servers.
- **Workspace fallback:** if a specified workspace is not reachable for the user, the service answers from the
  primary workspace without an error message. The tools point this out; the `TenantId` column of the Sentinel tables
  shows the workspace ID. `list_sentinel_workspaces` checks this for all configured workspaces.

**Setup:** nothing is needed if the ISOC workspace is the primary workspace (the default with one workspace). To
offer several workspaces by name, set `SentinelWorkspaces = 'isoc-ws=<workspace-id>,alt-ws=<workspace-id>'` in
`deploy.settings.psd1` and run `./deploy.ps1`. Users need read access to the workspace (see roles) and read access in
Exposure Management for the exposure graph. Queries on tables in the Basic or Auxiliary plan can incur query costs
depending on the data volume.

### Sanctioning apps (sanction_cloud_apps, undocumented API)

Microsoft offers no documented API for setting **Sanctioned/Unsanctioned**: the Graph API for Cloud Discovery is
read-only, and the documented Defender for Cloud Apps API has no call for app tags. `sanction_cloud_apps` therefore
uses the call that the Defender portal makes itself (`POST /cas/api/v1/discovery/discovery_app/{appId}/set_sanctioned/`
with `{"sanction": true|false}`), known from a public community script, not from Microsoft documentation.
**Microsoft does not support this and can change the endpoint at any time.** After setting the tag, the tool reads it
back for every app through Graph (also after an error, because a timeout may still have taken effect) and reports
overall `verified`, `accepted` (accepted, Graph does not show the new tag yet), `partial` (mixed) or `failed`.

- **Setup:** `MdcaApiUrl` in `deploy.settings.psd1` (portal: Settings > Cloud Apps > System > About, e.g.
  `https://contoso.eu2.portal.cloudappsecurity.com`), then `./deploy.ps1 -ConfigureAppRegistration -GrantWritePermissions`.
  Without `MDCA_API_URL` the tool reports "not configured".
- **Sign-in `MDCA_AUTH='obo'` (default):** on behalf of the signed-in user (resource "Microsoft Cloud App Security",
  delegated `Discovery.manage`); the user's permissions in Defender for Cloud Apps apply (e.g. Security Administrator
  or Cloud App Security Administrator). Whether the API accepts Entra tokens for this undocumented call is not
  documented; if it returns 403 despite a suitable role, `token` remains as an option.
- **Sign-in `MDCA_AUTH='token'`:** legacy Defender for Cloud Apps API token (Settings > Cloud Apps > System > API
  tokens), requested by `deploy.ps1` and stored in Key Vault (`<prefix>mdca-api-token`). The server then acts **with
  the permissions of the token owner**, not of the user; the audit log of the MCP server names the user. Microsoft has
  deprecated legacy tokens. Restart the revision after replacing the token.
- **Effect:** Unsanctioned blocks the app on devices with Defender for Endpoint if the integration is configured
  accordingly (block indicators for the app's domains, network protection required); without the integration the tag
  only marks the app. A Cloud Discovery policy can overwrite the tag later (the last action wins).
- **Limits:** only apps that Cloud Discovery has seen in the last 90 days; Monitored, custom tags and removing a tag
  remain in the portal; at most 10 apps per call (the API allows 30 requests per minute).

## Permissions

### App registration (delegated, admin consent required)
The OBO exchange uses `.default`; what counts is therefore the admin consent on the server app. **Do not add
application permissions**: the server rejects app-only tokens.

**Microsoft Graph, read permissions (default):** `AttackSimulation.Read.All`, `CloudApp-Discovery.Read.All`,
`CustomDetection.Read.All`, `IdentityRiskEvent.Read.All` (risk detections), `IdentityRiskyServicePrincipal.Read.All`
(risky service principals), `IdentityRiskyUser.Read.All` (user risk), `SecurityAlert.Read.All`,
`SecurityEvents.Read.All` (Secure Score), `SecurityIdentitiesAccount.Read.All` (MDI accounts for the AD actions),
`SecurityIdentitiesHealth.Read.All`, `SecurityIdentitiesSensors.Read.All` (MDI sensors), `SecurityIncident.Read.All`,
`ThreatHunting.Read.All`, `ThreatIntelligence.Read.All`, `ThreatSubmission.Read.All` (submissions), `User.Read`,
`User.Read.All` (resolve users)

**WindowsDefenderATP / Defender for Endpoint API, read permissions (default):** `Machine.Read` (antivirus health,
device risk level), `RemediationTask.Read` (remediation tasks)

**Microsoft Graph, write permissions (only with `-GrantWritePermissions`):** `CustomDetection.ReadWrite.All`,
`IdentityRiskyUser.ReadWrite.All` (confirm compromised, dismiss risk), `SecurityAlert.ReadWrite.All`,
`SecurityIdentitiesActions.ReadWrite.All` (disable, enable AD account, force password reset),
`SecurityIdentitiesHealth.ReadWrite.All`, `SecurityIncident.ReadWrite.All`, `ThreatSubmission.ReadWrite.All` (submit
URLs), `User.EnableDisableAccount.All` (disable account), `User.RevokeSessions.All` (revoke sessions)

**Defender for Cloud Apps API (Microsoft Cloud App Security, `05a65629-4c1b-48c1-a78b-804c4abdd4af`), only with
`MDCA_API_URL`, `MDCA_AUTH='obo'` and `-GrantWritePermissions`:** `Discovery.manage` (`sanction_cloud_apps`)

**WindowsDefenderATP, write permissions (only with `-GrantWritePermissions`):** `Machine.Isolate`, `Machine.Scan`,
`Machine.CollectForensics`, `Machine.RestrictExecution`, `Machine.StopAndQuarantine`, `Machine.ReadWrite` (status of
the actions, device tags), `Alert.ReadWrite` (start automated investigations and read their status; there is no
delegated read permission for this), `Ti.ReadWrite` (indicators). If the WindowsDefenderATP service principal is
missing in the tenant (error AADSTS650052), `deploy.ps1` creates it
(`az ad sp create --id fc780465-2017-40d4-a0c5-307022471b92`).

### User roles
The app permissions only open the door. What a user sees and may do is determined by their roles:

| Task | Entra role (simple) | Defender Unified RBAC (fine-grained) |
|---|---|---|
| Read: incidents, alerts, hunting, devices | Security Reader | Security data basics (Read); for the email tables additionally Email & collaboration metadata (Read) |
| Vulnerabilities, Secure Score | Security Reader | Vulnerability management (Read), Exposure Management (Read) |
| Edit and comment on incidents/alerts; antivirus scan, investigation package | Security Operator | Alerts (Manage) |
| Isolate, app restriction, stop and quarantine file | Security Operator | Response (Manage); classic MDE RBAC: "Active remediation actions" |
| Start automated investigation | Security Operator | Alerts (Manage); classic MDE RBAC: "Active remediation actions" |
| Device tags | Security Operator | Alerts (Manage); classic MDE RBAC: "Manage security settings" |
| Antivirus health, device risk level | Security Reader | Security data basics (Read) |
| Tables of the Sentinel/ISOC workspace (hunting, UEBA, own threat intelligence, watchlists) | – | Azure role Microsoft Sentinel Reader on the workspace (or Unified RBAC with Sentinel as a data source) |
| Exposure graph (`find_exposure_nodes`, `explore_exposure_graph`) | Security Reader | Exposure Management (Read) |
| AI agents (`find_ai_agents`, `get_ai_agent`) | Security Reader | Security data basics (Read); the data requires "Security for AI agents" (Microsoft 365 connector or Microsoft Agent 365), local agents require Defender for Endpoint Plan 2 |
| Remediation tasks | Security Reader | Vulnerability management (Read) |
| Status of response actions and automated investigations | Security Reader | Security data basics (Read); app permission only with `-GrantWritePermissions` |
| Custom detections, indicators | Security Administrator | Detection tuning (Manage) |
| Investigate users | Security Reader; for user risk Security Reader or higher (Entra ID P2) | – |
| Revoke sessions, disable account | Entra role that may manage the user (e.g. User Administrator; for administrator accounts Privileged Authentication Administrator) | – |
| Confirm compromised, dismiss risk | at least Security Administrator (Entra ID P2) | – |
| Identity risks (`get_identity_risks`) | Security Reader or higher (Entra ID P1/P2; service principals: Workload ID Premium) | – |
| Disable, enable AD account, force password reset | at least Security Administrator; Defender for Identity with sensors on the domain controllers (action account or local system account of the sensor) | – |
| Sanction apps (`sanction_cloud_apps`) | Permission to manage Cloud Discovery in Defender for Cloud Apps, e.g. Security Administrator or Cloud App Security Administrator (with `MDCA_AUTH='token'`: role of the token owner) | – |
| Submissions (`manage_submissions`) | Read e.g. Security Reader, submit e.g. Security Administrator (roles for submissions in Defender for Office 365) | – |
| Identity inventory, attack disruption, baselines, extensions, certificates | Security Reader | Security data basics (Read); baselines: Defender Vulnerability Management add-on or Premium |

**Device groups** apply in addition: hunting results, devices and actions only for devices the user has access to.
A detection rule that runs on all devices can only be changed by someone who sees all devices. License-dependent:
Defender for Endpoint P2, Defender for Identity, Defender for Office 365 P2, Defender for Cloud Apps, Entra ID P2
(sign-in events `EntraIdSignInEvents`, user risk); `hunt_ioc` skips missing tables, `investigate_user` lists them
under `notAvailable`, the other hunts report them as errors. Microsoft Threat Intelligence is included in Defender XDR (no
separate license).

## Setup

Required tools

· PowerShell 7.2 or later

· Azure CLI 2.60 or later

· Current Bicep CLI

Required permissions

The following role is required on the resource group:

· Owner

Contributor is not sufficient here, because the deployment itself creates RBAC assignments for Key Vault, Container Registry, and the managed identity.

In Microsoft Entra ID, you additionally need Cloud Application Administrator or Application Administrator.

Step 1: Review the deployment settings

The organization-specific settings are located in the file deploy.settings.psd1. On the first run, the deployment script automatically generates this file from the template deploy.settings.example.psd1.

However, I recommend creating the file yourself before the first deployment:

PowerShell
Copy-Item deploy.settings.example.psd1 deploy.settings.psd1

You can then adjust the settings to fit your environment. The most important values include:

```PowerShell
ResourceGroup = 'rg-defender-mcp-prod'
Location = 'westeurope'
 
ContainerApp = 'ca-defender-mcp-prod'
ContainerAppsEnvironment = 'cae-defender-mcp-prod'
LogAnalyticsWorkspace = 'log-defender-mcp-prod'
 
AppRegEnvironment = 'prod'
AllowedGroupIds = @()
```

If you use your own naming conventions, now is the right time to enter them. The names for the Container Registry and Key Vault can be generated automatically. This makes sense, since both names must be globally unique.

Step 2: Connect to Azure

Next, we sign in with the Azure CLI to the correct tenant and select the desired subscription:

```PowerShell
az login --tenant <tenant-id>
az account set --subscription <subscription-id>
```

The script checks whether the signed-in tenant matches the TenantId stored in the settings. Anyone who regularly switches between multiple tenants or test environments knows why a check here makes sense.

Step 3: Start the deployment

We start the actual deployment with the following command:

```PowerShell
./deploy.ps1 -ConfigureAppRegistration
```

If you also want to enable actions / write permissions, use this command:

```PowerShell
./deploy.ps1 -ConfigureAppRegistration -GrantWritePermissions
```

On the first run, the script first checks:

· PowerShell, Azure CLI, and Bicep versions
· Azure sign-in, tenant, and subscription
· Deployment settings
· Required resource providers

Afterwards, the Azure resources, the container image, and the two app registrations are created or configured. The client secret of the server app and the signing key are stored directly in the Key Vault and do not appear in the console output.
At the end, the script runs a smoke test and outputs the values we need for Copilot Studio in the next step. You can also run the script again. Existing resources are reused and missing components are added.

Step 4: Connect the MCP server to Copilot Studio
Now we come to the interesting part: the connection to Copilot Studio.
Open the desired agent and navigate to: Tools > Add tool > Model Context Protocol.
As the server URL, enter the endpoint output by the deployment script:

https://<container-app>.<domain>/mcp

For authentication, we select OAuth 2.0 > Manual. You will find the actual values in the deployment script's output. Here is an example:
Field	ValueClient ID	App ID of the Copilot client app
Client Secret	Secret of the Copilot client app
Authorization URL	https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
Token URL / Refresh URL	https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
Scopes	openid profile api://<server-client-id>/access_as_user offline_access

You have to create the client secret manually once on the client app, and then store it in Copilot Studio in the connection setup.
After saving, Copilot Studio displays a redirect URL. You can add it using the following command:

```PowerShell
./deploy.ps1 -AddRedirectUri '<redirect-url>'
```

Afterwards, we create the connection and sign in.

Optional:
Restrict access via Entra groups
```PowerShell
AllowedGroupIds = @('<object-id-of-the-security-group>')
```

The script assigns the groups to both enterprise apps and enables "Assignment required".
Access to the container endpoint
After a successful functional test, network access can additionally be restricted to the Power Platform connector ranges:

```PowerShell
./deploy.ps1 -RestrictIngressToPowerPlatform
```

Beforehand, you should check in the audit log which IP addresses the connector calls actually come from.
