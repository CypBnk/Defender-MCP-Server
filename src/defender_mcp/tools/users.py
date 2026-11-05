"""User-centric investigation: one call answers 'what do we know about this account and is it
compromised?' across Entra ID, Entra ID Protection, Defender for Identity, alerts, sign-ins, devices, email and
cloud apps. It also reads UEBA (BehaviorAnalytics, Anomalies) and risk detections from the Microsoft
Sentinel / ISOC workspace and returns a rule-based assessment - the analyze_user_entity tool of the Sentinel MCP
entity analyzer without Security Compute Units. Every section is optional: a missing role or license fills
'errors', a data source that does not exist in the tenant is listed under 'notAvailable'."""
from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

from .. import kql, runtime, workspaces
from ..errors import DefenderToolError, GraphError
from ..graph.odata import key
from ..resolve import entra_sid, resolve_user, user_key
from ..scopes import IDENTITY_RISKY_USER_READ, SECURITY_ALERT_READ, THREAT_HUNTING_READ, USER_READ_ALL
from ..shaping import UNTRUSTED_NOTE, compact, pick
from ..util import gather_sections
from .analysis import Assessment, num, unavailable
from .common import Days, MaxItems, Workspace
from .registry import read_tool

_ACCOUNT_FIELDS = ("id", "displayName", "userPrincipalName", "mail", "accountEnabled", "userType", "jobTitle",
                   "department", "createdDateTime", "lastPasswordChangeDateTime", "onPremisesSyncEnabled",
                   "onPremisesSamAccountName", "onPremisesDomainName", "signInSessionsValidFromDateTime")
_RISK_FIELDS = ("riskLevel", "riskState", "riskDetail", "riskLastUpdatedDateTime", "isProcessing")
_INCIDENT_LOOKUPS = 5
USER_VERDICTS = {"high": "likely compromised - investigate now and consider contain_user",
                 "medium": "suspicious - review the reasons", "low": "minor signals only",
                 "none": "no risk signals in the available data"}
USER_BASIS = ("Rule-based summary of the listed signals (not an AI verdict): Entra ID Protection risk and detections, "
              "alerts, risky sign-ins, UEBA investigation priority and anomalies, email threats and clicks.")


def _assess(out: dict) -> dict:
    a = Assessment()
    risk = out.get("risk") or {}
    level, state = str(risk.get("riskLevel") or "").lower(), str(risk.get("riskState") or "").lower()
    if state == "confirmedcompromised":
        a.add("high", "Entra ID Protection: confirmed compromised.")
    elif state == "atrisk" and level == "high":
        a.add("high", "Entra ID Protection: high user risk.")
    elif state == "atrisk" and level in ("medium", "low"):
        a.add("medium" if level == "medium" else "low", f"Entra ID Protection: {level} user risk.")
    alerts = out.get("alerts") or {}
    by_sev = {str(k).lower(): v for k, v in (alerts.get("bySeverity") or {}).items()}
    if by_sev.get("high"):
        a.add("high", f"{by_sev['high']} high-severity alert(s) involve the user.")
    elif by_sev.get("medium"):
        a.add("medium", f"{by_sev['medium']} medium-severity alert(s) involve the user.")
    elif alerts.get("count"):
        a.add("low", f"{alerts['count']} low-severity or informational alert(s) involve the user.")
    sign = out.get("signIns") or {}
    if num(sign.get("RiskySignIns")):
        a.add("medium", f"{int(num(sign['RiskySignIns']))} risky sign-in(s).")
    if num(sign.get("SingleFactorSuccess")):
        a.add("low", f"{int(num(sign['SingleFactorSuccess']))} successful single-factor sign-in(s).")
    if num(sign.get("Failed")) >= 20:
        a.add("low", f"{int(num(sign['Failed']))} failed sign-ins.")
    prio = num((out.get("ueba") or {}).get("MaxPriority"))
    if prio >= 7:
        a.add("high", f"UEBA investigation priority {int(prio)}/10.")
    elif prio >= 4:
        a.add("medium", f"UEBA investigation priority {int(prio)}/10.")
    anomalies = out.get("anomalies") or {}
    if num(anomalies.get("Anomalies")):
        names = [str(x) for x in (anomalies.get("Templates") or [])][:3]
        a.add("medium", f"{int(num(anomalies['Anomalies']))} UEBA anomaly(ies): {', '.join(names) or 'see anomalies'}.")
    detections = out.get("riskDetections") or {}
    if num(detections.get("High")):
        a.add("high", f"{int(num(detections['High']))} high-risk detection(s) in Entra ID Protection.")
    elif num(detections.get("AtRisk")):
        a.add("medium", f"{int(num(detections['AtRisk']))} open risk detection(s) in Entra ID Protection.")
    email = out.get("email") or {}
    if num(email.get("DeliveredWithThreats")):
        a.add("medium", f"{int(num(email['DeliveredWithThreats']))} email(s) with threats were delivered to the user.")
    clicks = out.get("urlClicks") or {}
    if num(clicks.get("ClickedThrough")) and num(clicks.get("WithThreats")):
        a.add("medium", "The user clicked through to a URL with threats.")
    if (out.get("account") or {}).get("accountEnabled") is False:
        a.context.append("The account is disabled.")
    checked = [k for k in ("risk", "alerts", "signIns", "ueba", "anomalies", "riskDetections", "email", "urlClicks")
               if k in out]
    return a.result(USER_VERDICTS, USER_BASIS, checked=checked)


def _first(rows: list, max_str: int = 300) -> dict:
    if not rows:
        return {}
    shaped, _ = kql.shape_rows(rows, limit=1, max_str=max_str)
    return shaped[0] if shaped else {}


def _has_data(rows: list) -> bool:
    """Workspace summaries return one row of zeros when nothing matched."""
    row = rows[0] if rows else {}
    return bool(num(row.get("Activities")) or num(row.get("Anomalies")) or num(row.get("Detections")))


def _or(*conditions: Optional[str]) -> str:
    parts = [c for c in conditions if c]
    return "(" + " or ".join(parts) + ")"


async def _risk(object_id: str) -> dict:
    try:
        res = await runtime.graph().get(f"/identityProtection/riskyUsers/{object_id}")
    except GraphError as exc:
        if exc.status == 404:
            return {"riskState": "none", "note": "The user is not listed in Entra ID Protection risky users."}
        raise
    return compact(pick(res, _RISK_FIELDS))


async def _incident_of(alert_id: str) -> dict:
    res = await runtime.graph().get(f"/security/alerts_v2/{key(alert_id, 'alert_id')}")
    return pick(res, ("id", "incidentId", "status", "assignedTo"))


@read_tool(scopes=(USER_READ_ALL, IDENTITY_RISKY_USER_READ, THREAT_HUNTING_READ, SECURITY_ALERT_READ),
           title="Investigate user")
async def investigate_user(
    user: Annotated[str, "UPN (name@contoso.com) or Entra object ID of the user."],
    days: Days = 7,
    workspace: Workspace = None,
) -> dict:
    """Investigate one user account and assess whether it is compromised: account status (enabled, synchronized,
    last password change, sessions revoked), Entra ID Protection risk and risk detections, identity details
    (department, roles, criticality, Defender for Identity tags), alerts involving the user (with incident IDs),
    Entra sign-ins (failures, countries, apps, risky or single-factor sign-ins), devices the user signed in to,
    threats in received emails and Safe Links clicks, cloud app activity and - from the Microsoft Sentinel / ISOC
    workspace - UEBA behavior (investigation priority, insights) and anomalies. 'assessment' gives level
    (high/medium/low/none), verdict and the reasons. Use contain_user to respond (revoke sessions, disable,
    confirm compromised)."""
    kind, value = user_key(user)
    d = kql.days(days)
    wid = workspaces.resolve(workspace)
    out: dict[str, Any] = {"days": d}
    errors: dict[str, str] = {}
    account: dict = {}
    try:
        account = await resolve_user(value)
        out["account"] = compact(pick(account, _ACCOUNT_FIELDS))
    except DefenderToolError as exc:
        errors["account"] = str(exc)

    object_id = account.get("id") or (value if kind == "objectId" else None)
    upn = account.get("userPrincipalName") or (value if kind == "upn" else None)
    mail = account.get("mail")
    sids = [s for s in (account.get("onPremisesSecurityIdentifier"), entra_sid(object_id) if object_id else None) if s]

    def lit(v: str) -> str:
        return kql.kql_str(v)

    generic = _or(f"AccountObjectId =~ {lit(object_id)}" if object_id else None,
                  f"AccountUpn =~ {lit(upn)}" if upn else None)
    if sids:
        logon = f"AccountSid in~ ({', '.join(lit(s) for s in sids)})"
    else:   # no Graph data: the UPN prefix is usually the SAM account name (approximation)
        logon = f"AccountName =~ {lit(str(upn).split('@', 1)[0])}"
        out["devicesMatch"] = "approximate (account name), because the account could not be read from Entra ID"
    addresses = sorted({a.lower() for a in (mail, upn) if a})
    since = f"| where Timestamp > ago({d}d)"

    tasks: dict = {}
    if object_id:
        tasks["risk"] = _risk(object_id)
    tasks["identity"] = kql.rows("\n".join([
        "IdentityInfo", "| where Timestamp > ago(14d)", f"| where {generic}",
        "| summarize arg_max(Timestamp, *) by AccountObjectId",
        '| extend AccountDomain = column_ifexists("AccountDomain", ""), Manager = column_ifexists("Manager", ""), '
        'CriticalityLevel = column_ifexists("CriticalityLevel", int(null)), Tags = column_ifexists("Tags", dynamic(null)), '
        'AssignedRoles = column_ifexists("AssignedRoles", dynamic(null)), '
        'PrivilegedEntraPimRoles = column_ifexists("PrivilegedEntraPimRoles", dynamic(null)), '
        'IdentityEnvironment = column_ifexists("IdentityEnvironment", ""), '
        'SourceProviders = column_ifexists("SourceProviders", dynamic(null))',
        # an on-premises row (empty AccountObjectId) and the Entra row can both match: prefer the Entra row
        "| extend HasObjectId = isnotempty(AccountObjectId)", "| order by HasObjectId desc, Timestamp desc",
        "| project AccountDisplayName, AccountDomain, AccountName, Department, JobTitle, IsAccountEnabled, RiskLevel, "
        "RiskLevelDetails, CriticalityLevel, Tags, AssignedRoles, PrivilegedEntraPimRoles, IdentityEnvironment, "
        "SourceProviders, Manager, LastUpdated = Timestamp",
        "| take 1"]))
    tasks["alerts"] = kql.rows("\n".join([
        f"let Ids = AlertEvidence {since} | where {generic} | distinct AlertId;",
        "AlertInfo", since, "| where AlertId in (Ids)",
        "| summarize arg_max(Timestamp, Title, Severity, Category, ServiceSource, DetectionSource, AttackTechniques) "
        "by AlertId",
        "| order by Timestamp desc", "| take 30"]))
    tasks["signIns"] = kql.rows("\n".join([
        "EntraIdSignInEvents", since, f"| where {generic}",
        "| summarize SignIns = count(), Failed = countif(ErrorCode != 0), "
        "RiskySignIns = countif(RiskLevelDuringSignIn >= 50 or RiskLevelAggregated >= 50), "
        'SingleFactorSuccess = countif(ErrorCode == 0 and AuthenticationRequirement =~ "singleFactorAuthentication"), '
        "FromUnmanagedDevice = countif(IsManaged == 0), DistinctIPs = dcount(IPAddress), "
        "Countries = make_set(Country, 20), Applications = make_set(Application, 15), LastSignIn = max(Timestamp), "
        'Notable = make_list_if(bag_pack("Time", Timestamp, "Application", Application, "IP", IPAddress, '
        '"Country", Country, "ErrorCode", ErrorCode, "Risk", RiskLevelDuringSignIn, "Client", ClientAppUsed), '
        "ErrorCode != 0 or RiskLevelDuringSignIn >= 50, 10)"]))
    tasks["devices"] = kql.rows("\n".join([
        "DeviceLogonEvents", since, '| where ActionType == "LogonSuccess"', f"| where {logon}",
        "| summarize Logons = count(), AdminLogons = countif(IsLocalAdmin == true), LogonTypes = make_set(LogonType, 5), "
        "LastLogon = max(Timestamp) by DeviceName, DeviceId",
        "| order by LastLogon desc", "| take 20"]))
    if addresses:
        tasks["email"] = kql.rows("\n".join([
            "EmailEvents", since, f"| where RecipientEmailAddress in~ ({', '.join(lit(a) for a in addresses)})",
            "| summarize Received = count(), WithThreats = countif(isnotempty(ThreatTypes)), "
            'Phish = countif(ThreatTypes has "Phish"), Malware = countif(ThreatTypes has "Malware"), '
            'DeliveredWithThreats = countif(isnotempty(ThreatTypes) and DeliveryAction == "Delivered"), '
            'Samples = make_list_if(bag_pack("Time", Timestamp, "Sender", SenderFromAddress, "Subject", Subject, '
            '"Threats", ThreatTypes, "Location", LatestDeliveryLocation, "NetworkMessageId", NetworkMessageId), '
            "isnotempty(ThreatTypes), 5)"]))
    if upn:
        tasks["urlClicks"] = kql.rows("\n".join([
            "UrlClickEvents", since, f"| where AccountUpn =~ {lit(upn)}",
            "| summarize Clicks = count(), ClickedThrough = countif(IsClickedThrough == true), "
            'Blocked = countif(ActionType contains "Blocked"), WithThreats = countif(isnotempty(ThreatTypes)), '
            'Samples = make_list_if(bag_pack("Time", Timestamp, "Url", Url, "Action", ActionType, "Threats", ThreatTypes), '
            "isnotempty(ThreatTypes) or IsClickedThrough == true, 5)"]))
    if upn:
        ws_since = f"| where TimeGenerated > ago({d}d)"
        tasks["ueba"] = kql.rows("\n".join([
            "BehaviorAnalytics", ws_since, f"| where UserPrincipalName =~ {lit(upn)}",
            "| summarize Activities = count(), MaxPriority = max(InvestigationPriority), "
            "HighPriority = countif(InvestigationPriority >= 5), ActivityTypes = make_set(ActivityType, 10), "
            "Locations = make_set(SourceIPLocation, 10), "
            'Notable = make_list_if(bag_pack("Time", TimeGenerated, "Activity", ActivityType, "Action", ActionType, '
            '"Priority", InvestigationPriority, "IP", SourceIPAddress, "Location", SourceIPLocation, '
            '"Insights", ActivityInsights), InvestigationPriority >= 3, 10)']), workspace_id=wid)
        tasks["anomalies"] = kql.rows("\n".join([
            "Anomalies", ws_since, f"| where UserPrincipalName =~ {lit(upn)}",
            "| summarize Anomalies = count(), MaxScore = max(Score), Templates = make_set(AnomalyTemplateName, 10), "
            "Tactics = make_set(Tactics, 10), Techniques = make_set(Techniques, 10), LastAnomaly = max(EndTime)"]),
            workspace_id=wid)
        tasks["riskDetections"] = kql.rows("\n".join([
            "AADUserRiskEvents", ws_since, f"| where UserPrincipalName =~ {lit(upn)}",
            "| summarize arg_max(TimeGenerated, *) by Id",
            '| summarize Detections = count(), High = countif(RiskLevel == "high"), AtRisk = countif(RiskState == "atRisk"), '
            "Types = make_set(RiskEventType, 10), "
            'Samples = make_list(bag_pack("Time", DetectedDateTime, "Type", RiskEventType, "Level", RiskLevel, '
            '"State", RiskState, "IP", IpAddress), 5)']), workspace_id=wid)
    tasks["cloudApps"] = kql.rows("\n".join([
        "CloudAppEvents", since,
        f"| where {_or(f'AccountObjectId =~ {lit(object_id)}' if object_id else None, f'AccountId =~ {lit(upn)}' if upn else None)}",
        "| summarize Events = count(), Applications = make_set(Application, 10), Countries = make_set(CountryCode, 10), "
        "DistinctIPs = dcount(IPAddress), AdminOperations = countif(IsAdminOperation == true), "
        'Downloads = countif(ActionType == "FileDownloaded"), LastActivity = max(Timestamp)']))

    ok, failed = await gather_sections(tasks)
    errors.update(failed)
    errors, missing = unavailable(errors)
    if "risk" in ok:
        out["risk"] = ok["risk"]
    if ok.get("identity"):
        out["identity"] = _first(ok["identity"])
    if "alerts" in ok:
        alerts = kql.shape_rows(ok["alerts"], limit=30, max_str=300)[0]
        lookups = {a["AlertId"]: _incident_of(a["AlertId"]) for a in alerts[:_INCIDENT_LOOKUPS] if a.get("AlertId")}
        found, _missing = await gather_sections(lookups) if lookups else ({}, {})
        for a in alerts:
            info = found.get(a.get("AlertId"))
            if info:
                a["IncidentId"] = info.get("incidentId")
                a["Status"] = info.get("status")
        by_sev: dict = {}
        for a in alerts:
            by_sev[a.get("Severity") or "Unknown"] = by_sev.get(a.get("Severity") or "Unknown", 0) + 1
        out["alerts"] = {"count": len(alerts), "bySeverity": by_sev, "items": alerts,
                         "incidentIds": sorted({str(a["IncidentId"]) for a in alerts if a.get("IncidentId")})}
    for name in ("signIns", "email", "urlClicks", "cloudApps", "ueba", "anomalies", "riskDetections"):
        if name in ok and (name not in ("ueba", "anomalies", "riskDetections") or _has_data(ok[name])):
            out[name] = _first(ok[name], max_str=400)
    if "devices" in ok:
        out["devices"] = kql.shape_rows(ok["devices"], limit=20, max_str=200)[0]
    out["assessment"] = _assess(out)
    if missing:
        out["notAvailable"] = missing
    if errors:
        out["errors"] = errors
    out["next_steps"] = ("get_alert / get_incident for details; hunt_cloud_app_activity(hunt='account_activity', "
                         "account=...) or hunt_identity_threats(account=...) to dig deeper; contain_user to revoke "
                         "sessions, disable the account or confirm it as compromised.")
    out["note"] = UNTRUSTED_NOTE
    return out


# =========================================================================== identity inventory
_ID_LATEST = "\n".join([
    "IdentityAccountInfo",
    "| where Timestamp > ago(14d)",   # a new row per change and at least every 24 hours
    "| summarize arg_max(Timestamp, *) by AccountId",
    # license- and provider-dependent columns: tolerate their absence
    '| extend AssignedRoles = column_ifexists("AssignedRoles", dynamic(null)), '
    'EligibleRoles = column_ifexists("EligibleRoles", dynamic(null)), Tags = column_ifexists("Tags", dynamic(null)), '
    'EnrolledMfas = column_ifexists("EnrolledMfas", dynamic(null)), '
    'CriticalityLevel = column_ifexists("CriticalityLevel", int(null)), '
    'DefenderRiskLevel = column_ifexists("DefenderRiskLevel", int(null)), '
    'TenantMembershipType = tostring(column_ifexists("TenantMembershipType", "")), '
    'Department = tostring(column_ifexists("Department", "")), JobTitle = tostring(column_ifexists("JobTitle", "")), '
    'LastPasswordChangeTime = column_ifexists("LastPasswordChangeTime", datetime(null))',
    '| extend Privileged = coalesce(array_length(AssignedRoles), 0) > 0 or coalesce(array_length(EligibleRoles), 0) > 0 '
    'or tostring(Tags) has "Sensitive", MfaMethods = coalesce(array_length(EnrolledMfas), 0), '
    'IsCloudAccount = SourceProvider contains "Entra" or SourceProvider contains "AzureActiveDirectory" '
    'or SourceProvider in~ ("AzureAD", "AAD")',
])


_CLOUD_SOURCES = frozenset({"entra", "entraid", "microsoftentraid", "azuread", "aad", "azureactivedirectory"})
_AD_SOURCES = frozenset({"ad", "activedirectory", "onprem", "on-prem", "onpremises", "on-premises", "adds"})


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Find identities (inventory)")
async def find_identities(
    name_contains: Annotated[Optional[str], "Part of the display name or UPN."] = None,
    source: Annotated[Optional[str], "Identity provider, e.g. 'Entra', 'Active Directory', 'Okta' (part of the "
                                     "name)."] = None,
    account_type: Annotated[Optional[Literal["User", "ServiceAccount"]], "Only users or only service accounts."] = None,
    status: Annotated[Optional[Literal["Enabled", "Disabled"]], "Only enabled or only disabled accounts."] = None,
    privileged_only: Annotated[bool, "Only accounts with assigned or eligible roles or the Defender for Identity tag "
                                     "'Sensitive'."] = False,
    guests_only: Annotated[bool, "Only guest accounts."] = False,
    without_mfa: Annotated[bool, "Only Entra ID accounts without a registered MFA method."] = False,
    department: Annotated[Optional[str], "Part of the department name."] = None,
    summary_only: Annotated[bool, "Counts per identity provider and account type instead of the list."] = False,
    max_items: MaxItems = 50,
) -> dict:
    """Identity inventory of Microsoft Defender (portal: Assets > Identities) from IdentityAccountInfo: accounts
    from Entra ID, on-premises Active Directory and other identity providers (e.g. Okta), linked to identities.
    Per account: provider, type (user / service account), status, department, privileged roles (assigned and
    eligible), Defender for Identity tags, number of MFA methods, criticality, Defender risk level, last password
    change and IDs. Use investigate_user for one account and contain_user to respond."""
    filters = []
    if name_contains:
        lit = kql.kql_str(name_contains, "name_contains", 200)
        filters.append(f"| where DisplayName contains {lit} or AccountUpn contains {lit}")
    if source:
        compact_name = "".join(str(source).split())
        if compact_name.lower() in _CLOUD_SOURCES:
            filters.append("| where IsCloudAccount")
        elif compact_name.lower() in _AD_SOURCES:      # 'ActiveDirectory' is also part of 'AzureActiveDirectory'
            filters.append('| where replace_string(SourceProvider, " ", "") contains "ActiveDirectory" and not(IsCloudAccount)')
        else:
            filters.append(f'| where replace_string(SourceProvider, " ", "") contains {kql.kql_str(compact_name, "source", 100)}')
    if account_type:
        filters.append(f"| where Type == {kql.kql_str(account_type)}")
    if status:
        filters.append(f"| where AccountStatus == {kql.kql_str(status)}")
    if privileged_only:
        filters.append("| where Privileged")
    if guests_only:
        filters.append('| where TenantMembershipType == "Guest"')
    if without_mfa:
        filters.append("| where IsCloudAccount and MfaMethods == 0")
    if department:
        filters.append(f"| where Department contains {kql.kql_str(department, 'department', 200)}")
    base = [_ID_LATEST, '| where AccountStatus != "Deleted"', *filters]
    if summary_only:
        query = "\n".join(base + [
            '| summarize Accounts = count(), Enabled = countif(AccountStatus == "Enabled"), Privileged = countif(Privileged), '
            'Guests = countif(TenantMembershipType == "Guest"), CloudWithoutMfa = countif(IsCloudAccount and MfaMethods == 0) '
            "by SourceProvider, Type",
            "| order by Accounts desc"])
    else:
        query = "\n".join(base + [
            "| project DisplayName, AccountUpn, SourceProvider, Type, AccountStatus, Department, JobTitle, "
            "TenantMembershipType, Privileged, AssignedRoles, EligibleRoles, Tags, MfaMethods, CriticalityLevel, "
            "DefenderRiskLevel, LastPasswordChangeTime, CreatedDateTime, Sid, IdentityId, AccountId",
            "| order by Privileged desc, DefenderRiskLevel desc nulls last, DisplayName asc"])
    try:
        return await kql.hunt(query, max_items=max_items, max_str=300)
    except DefenderToolError as exc:
        if "IdentityAccountInfo" in str(exc) and "resolve" in str(exc):
            return {"count": 0, "items": [], "hint": "The IdentityAccountInfo table is not available in this tenant "
                                                     "(identity inventory not enabled or no access)."}
        raise
