"""Indicator analysis with a verdict.

Covers analyze_url_entity of the Microsoft Sentinel MCP entity analyzer and extends it to domains, IP addresses and
file hashes. Instead of Security Copilot (Security Compute Units) it combines, in one call, Microsoft Threat
Intelligence, the organization's own threat intelligence (ThreatIntelIndicators) and watchlists in the Sentinel /
ISOC workspace, and the indicator's activity in the organization (hunt_ioc), and derives a transparent rule-based
assessment. Every source is optional: what is not available is listed, the rest still counts."""
from __future__ import annotations

import re
from typing import Annotated, Any, Optional
from urllib.parse import urlsplit

from .. import kql, workspaces
from ..errors import NotFoundError
from ..scopes import THREAT_HUNTING_READ, THREAT_INTEL_READ
from ..shaping import UNTRUSTED_NOTE
from ..util import gather_sections
from . import hunts, threat_intel
from .common import Days, Workspace
from .registry import read_tool

# A table that does not exist in the tenant (product, connector or workspace not deployed) - not a column error
# ('Failed to resolve scalar expression'), which would point to a bug and stays a real error.
_MISSING_TABLE = re.compile(r"resolve table|table or column expression|table '?\w+'? (could not be found|does not exist)",
                            re.IGNORECASE)
VERDICTS = {"high": "malicious", "medium": "suspicious", "low": "low risk (weak signals)",
            "none": "no known threat"}
BASIS = ("Rule-based summary of the listed signals (not an AI verdict): Microsoft and own threat intelligence, "
         "file reputation and alerts decide the level; activity in the organization shows the exposure; watchlist "
         "hits are context only (a watchlist can be an allow list).")


def num(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def unavailable(errors: dict) -> tuple[dict, list]:
    """Split section errors into real errors and data sources that are simply not there (table not found)."""
    real = {k: v for k, v in errors.items() if not _MISSING_TABLE.search(str(v))}
    return real, sorted(k for k in errors if k not in real)


class Assessment:
    def __init__(self) -> None:
        self.reasons: dict[str, list[str]] = {"high": [], "medium": [], "low": []}
        self.context: list[str] = []

    def add(self, level: str, reason: str) -> None:
        self.reasons[level].append(reason)

    def level(self) -> str:
        return next((lvl for lvl in ("high", "medium", "low") if self.reasons[lvl]), "none")

    def result(self, verdicts: dict, basis: str, **extra: Any) -> dict:
        lvl = self.level()
        out = {"level": lvl, "verdict": verdicts[lvl],
               "reasons": self.reasons["high"] + self.reasons["medium"] + self.reasons["low"]}
        if self.context:
            out["context"] = self.context
        out.update({k: v for k, v in extra.items() if v not in (None, [], {})})
        out["basis"] = basis
        return out


def _ti_match(kind: str, value: str) -> str:
    lit = kql.kql_str(value, "indicator", 2000)
    if kind == "url":
        host = urlsplit(value).hostname or ""
        return f"(ObservableValue =~ {lit} or (ObservableKey == 'domain-name:value' and ObservableValue =~ " \
               f"{kql.kql_str(host or value, 'indicator')}))"
    if kind == "domain":
        return f"(ObservableValue =~ {lit} or (ObservableKey == 'url:value' and ObservableValue has {lit}))"
    if kind == "ip" and ":" not in value:   # STIX IPv4 indicators can be CIDR ranges
        return f'(ObservableValue == {lit} or (ObservableValue contains "/" and ipv4_is_in_range({lit}, ObservableValue)))'
    return f"ObservableValue =~ {lit}"


async def _custom_ti(kind: str, value: str, workspace_id: Optional[str]) -> list:
    """Own threat intelligence (Sentinel / ISOC TI platform, STIX table ThreatIntelIndicators): latest version of
    each matching indicator; the table is republished every 7-10 days, so 30 days cover all live indicators."""
    return await kql.rows("\n".join([
        "ThreatIntelIndicators", "| where TimeGenerated > ago(30d)", f"| where {_ti_match(kind, value)}",
        "| summarize arg_max(TimeGenerated, *) by Id", "| where IsDeleted == false",
        "| extend Active = IsActive == true and Revoked != true and (isnull(ValidUntil) or ValidUntil > now())",
        "| project Id, ObservableKey, ObservableValue, Active, Confidence, ValidFrom, ValidUntil, SourceSystem, Tags, "
        "Name = tostring(Data.name), Description = tostring(Data.description), "
        "IndicatorTypes = tostring(Data.indicator_types)",
        "| order by Active desc, Confidence desc", "| take 20"]), workspace_id=workspace_id)


async def _watchlists(value: str, workspace_id: Optional[str]) -> list:
    lit = kql.kql_str(value, "indicator", 2000)
    return await kql.rows("\n".join([
        "Watchlist", "| where TimeGenerated > ago(30d)", "| where _DTItemType == 'watchlist-item'",
        "| summarize arg_max(_DTTimestamp, *) by _DTItemId",
        '| where _DTItemStatus !startswith "Delete" and (isnull(TimeToLive) or TimeToLive > now())',
        f"| where SearchKey =~ {lit} or tostring(WatchlistItem) has {lit}",
        "| project WatchlistAlias, WatchlistName, WatchlistCategory, SearchKey, WatchlistItem, LastUpdatedTimeUTC",
        "| take 20"]), workspace_id=workspace_id)


async def _microsoft_ti(kind: str, value: str) -> dict:
    host = value if kind in ("ip", "domain") else urlsplit(value).hostname or value
    try:
        return await threat_intel._host(host)
    except NotFoundError:
        return {"host": host, "known": False}


def _assess(kind: str, ms: Optional[dict], custom: Optional[list], org: Optional[dict],
            watch: Optional[list]) -> dict:
    a = Assessment()
    rep = (ms or {}).get("reputation") or {}
    cls = str(rep.get("classification") or "").lower()
    if cls == "malicious":
        a.add("high", f"Microsoft Threat Intelligence: malicious (score {rep.get('score')}).")
    elif cls == "suspicious":
        a.add("medium", f"Microsoft Threat Intelligence: suspicious (score {rep.get('score')}).")
    elif cls:
        a.context.append(f"Microsoft Threat Intelligence: {cls} (score {rep.get('score')}).")
    for ind in custom or []:
        label = f"{ind.get('SourceSystem') or 'own TI'} ({ind.get('ObservableKey')}, confidence {ind.get('Confidence')})"
        if ind.get("Active") and num(ind.get("Confidence")) >= 50:
            a.add("high", f"Active indicator in your threat intelligence: {label}.")
        elif ind.get("Active"):
            a.add("medium", f"Active low-confidence indicator in your threat intelligence: {label}.")
        else:
            a.add("low", f"Expired or inactive indicator in your threat intelligence: {label}.")
    org = org or {}
    profile = org.get("fileProfile") or {}
    if profile.get("ThreatName"):
        a.add("high", f"File reputation: detected as {profile['ThreatName']}.")
    elif profile and num(profile.get("GlobalPrevalence")) < 50 and profile.get("SignatureState") != "SignedValid":
        a.add("low", f"Rare, not validly signed file (global prevalence {profile.get('GlobalPrevalence')}).")
    alerts = org.get("alerts") or []
    severities = {str(x.get("Severity") or "").lower() for x in alerts}
    if "high" in severities:
        a.add("high", f"{len(alerts)} alert(s) in your organization contain it, at least one of high severity.")
    elif alerts:
        a.add("medium", f"{len(alerts)} alert(s) in your organization contain it.")
    for hit in watch or []:
        a.context.append(f"On watchlist '{hit.get('WatchlistAlias') or hit.get('WatchlistName')}'.")
    sources = {str(r.get("Source")): int(num(r.get("Hits"))) for r in org.get("bySource") or []}
    exposure = {"totalHits": org.get("totalHits"), "devices": (org.get("devices") or {}).get("count"),
                "bySource": sources or None}
    return a.result(VERDICTS, BASIS, exposure={k: v for k, v in exposure.items() if v})


@read_tool(scopes=(THREAT_HUNTING_READ, THREAT_INTEL_READ), title="Analyze indicator (verdict)")
async def analyze_indicator(
    indicator: Annotated[str, "URL, domain, IP address or file hash (SHA256, SHA1, MD5)."],
    indicator_type: Annotated[hunts.IndicatorType, "Type of the indicator; auto detects it."] = "auto",
    days: Days = 30,
    workspace: Workspace = None,
) -> dict:
    """Verdict for a URL, domain, IP address or file hash (like the Sentinel entity analyzer for URLs, without
    Security Compute Units): Microsoft Threat Intelligence reputation, your own threat intelligence indicators and
    watchlists (Sentinel / ISOC workspace), file reputation, alerts that contain it and its activity in your
    organization (devices, emails, clicks, sign-ins). Returns assessment.level (high/medium/low/none) and verdict
    (malicious/suspicious/...) with the reasons, the exposure in the organization and the details per source.
    Use hunt_ioc for the full event list and manage_indicator to block it."""
    kind, value = hunts._detect(indicator, indicator_type)
    d = kql.days(days)
    wid = workspaces.resolve(workspace)
    tasks: dict = {
        "organization": hunts.hunt_ioc(value, kind, d, max_items=5),
        "ownThreatIntel": _custom_ti(kind, value, wid),
        "watchlists": _watchlists(value, wid),
    }
    if kind in ("ip", "domain", "url"):
        tasks["microsoftThreatIntel"] = _microsoft_ti(kind, value)
    ok, errors = await gather_sections(tasks)
    errors, missing = unavailable(errors)
    org = ok.get("organization") or {}
    out: dict = {"indicator": value, "type": kind, "days": d,
                 "assessment": _assess(kind, ok.get("microsoftThreatIntel"), ok.get("ownThreatIntel"), org,
                                       ok.get("watchlists"))}
    if "microsoftThreatIntel" in ok:
        out["microsoftThreatIntel"] = ok["microsoftThreatIntel"]
    if "ownThreatIntel" in ok:
        out["ownThreatIntel"] = kql.shape_rows(ok["ownThreatIntel"], limit=20, max_str=400)[0]
    if "watchlists" in ok:
        out["watchlists"] = kql.shape_rows(ok["watchlists"], limit=20, max_str=400)[0]
    if org:
        out["organization"] = {k: org[k] for k in ("totalHits", "bySource", "devices", "alerts", "fileProfile",
                                                     "alsoSearchedSha1", "errors") if k in org}
    if missing:
        out["notAvailable"] = missing
    if errors:
        out["errors"] = errors
    if wid:
        out["workspaceId"] = wid
    out["next_steps"] = ("hunt_ioc for every event, get_alert for the alerts, manage_indicator to block or allow it, "
                         "run_device_response on affected devices.")
    out["note"] = UNTRUSTED_NOTE
    return out
