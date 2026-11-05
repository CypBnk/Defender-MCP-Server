"""Microsoft Defender Antivirus health from the Defender for Endpoint device health report
(GET /api/deviceavinfo, delegated Machine.Read). Snapshot of the current state, refreshed by Defender."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from .. import kql, runtime
from ..graph.odata import odata_str
from ..graph.paging import clamp
from ..resolve import resolve_device
from ..scopes import MDE_MACHINE_READ
from ..shaping import compact, pick
from .common import MaxItems, one_of
from .registry import read_tool

AvIssue = Literal["outdated_signatures", "outdated_engine", "outdated_platform", "not_active_mode",
                  "quick_scan_failed", "full_scan_failed"]
AV_MODES = {"0": "Active", "1": "Passive", "2": "Disabled", "3": "Other", "4": "EDRBlocked", "5": "PassiveAudit",
            "": "Other"}
# Server-side filters ($filter properties documented for /api/deviceavinfo); not_active_mode is filtered here.
_ISSUE_FILTERS = {
    "outdated_signatures": "avIsSignatureUpToDate eq 'False'",
    "outdated_engine": "avIsEngineUpToDate eq 'False'",
    "outdated_platform": "avIsPlatformUpToDate eq 'False'",
    "quick_scan_failed": "quickScanResult eq 'Failed'",
    "full_scan_failed": "fullScanResult eq 'Failed'",
    "not_active_mode": None,
}
_FIELDS = ("machineId", "computerDnsName", "osKind", "osPlatform", "osVersion", "avMode", "avSignatureVersion",
           "avSignatureUpdateTime", "avIsSignatureUpToDate", "avEngineVersion", "avIsEngineUpToDate",
           "avPlatformVersion", "avIsPlatformUpToDate", "quickScanResult", "quickScanTime", "fullScanResult",
           "fullScanTime", "rbacGroupName", "lastSeenTime", "dataRefreshTimestamp")
_PAGE = 10000   # documented maximum of $top


def _row(r: dict) -> dict:
    row = pick(r, _FIELDS)
    row["avMode"] = AV_MODES.get(str(r.get("avMode") if r.get("avMode") is not None else ""), str(r.get("avMode")))
    return compact(row)


def _age_days(value: Optional[str], now: datetime) -> Optional[float]:
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds() / 86400


def _count(rows: list, key: str) -> dict:
    out: dict = {}
    for r in rows:
        k = str(r.get(key) if r.get(key) not in (None, "") else "Unknown")
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def summarize(rows: list, now: Optional[datetime] = None) -> dict:
    now = now or datetime.now(timezone.utc)
    shaped = [_row(r) for r in rows]
    buckets = {"<1d": 0, "1-3d": 0, "3-7d": 0, ">7d": 0, "unknown": 0}
    for r in rows:
        age = _age_days(r.get("avSignatureUpdateTime"), now)
        if age is None:
            buckets["unknown"] += 1
        elif age < 1:
            buckets["<1d"] += 1
        elif age < 3:
            buckets["1-3d"] += 1
        elif age < 7:
            buckets["3-7d"] += 1
        else:
            buckets[">7d"] += 1
    stale = sum(1 for r in rows if (_age_days(r.get("lastSeenTime"), now) or 0) > 7)
    return {
        "devices": len(rows),
        "byMode": _count(shaped, "avMode"),
        "signaturesUpToDate": _count(rows, "avIsSignatureUpToDate"),
        "engineUpToDate": _count(rows, "avIsEngineUpToDate"),
        "platformUpToDate": _count(rows, "avIsPlatformUpToDate"),
        "signatureAge": buckets,
        "quickScan": _count(rows, "quickScanResult"),
        "fullScan": _count(rows, "fullScanResult"),
        "topPlatformVersions": dict(list(_count(rows, "avPlatformVersion").items())[:5]),
        "notSeenFor7Days": stale,
        "reportRefreshed": max((str(r.get("dataRefreshTimestamp")) for r in rows if r.get("dataRefreshTimestamp")),
                               default=None),
    }


@read_tool(scopes=(MDE_MACHINE_READ,), title="Antivirus health")
async def get_antivirus_health(
    issue: Annotated[Optional[AvIssue], "List the devices with this problem instead of the summary: outdated "
                                        "security intelligence (signatures), engine or platform, antivirus not in "
                                        "active mode (passive, EDR block, disabled), failed quick or full scan."] = None,
    device: Annotated[Optional[str], "One device (name, FQDN or Defender device ID): its antivirus details."] = None,
    os_kind: Annotated[Optional[Literal["windows", "mac", "linux"]], "Only devices with this OS."] = None,
    max_items: MaxItems = 50,
) -> dict:
    """Microsoft Defender Antivirus health from the Defender for Endpoint device health report: summary of
    antivirus mode (active, passive, EDR block, disabled), up-to-date status of security intelligence
    (signatures), engine and platform, signature age and last quick/full scan results; or the devices with one
    problem (e.g. outdated signatures, antivirus not active, failed scans); or the antivirus details of one
    device. The report is a snapshot that Defender refreshes periodically, not real time."""
    mde = runtime.mde()
    filters = []
    if os_kind:
        filters.append(f"osKind eq {odata_str(one_of(os_kind, ('windows', 'mac', 'linux'), 'os_kind'))}")
    if device:
        device_id = device.strip().lower() if kql.is_mde_device_id(device) else (await resolve_device(device))["DeviceId"]
        res = await mde.get("/api/deviceavinfo", params={"$filter": f"machineId eq {odata_str(device_id)}"})
        rows = res.get("value") or []
        if not rows:
            return {"deviceId": device_id, "hint": "No antivirus health data for this device (not Windows/macOS/Linux "
                                                   "with Defender Antivirus, or not reported yet)."}
        return {"device": _row(rows[0])}
    if issue:
        one_of(issue, _ISSUE_FILTERS, "issue")
        if _ISSUE_FILTERS[issue]:
            filters.append(_ISSUE_FILTERS[issue])
    params = {"$top": str(_PAGE)}
    if filters:
        params["$filter"] = " and ".join(filters)
    res = await mde.get("/api/deviceavinfo", params=params)
    rows = res.get("value") or []
    complete = not res.get("@odata.nextLink")
    if not issue:
        out = summarize(rows)
        out["complete"] = complete
        if not complete:
            out["hint"] = f"Summary of the first {len(rows)} devices; filter with os_kind for a complete picture."
        out["next_steps"] = "get_antivirus_health(issue=...) lists the affected devices; run_device_response can scan."
        return out
    if issue == "not_active_mode":
        rows = [r for r in rows if str(r.get("avMode")) != "0"]
    rows.sort(key=lambda r: str(r.get("avSignatureUpdateTime") or ""))   # oldest signatures first
    limit = clamp(max_items)
    items = [_row(r) for r in rows[:limit]]
    return {"issue": issue, "items": items, "count": len(items), "total": len(rows),
            "truncated": len(rows) > limit or not complete}
