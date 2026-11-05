"""Security posture: Microsoft Secure Score with improvement actions and attack simulation training."""
from __future__ import annotations

import re
from typing import Annotated, Literal, Optional

from .. import runtime
from ..graph.odata import clamp_int, guid, odata_str
from ..graph.paging import collect, get_paged
from ..scopes import ATTACK_SIMULATION_READ, SECURITY_EVENTS_READ
from ..shaping import compact, pick, truncate
from ..util import gather_sections
from .common import Cursor, MaxItems
from .registry import read_tool

_TAGS = re.compile(r"<[^>]+>")


def _text(html: Optional[str], limit: int) -> Optional[str]:
    if not html:
        return None
    return truncate(re.sub(r"\s+", " ", _TAGS.sub(" ", html)).strip(), limit)


def _pct(score: Optional[float], maximum: Optional[float]) -> Optional[float]:
    try:
        return round(100.0 * float(score) / float(maximum), 1) if maximum else None
    except (TypeError, ValueError):
        return None


@read_tool(scopes=(SECURITY_EVENTS_READ,), title="Microsoft Secure Score")
async def get_secure_score(
    history_days: Annotated[int, "Number of daily scores for the trend (1-90)."] = 30,
    include_improvements: Annotated[bool, "Also return the improvement actions with the largest possible gain."] = True,
    max_improvements: Annotated[int, "Number of improvement actions (1-50)."] = 15,
    category: Annotated[Optional[Literal["Identity", "Data", "Device", "Apps", "Infrastructure"]],
                        "Only improvement actions of this category."] = None,
) -> dict:
    """Microsoft Secure Score: current score and percentage, trend over the last days, comparison with similar
    organizations, score per category and the improvement actions with the largest possible gain (title,
    category, product, current/max points, user impact, implementation cost, remediation and portal link)."""
    days = clamp_int(history_days, 1, 90, "history_days")
    top = clamp_int(max_improvements, 1, 50, "max_improvements")
    graph = runtime.graph()
    tasks = {"scores": graph.get("/security/secureScores", params={"$top": str(days)})}
    if include_improvements:
        tasks["profiles"] = collect("/security/secureScoreControlProfiles", version="v1.0", limit=1000)
    ok, errors = await gather_sections(tasks)
    out: dict = {}
    scores = (ok.get("scores") or {}).get("value") or []
    scores.sort(key=lambda s: str(s.get("createdDateTime") or ""), reverse=True)
    if scores:
        latest = scores[0]
        out["current"] = compact({
            "date": latest.get("createdDateTime"), "score": latest.get("currentScore"),
            "maxScore": latest.get("maxScore"), "percentage": _pct(latest.get("currentScore"), latest.get("maxScore")),
            "licensedUsers": latest.get("licensedUserCount"), "activeUsers": latest.get("activeUserCount"),
            "enabledServices": latest.get("enabledServices"),
        })
        out["comparison"] = [compact({"basis": c.get("basis"), "basisValue": c.get("basisValue"),
                                      "averageScore": c.get("averageScore")})
                             for c in latest.get("averageComparativeScores") or []][:5]
        out["trend"] = [{"date": str(s.get("createdDateTime") or "")[:10], "score": s.get("currentScore"),
                         "percentage": _pct(s.get("currentScore"), s.get("maxScore"))} for s in scores]
        controls = latest.get("controlScores") or []
        profiles = {p.get("id"): p for p in ok.get("profiles", ([], True))[0]} if "profiles" in ok else {}
        by_category: dict = {}
        improvements = []
        for c in controls:
            name = c.get("controlName")
            profile = profiles.get(name) or {}
            cat = c.get("controlCategory") or profile.get("controlCategory") or "Other"
            entry = by_category.setdefault(cat, {"score": 0.0, "maxScore": 0.0})
            current = float(c.get("score") or 0)
            maximum = float(profile.get("maxScore") or 0)
            entry["score"] += current
            entry["maxScore"] += maximum
            if include_improvements and profile and not profile.get("deprecated") and maximum - current > 0:
                if category and cat.lower() != category.lower():
                    continue
                improvements.append(compact({
                    "id": name, "title": profile.get("title"), "category": cat, "service": profile.get("service"),
                    "currentScore": current, "maxScore": maximum, "possibleGain": round(maximum - current, 2),
                    "userImpact": profile.get("userImpact"), "implementationCost": profile.get("implementationCost"),
                    "tier": profile.get("tier"), "actionUrl": profile.get("actionUrl"),
                    "remediation": _text(profile.get("remediation"), 400),
                }))
        if profiles:
            out["byCategory"] = {k: {"score": round(v["score"], 1), "maxScore": round(v["maxScore"], 1),
                                     "percentage": _pct(v["score"], v["maxScore"])} for k, v in by_category.items()}
        if include_improvements:
            improvements.sort(key=lambda r: r.get("possibleGain") or 0, reverse=True)
            out["topImprovements"] = improvements[:top]
    elif "scores" in ok:
        out["hint"] = "No Secure Score data returned for this tenant."
    if errors:
        out["errors"] = errors
    return out


SimulationStatus = Literal["running", "scheduled", "succeeded", "failed", "canceled", "draft", "excluded"]


def _simulation_row(s: dict) -> dict:
    return compact({**pick(s, ("id", "displayName", "status", "attackTechnique", "attackType", "payloadDeliveryPlatform",
                                "launchDateTime", "completionDateTime", "durationInDays", "isAutomated")),
                    "createdBy": (s.get("createdBy") or {}).get("email")})


@read_tool(scopes=(ATTACK_SIMULATION_READ,), title="Attack simulation training")
async def list_attack_simulations(
    status: Annotated[Optional[SimulationStatus], "Only simulations with this status."] = None,
    simulation_id: Annotated[Optional[str], "Simulation ID: returns this simulation with its result overview."] = None,
    max_items: MaxItems = 50,
    cursor: Cursor = None,
) -> dict:
    """Attack simulation training campaigns (Defender for Office 365), newest launch first, or one campaign with
    its result overview (targeted users, compromise rate, simulation and training events)."""
    graph = runtime.graph()
    if simulation_id:
        sid = guid(simulation_id, "simulation_id")
        ok, errors = await gather_sections({
            "simulation": graph.get(f"/security/attackSimulation/simulations/{sid}"),
            "overview": graph.get(f"/security/attackSimulation/simulations/{sid}/report/overview"),
        })
        out: dict = {}
        if "simulation" in ok:
            out["simulation"] = _simulation_row(ok["simulation"])
            out["description"] = truncate(ok["simulation"].get("description"), 500)
        if "overview" in ok:
            out["overview"] = compact(ok["overview"], max_str=500)
        if errors:
            out["errors"] = errors
        return compact(out)
    if cursor:
        return await get_paged("", tool="list_attack_simulations", cursor=cursor, max_items=max_items,
                               transform=_simulation_row)
    params = {"$orderby": "launchDateTime desc"}
    if status:
        params["$filter"] = f"status eq {odata_str(status)}"
    return await get_paged("/security/attackSimulation/simulations", tool="list_attack_simulations", params=params,
                           version="v1.0", use_top=True, max_items=max_items, transform=_simulation_row)
