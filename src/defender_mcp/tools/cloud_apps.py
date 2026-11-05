"""Defender for Cloud Apps - Cloud Discovery (Graph beta, CloudApp-Discovery.Read.All): evaluation of the discovery
report. Data sources (streams), a summary of the discovered apps for a period (risk, tags, categories, traffic,
unsanctioned apps still in use, risky untagged apps to review, AI apps), filtered app lists and one app in detail
(security, compliance and GDPR attributes, users, IP addresses, devices).

The risk field is 'riskScore'; categories are the Graph
enum (cloudStorage, generativeAi, mcpServer, ...), filtered here because aggregatedAppsDetails has no $orderby and the
documented filter examples disagree with the schema. Setting Sanctioned / Unsanctioned: sanction_cloud_apps."""
from __future__ import annotations

import re
from collections import Counter
from typing import Annotated, Any, Literal, Optional

from .. import runtime
from ..errors import GraphError, InputError, NotFoundError
from ..graph.odata import clamp_int, key
from ..graph.paging import clamp, collect, paginate_list, read_list_cursor, split_next_link
from ..scopes import CLOUDAPP_DISCOVERY_READ
from ..shaping import compact, pick
from ..util import gather_sections
from .common import Cursor, MaxItems, one_of
from .registry import read_tool

TOOL = "get_cloud_app_discovery"
STREAMS = "/security/dataDiscovery/cloudAppDiscovery/uploadedStreams"
PERIODS = ("P7D", "P30D", "P90D")
Period = Literal["P7D", "P30D", "P90D"]
View = Literal["summary", "apps", "app", "streams"]
SortBy = Literal["users", "upload", "traffic", "transactions", "risk", "last_seen", "name"]
_SORTS = ("users", "upload", "traffic", "transactions", "risk", "last_seen", "name")
_MDE_PROVIDER = "microsoftdefenderforendpoint"
_STREAM_FIELDS = ("id", "displayName", "logDataProvider", "isSnapshotReport", "lastDataReceivedDateTime",
                  "createdDateTime", "lastModifiedDateTime", "logFileCount", "receiverProtocol", "supportedEntityTypes",
                  "supportedTrafficTypes", "anonymizeUserData", "anonymizeMachineData", "description")
_MAX_APP_PAGES = 40
_PAGE_SIZE = "500"
_TOP = 10
_REVIEW_THRESHOLD = 6
# Bands used by this tool (the score is 0-10, 10 = lowest risk); Microsoft documents no fixed bands.
_BANDS = (("high", 0, 3), ("medium", 4, 6), ("low", 7, 10))
BAND_NOTE = "risk score 0-10 (10 = lowest risk); bands of this tool: 0-3 high, 4-6 medium, 7-10 low"

# Graph enum microsoft.graph.security.appCategory (aiModelProvider, mcpServer, clientAiApp need the Prefer header
# include-unknown-enum-members, which the Graph client always sends).
_CATEGORIES = ("security collaboration hostingServices onlineMeetings newsAndEntertainment eCommerce education "
               "cloudStorage marketing operationsManagement health advertising productivity accountingAndFinance "
               "contentManagement contentSharing businessManagement communications dataAnalytics businessIntelligence "
               "webemail codeHosting webAnalytics socialNetwork crm forums humanResourceManagement "
               "transportationAndTravel productDesign sales cloudComputingPlatform projectManagement "
               "personalInstantMessaging developmentTools itServices supplyChainAndLogistics propertyManagement "
               "customerSupport internetOfThings vendorManagementSystems websiteMonitoring generativeAi "
               "aiModelProvider mcpServer clientAiApp").split()
AI_CATEGORIES = ("generativeAi", "aiModelProvider", "mcpServer", "clientAiApp")


def _norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


_CAT_BY_NORM = {_norm(c): c for c in _CATEGORIES}
_CAT_ALIASES = {"webmail": "webemail", "email": "webemail", "genai": "generativeAi",
                "mcp": "mcpServer", "mcpservers": "mcpServer", "aimcpserver": "mcpServer", "llm": "aiModelProvider",
                "aimodel": "aiModelProvider", "modelprovider": "aiModelProvider", "aiclient": "clientAiApp",
                "storage": "cloudStorage", "filesharing": "cloudStorage", "hosting": "hostingServices",
                "hr": "humanResourceManagement", "humanresources": "humanResourceManagement", "iot": "internetOfThings",
                "messaging": "personalInstantMessaging", "instantmessaging": "personalInstantMessaging",
                "vendormanagementsystem": "vendorManagementSystems", "it": "itServices", "itservice": "itServices",
                "meetings": "onlineMeetings", "social": "socialNetwork", "socialnetworks": "socialNetwork"}
_AI_NORM = {_norm(c) for c in AI_CATEGORIES}


def categories(value: str) -> tuple[str, ...]:
    """Graph category enum value(s) for a user term ('Cloud storage', 'generative AI', 'ai' = all AI categories)."""
    n = _norm(value)
    if n in {"ai", "ki", "allai", "aiapps", "kiapps", "shadowai"}:
        return AI_CATEGORIES
    for candidate in (n, n.removeprefix("ai") if n.startswith("ai") and len(n) > 2 else n):
        if candidate in _CAT_BY_NORM:
            return (_CAT_BY_NORM[candidate],)
        if candidate in _CAT_ALIASES:
            return (_CAT_ALIASES[candidate],)
    raise InputError(f"Unknown category {str(value)[:60]!r}. Examples: cloudStorage, webemail, generativeAi, mcpServer, "
                     "aiModelProvider, collaboration, socialNetwork, codeHosting; 'ai' = all AI categories.")


def _num(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def score(app: Optional[dict]) -> Optional[int]:
    """Risk score 0-10 (Graph field riskScore)."""
    if not app:
        return None
    value = app.get("riskScore")
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def band(value: Optional[int]) -> str:
    if value is None:
        return "unscored"
    for name, lo, hi in _BANDS:
        if lo <= value <= hi:
            return name
    return "unscored"


def tags_of(app: Optional[dict]) -> list[str]:
    return [str(t) for t in ((app or {}).get("tags") or []) if t]


def has_tag(app: Optional[dict], tag: str) -> bool:
    wanted = tag.strip().lower()
    have = {t.lower() for t in tags_of(app)}
    if wanted in {"untagged", "none", "notagged"}:
        return not have
    return wanted in have


def brief(app: dict) -> dict:
    return compact({"id": str(app.get("id")), "name": app.get("displayName"), "category": app.get("category"),
                    "riskScore": score(app), "tags": tags_of(app) or None, "users": app.get("userCount"),
                    "uploadBytes": app.get("uploadNetworkTrafficInBytes"), "lastSeen": app.get("lastSeenDateTime")})


def _full(app: dict, domains: int = 5) -> dict:
    row = brief(app)
    row.update(compact({"ipAddresses": app.get("ipAddressCount"), "devices": app.get("deviceCount"),
                        "transactions": app.get("transactionCount"),
                        "downloadBytes": app.get("downloadNetworkTrafficInBytes"),
                        "domains": list(app.get("domains") or [])[:domains] or None}))
    return row


def apps_path(stream_id: str, period: str) -> str:
    return f"{STREAMS}/{stream_id}/microsoft.graph.security.aggregatedAppsDetails(period=duration'{period}')"


async def list_streams() -> list[dict]:
    items, _ = await collect(STREAMS, version="beta", limit=200)    # the method supports no OData parameters
    return [s for s in items if isinstance(s, dict) and s.get("id")]


async def resolve_stream(stream_id: Optional[str]) -> tuple[str, dict, list]:
    """(stream ID, stream info, other streams). Default: the Defender for Endpoint stream, else the most recently
    active one."""
    if stream_id:
        sid = key(stream_id, "stream_id")
        return sid, {"id": sid}, []
    streams = await list_streams()
    if not streams:
        raise NotFoundError("No Cloud Discovery data source found. Turn on the Defender for Endpoint integration in "
                            "Defender for Cloud Apps or add a log collector / snapshot report, or pass stream_id.")
    mde = [s for s in streams if str(s.get("logDataProvider") or "").lower() == _MDE_PROVIDER]
    chosen = mde[0] if mde else max(streams, key=lambda s: str(s.get("lastDataReceivedDateTime") or ""))
    info = compact(pick(chosen, ("id", "displayName", "logDataProvider", "isSnapshotReport", "lastDataReceivedDateTime",
                                 "anonymizeUserData")))
    others = [compact(pick(s, ("id", "displayName", "logDataProvider", "lastDataReceivedDateTime")))
              for s in streams if s is not chosen]
    return key(str(chosen["id"]), "stream_id"), info, others


async def all_apps(stream_id: str, period: str) -> tuple[list, bool]:
    """All discovered apps of a stream and period, up to MCP_SCAN_LIMIT. Returns (apps, complete). Pages follow
    @odata.nextLink; without it $skip is used until a short or empty page (or a repeated page, if $skip is ignored)."""
    graph = runtime.graph()
    path = apps_path(stream_id, period)
    limit = runtime.settings().scan_limit
    params: Optional[dict] = {"$top": _PAGE_SIZE}
    try:
        resp = await graph.get(path, version="beta", params=params)
    except GraphError as exc:
        if exc.status != 400:
            raise
        params = None                       # $top not accepted: server-side page size
        resp = await graph.get(path, version="beta")
    top_used = params is not None
    items: list = []
    first_ids: set = set()
    first_size: Optional[int] = None
    via_link = False
    for _ in range(_MAX_APP_PAGES):
        page = (resp.get("value") or []) if isinstance(resp, dict) else []
        if not page:
            return items, True
        marker = str(page[0].get("id"))
        if marker in first_ids:             # the service repeated a page ($skip ignored or a looping nextLink):
            # complete only if everything fitted into the first page of the requested size
            return items, bool(top_used and not via_link and first_size is not None and first_size < int(_PAGE_SIZE))
        first_ids.add(marker)
        items.extend(page)
        if len(items) >= limit:
            return items[:limit], False
        link = resp.get("@odata.nextLink") if isinstance(resp, dict) else None
        if link:
            via_link = True
            path, params, _version = split_next_link(link)
        elif via_link:
            return items, True
        else:
            first_size = first_size or len(page)
            if len(page) < first_size:
                return items, True
            params = {**(params or {}), "$skip": str(len(items))}
        resp = await graph.get(path, version="beta", params=params or None)
    return items, False


def summarize(apps: list, threshold: int) -> dict:
    by_tag: Counter = Counter()
    by_band: Counter = Counter()
    cats: dict = {}
    upload = download = transactions = 0
    for app in apps:
        for tag in tags_of(app) or ["untagged"]:
            by_tag[tag] += 1
        by_band[band(score(app))] += 1
        cat = cats.setdefault(str(app.get("category") or "unknown"), {"apps": 0, "users": 0, "uploadBytes": 0})
        cat["apps"] += 1
        cat["users"] += _num(app.get("userCount"))
        cat["uploadBytes"] += _num(app.get("uploadNetworkTrafficInBytes"))
        upload += _num(app.get("uploadNetworkTrafficInBytes"))
        download += _num(app.get("downloadNetworkTrafficInBytes"))
        transactions += _num(app.get("transactionCount"))

    def by_users(a: dict) -> tuple:
        return _num(a.get("userCount")), _num(a.get("uploadNetworkTrafficInBytes"))

    def top(rows: list, sort_key: Any) -> list:
        return [brief(a) for a in sorted(rows, key=sort_key, reverse=True)[:_TOP]]

    unsanctioned = [a for a in apps if has_tag(a, "Unsanctioned")
                    and (_num(a.get("userCount")) > 0 or _num(a.get("transactionCount")) > 0)]
    review = [a for a in apps if not tags_of(a) and score(a) is not None and score(a) <= threshold]
    ai_apps = [a for a in apps if _norm(a.get("category")) in _AI_NORM]
    top_categories = sorted(({"category": c, **v} for c, v in cats.items()), key=lambda c: (c["apps"], c["users"]),
                            reverse=True)[:_TOP]
    return {
        "apps": len(apps),
        "traffic": {"uploadBytes": upload, "downloadBytes": download, "transactions": transactions},
        "byTag": dict(by_tag.most_common()),
        "byRiskBand": {name: by_band.get(name, 0) for name in ("high", "medium", "low", "unscored")},
        "riskBands": BAND_NOTE,
        "topCategories": top_categories,
        "unsanctionedInUse": {"count": len(unsanctioned), "top": top(unsanctioned, by_users),
                              "meaning": "apps tagged Unsanctioned that still show users or transactions in the period"},
        "reviewCandidates": {"count": len(review), "maxRiskScore": threshold, "top": top(review, by_users),
                             "meaning": "untagged apps with a risk score up to maxRiskScore, most used first: "
                                        "decide Sanctioned or Unsanctioned"},
        "aiApps": {"count": len(ai_apps), "top": top(ai_apps, by_users),
                   "meaning": "categories generativeAi, aiModelProvider, mcpServer, clientAiApp"},
        "topByUsers": top(apps, by_users),
        "topByUpload": top(apps, lambda a: _num(a.get("uploadNetworkTrafficInBytes"))),
    }


def _sort_key(sort_by: str) -> tuple[Any, bool]:
    if sort_by == "upload":
        return (lambda a: _num(a.get("uploadNetworkTrafficInBytes"))), True
    if sort_by == "traffic":
        return (lambda a: _num(a.get("uploadNetworkTrafficInBytes")) + _num(a.get("downloadNetworkTrafficInBytes"))), True
    if sort_by == "transactions":
        return (lambda a: _num(a.get("transactionCount"))), True
    if sort_by == "risk":   # riskiest first, unscored last
        return (lambda a: (score(a) is None, score(a) if score(a) is not None else 0, -_num(a.get("userCount")))), False
    if sort_by == "last_seen":
        return (lambda a: str(a.get("lastSeenDateTime") or "")), True
    if sort_by == "name":
        return (lambda a: str(a.get("displayName") or "").lower()), False
    return (lambda a: (_num(a.get("userCount")), _num(a.get("uploadNetworkTrafficInBytes")))), True


_STATE_TRUE, _STATE_FALSE = "true", "false"
_GENERAL = ("vendor", "headquarters", "dataCenter", "founded", "holding", "hostingCompany", "domainRegistrationDateTime",
            "latestBreachDateTime", "logonUrls")
_SECURITY = ("isMultiFactorAuthentication", "isSupportsSaml", "dataAtRestEncryptionMethod", "encryptionProtocol",
             "isAdminAuditTrail", "isUserAuditTrail", "isDataAuditTrail", "isIpAddressRestriction", "isUserRolesSupport",
             "isRequiresUserAuthentication", "isPasswordPolicy", "isRememberPassword", "isFileSharing",
             "isUserCanUploadData", "dataTypes", "isDataClassification", "isDataOwnership", "isPenetrationTesting",
             "isDisasterRecoveryPlan", "isTrustedCertificate", "isValidCertificateName")
_LEGAL = ("isDmca", "dataRetentionPolicy", "gdprReadinessStatement")
_CERTS = {"isSoc1Compliant": "SOC 1", "isSoc2Compliant": "SOC 2", "isSoc3Compliant": "SOC 3",
          "isIso27001Compliant": "ISO 27001", "isIso27017Compliant": "ISO 27017", "isIso27018Compliant": "ISO 27018",
          "isHipaaCompliant": "HIPAA", "isHitrustCsfCompliant": "HITRUST CSF", "isFinraCompliant": "FINRA",
          "isFismaCompliant": "FISMA", "isGaapCompliant": "GAAP", "isGlbaCompliant": "GLBA",
          "isIsae3402Compliant": "ISAE 3402", "isSsae16Compliant": "SSAE 16", "isSoxCompliant": "SOX",
          "isSp80053Compliant": "NIST SP 800-53", "isItarCompliant": "ITAR", "isCobitCompliant": "COBIT",
          "isCoppaCompliant": "COPPA", "isFerpaCompliant": "FERPA", "isFfiecCompliant": "FFIEC",
          "isPrivacyShieldCompliant": "Privacy Shield"}
_LEVELS = (("pciDssVersion", "PCI DSS"), ("fedRampLevel", "FedRAMP"), ("csaStarLevel", "CSA STAR"))
_UNKNOWN = {"", "unknown", "unknownfuturevalue"}
_NO_LEVEL = _UNKNOWN | {"notsupported", "notapplicable"}


def _known(value: Any) -> bool:
    """Present and not unknown; 'notSupported' stays visible (e.g. no TLS or no encryption at rest)."""
    return value is not None and str(value).strip().lower() not in _UNKNOWN


def _level(value: Any) -> bool:
    """A certification level that is actually held (not notSupported / notApplicable)."""
    return value is not None and str(value).strip().lower() not in _NO_LEVEL


def _state(value: Any) -> Optional[bool]:
    s = str(value).strip().lower() if value is not None else ""
    return True if s == _STATE_TRUE else False if s == _STATE_FALSE else None


def _attr(name: str) -> str:
    return name[2].lower() + name[3:] if name.startswith("is") and len(name) > 3 else name


def app_info(info: Optional[dict]) -> dict:
    """Compact risk attributes: general facts, security features, certifications, GDPR and legal."""
    if not isinstance(info, dict):
        return {}
    general = {k: info[k] for k in _GENERAL if _known(info.get(k))}
    security = {_attr(k): (_state(info[k]) if k.startswith("is") else info[k]) for k in _SECURITY if _known(info.get(k))}
    certs = [label for k, label in _CERTS.items() if _state(info.get(k)) is True]
    certs += [f"{label} ({info[k]})" for k, label in _LEVELS if _level(info.get(k))]
    gdpr_keys = [k for k in info if k.startswith("isGdpr")]
    headers = [k for k in info if k.startswith("isHttpSecurityHeaders")]
    legal = {_attr(k): (_state(info[k]) if k.startswith("is") else info[k]) for k in _LEGAL if _known(info.get(k))}
    return compact({
        "general": general, "security": security, "certifications": certs,
        "gdpr": {"yes": sum(_state(info[k]) is True for k in gdpr_keys),
                 "no": [_attr(k).removeprefix("gdpr") for k in gdpr_keys if _state(info[k]) is False],
                 "unknown": sum(_state(info[k]) is None for k in gdpr_keys)} if gdpr_keys else None,
        "httpSecurityHeaders": (f"{sum(_state(info[k]) is True for k in headers)} of {len(headers)} present"
                                if headers else None),
        "legal": legal,
    })


async def _streams_view(max_items: Optional[int]) -> dict:
    streams = await list_streams()
    rows = []
    for s in streams:
        row = compact(pick(s, _STREAM_FIELDS))
        if str(s.get("logDataProvider") or "").lower() == _MDE_PROVIDER:
            row["isDefenderForEndpoint"] = True
        rows.append(row)
    limit = clamp(max_items)
    return {"count": min(len(rows), limit), "total": len(rows), "items": rows[:limit],
            "hint": "Without stream_id the other views use the Defender for Endpoint stream (else the most recently "
                    "active one)."}


async def _summary_view(stream_id: Optional[str], period: str, max_risk_score: Optional[int]) -> dict:
    threshold = _REVIEW_THRESHOLD if max_risk_score is None else clamp_int(max_risk_score, 0, 10, "max_risk_score")
    sid, stream, others = await resolve_stream(stream_id)
    apps, complete = await all_apps(sid, period)
    out: dict = {"view": "summary", "stream": stream, "period": period, **summarize(apps, threshold)}
    if others:
        out["otherStreams"] = others
    if not apps:
        out["note"] = "No apps discovered in this stream and period. Try period 'P90D' or another stream_id."
    if not complete:
        out["incomplete"] = True
        out["note"] = (f"Only {len(apps)} apps could be read (MCP_SCAN_LIMIT or paging of the service): totals may "
                       "be incomplete.")
    out["next_steps"] = ("view='app' with app_id: risk attributes, users, IP addresses, devices; view='apps' with "
                         "category, tag, max_risk_score, sort_by for lists; sanction_cloud_apps sets Sanctioned / "
                         "Unsanctioned.")
    return out


async def _apps_view(*, stream_id: Optional[str], period: str, category: Optional[str], tag: Optional[str],
                     max_risk_score: Optional[int], name_contains: Optional[str], sort_by: str,
                     max_items: Optional[int], offset: int) -> dict:
    sort_by = one_of(sort_by, _SORTS, "sort_by")
    cats = {_norm(c) for c in categories(category)} if category else None
    max_score = clamp_int(max_risk_score, 0, 10, "max_risk_score") if max_risk_score is not None else None
    tag = str(tag).strip()[:100] if tag else None
    needle = str(name_contains).strip().lower()[:200] if name_contains else None
    sid, stream, _others = await resolve_stream(stream_id)
    apps, complete = await all_apps(sid, period)
    rows = []
    for app in apps:
        if cats is not None and _norm(app.get("category")) not in cats:
            continue
        if tag and not has_tag(app, tag):
            continue
        if max_score is not None and (score(app) is None or score(app) > max_score):
            continue
        if needle and needle not in str(app.get("displayName") or "").lower() \
                and not any(needle in str(d).lower() for d in (app.get("domains") or [])):
            continue
        rows.append(app)
    sort_key, reverse = _sort_key(sort_by)
    rows.sort(key=sort_key, reverse=reverse)
    args = {"stream_id": sid, "period": period, "category": category, "tag": tag, "max_risk_score": max_score,
            "name_contains": name_contains, "sort_by": sort_by}
    page = paginate_list([_full(a) for a in rows], tool=TOOL, args=args, offset=offset, max_items=max_items,
                         complete=complete)
    return {"view": "apps", "stream": stream, "period": period, "sortBy": sort_by, **page}


async def _app_view(stream_id: Optional[str], app_id: str, period: str, max_items: Optional[int]) -> dict:
    sid, stream, _others = await resolve_stream(stream_id)
    base = f"{apps_path(sid, period)}/{app_id}"
    graph = runtime.graph()
    try:
        app = await graph.get(base, version="beta")
    except GraphError as exc:
        if exc.status in (400, 404):
            raise NotFoundError(f"App {app_id} was not seen in stream {sid} in period {period}. Check the ID with "
                                "view 'apps', use period 'P90D' or another stream_id.") from None
        raise
    if not isinstance(app, dict):
        app = {}
    limit = clamp(max_items)
    ok, errors = await gather_sections({
        "appInfo": graph.get(f"{base}/appInfo", version="beta"),
        "users": collect(f"{base}/users", version="beta", limit=limit),
        "ipAddresses": collect(f"{base}/ipAddresses", version="beta", limit=limit),
        "devices": collect(f"{base}/devices", version="beta", limit=limit),
    })
    if "devices" in errors and not app.get("deviceCount"):
        errors.pop("devices")               # only Defender for Endpoint streams know devices

    def listing(section: str, field: str) -> Optional[dict]:
        if section not in ok:
            return None
        items, complete = ok[section]
        values = [str(i.get(field)) for i in items if isinstance(i, dict) and i.get(field)]
        return {"count": len(values), "complete": complete, "items": values}

    out = compact({
        "view": "app", "stream": stream, "period": period,
        "app": _full(app, domains=20), "riskBand": band(score(app)), "riskBands": BAND_NOTE,
        "appInfo": app_info(ok.get("appInfo")),
        "users": listing("users", "userIdentifier"),
        "ipAddresses": listing("ipAddresses", "ipAddress"),
        "devices": listing("devices", "name"),
    })
    if errors:
        out["errors"] = errors
    out["next_steps"] = (f"sanction_cloud_apps(app_ids=['{app_id}'], status='Sanctioned' or 'Unsanctioned') sets the "
                         "tag; investigate_user for one of the users.")
    return out


@read_tool(scopes=(CLOUDAPP_DISCOVERY_READ,), title="Cloud Discovery")
async def get_cloud_app_discovery(
    view: Annotated[Optional[View], "summary = evaluation of the discovery report (default); apps = filtered, sorted "
                                    "app list; app = one app in detail (needs app_id); streams = data sources."] = None,
    stream_id: Annotated[Optional[str], "Data source (stream) ID. Default: the Defender for Endpoint stream, else the "
                                        "most recently active one."] = None,
    app_id: Annotated[Optional[str], "App ID from summary or apps (view 'app')."] = None,
    period: Annotated[Period, "Last 7, 30 or 90 days."] = "P30D",
    category: Annotated[Optional[str], "apps: category, e.g. 'cloud storage', 'webmail', 'generative AI', "
                                       "'MCP server' or 'ai' for all AI categories."] = None,
    tag: Annotated[Optional[str], "apps: Sanctioned, Unsanctioned, Monitored, untagged or a custom tag."] = None,
    max_risk_score: Annotated[Optional[int], "apps: only apps with a risk score up to this value (0-10, 10 = lowest "
                                             "risk); summary: threshold for review candidates (default 6)."] = None,
    name_contains: Annotated[Optional[str], "apps: part of the app name or of a domain."] = None,
    sort_by: Annotated[SortBy, "apps: sort order (risk = riskiest first)."] = "users",
    max_items: MaxItems = 50,
    cursor: Cursor = None,
) -> dict:
    """Defender for Cloud Apps Cloud Discovery (shadow IT). summary: evaluation of the discovery report for a period -
    apps by risk band, tag (Sanctioned, Unsanctioned, Monitored, untagged) and category, traffic, unsanctioned apps still
    in use, risky untagged apps to review, generative AI and MCP apps, top apps by users and by upload. apps: filtered,
    sorted list. app: one app with security, compliance and GDPR attributes, users, IP addresses and devices. streams:
    data sources (Defender for Endpoint, firewall and proxy logs). Risk score 0-10, 10 = lowest risk. Tags are set with
    sanction_cloud_apps."""
    if cursor:
        args, offset = read_list_cursor(cursor, TOOL)
        return await _apps_view(**args, max_items=max_items, offset=offset)
    chosen = one_of(view or ("app" if app_id else "summary"), ("summary", "apps", "app", "streams"), "view")
    if chosen == "streams":
        return await _streams_view(max_items)
    p = one_of(period, PERIODS, "period")
    if chosen == "app":
        if not app_id:
            raise InputError("view 'app' needs app_id (from view 'summary' or 'apps').")
        return await _app_view(stream_id, key(app_id, "app_id"), p, max_items)
    if chosen == "summary":
        return await _summary_view(stream_id, p, max_risk_score)
    return await _apps_view(stream_id=stream_id, period=p, category=category, tag=tag, max_risk_score=max_risk_score,
                            name_contains=name_contains, sort_by=sort_by, max_items=max_items, offset=0)
