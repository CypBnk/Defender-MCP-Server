"""Microsoft Threat Intelligence via Microsoft Graph. Available to every tenant with a Defender XDR
or Sentinel license, no separate license. Reputation of hosts (IP, domain, URL host), CVE intelligence and a
keyword search in threat articles and threat actor / tool profiles."""
from __future__ import annotations

import re
from typing import Annotated, Any, Optional
from urllib.parse import urlsplit

from .. import kql, runtime
from ..errors import DefenderToolError, GraphError, InputError, NotFoundError
from ..graph.odata import clamp_int
from ..scopes import THREAT_INTEL_READ
from ..shaping import UNTRUSTED_NOTE, compact, pick, truncate
from ..util import gather_sections
from .registry import read_tool

_TERM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
_HASH = re.compile(r"^[0-9a-fA-F]+$")
_BASE = "/security/threatIntelligence"


def _content(value: Any, limit: int) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("content")
    return truncate(value, limit) if value else None


def _links(items: Any, limit: int = 5) -> list:
    return [compact(pick(i, ("name", "url"))) for i in (items or [])[:limit] if isinstance(i, dict)]


def _host_of(indicator: str) -> tuple[str, str]:
    """('ip' | 'domain', host) for an IP address, a domain or the host of a URL."""
    v = indicator.strip()
    if "://" in v:
        host = urlsplit(kql.url(v)).hostname or ""
        if not host:
            raise InputError("The URL has no host name.")
        v = host
    try:
        return "ip", kql.ip_address(v)
    except InputError:
        return "domain", kql.domain(v)


async def _vulnerability(cve: str) -> dict:
    try:
        v = await runtime.graph().get(f"{_BASE}/vulnerabilities/{cve}")
    except GraphError as exc:
        if exc.status == 404:
            raise NotFoundError(f"{cve} is not in Microsoft Threat Intelligence.") from None
        raise
    cvss3 = v.get("cvss3Summary") or {}
    return compact({
        "cve": v.get("id") or cve,
        "severity": v.get("severity"), "priorityScore": v.get("priorityScore"),
        "cvss3": compact(pick(cvss3, ("score", "severity", "vectorString"))),
        "cvss2Score": (v.get("cvss2Summary") or {}).get("score"),
        "exploitsAvailable": v.get("exploitsAvailable"), "activeExploitsObserved": v.get("activeExploitsObserved"),
        "hasChatter": v.get("hasChatter"),
        "publishedDateTime": v.get("publishedDateTime"), "lastModifiedDateTime": v.get("lastModifiedDateTime"),
        "weaknesses": (v.get("commonWeaknessEnumerationIds") or [])[:10],
        "description": _content(v.get("description"), 1500),
        "remediation": _content(v.get("remediation"), 1500),
        "exploits": _links(v.get("exploits")), "references": _links(v.get("references")),
        "next_steps": "get_cve_exposure(cve_id) shows the affected devices in your organization.",
    })


async def _host(host: str) -> dict:
    graph = runtime.graph()
    ok, errors = await gather_sections({
        "host": graph.get(f"{_BASE}/hosts/{host}"),
        "reputation": graph.get(f"{_BASE}/hosts/{host}/reputation"),
    })
    if not ok:
        first = next(iter(errors.values()))
        if "404" in first:
            raise NotFoundError(f"'{host}' is not known to Microsoft Threat Intelligence.")
        raise DefenderToolError(first)
    out: dict = {"host": host}
    if "host" in ok:
        h = ok["host"]
        out["type"] = str(h.get("@odata.type") or "").rsplit(".", 1)[-1] or None
        out.update(pick(h, ("firstSeenDateTime", "lastSeenDateTime", "registrar", "registrant", "countryOrRegion",
                            "hostingProvider", "netblock")))
        asn = h.get("autonomousSystem")
        if isinstance(asn, dict):
            out["autonomousSystem"] = compact(pick(asn, ("number", "name", "organization")))
    if "reputation" in ok:
        r = ok["reputation"]
        out["reputation"] = compact({
            "classification": r.get("classification"), "score": r.get("score"),
            "rules": [compact({"name": x.get("name"), "description": truncate(x.get("description"), 300),
                               "severity": x.get("severity"), "link": x.get("relatedDetailsUrl")})
                      for x in (r.get("rules") or [])[:10] if isinstance(x, dict)],
        })
    if errors:
        out["errors"] = errors
    out["next_steps"] = ("hunt_ioc(indicator) shows where it appears in your tenant; manage_indicator can block it "
                         "in Defender for Endpoint.")
    return compact(out)


async def _search(term: str, top: int) -> dict:
    graph = runtime.graph()
    params = {"$search": f'"{term}"', "$top": str(top)}
    ok, errors = await gather_sections({
        "articles": graph.get(f"{_BASE}/articles", params=params),
        "profiles": graph.get(f"{_BASE}/intelProfiles", params=params),
    })
    out: dict = {"search": term}
    if "articles" in ok:
        out["articles"] = [compact({
            "id": a.get("id"), "title": a.get("title"), "created": a.get("createdDateTime"),
            "updated": a.get("lastUpdatedDateTime"), "summary": _content(a.get("summary"), 400),
            "tags": (a.get("tags") or [])[:10]}) for a in (ok["articles"].get("value") or [])[:top]]
    if "profiles" in ok:
        out["profiles"] = [compact({
            "id": p.get("id"), "title": p.get("title"), "kind": p.get("kind"),
            "aliases": (p.get("aliases") or [])[:10], "targets": (p.get("targets") or [])[:8],
            "firstActive": p.get("firstActiveDateTime"), "summary": _content(p.get("summary"), 500)})
            for p in (ok["profiles"].get("value") or [])[:top]]
    if errors:
        out["errors"] = errors
    return compact(out)


@read_tool(scopes=(THREAT_INTEL_READ,), title="Microsoft Threat Intelligence")
async def get_threat_intelligence(
    indicator: Annotated[Optional[str], "IP address, domain, URL or CVE ID (e.g. CVE-2024-3400) to look up."] = None,
    search: Annotated[Optional[str], "One keyword (single term) to search threat intelligence articles and threat "
                                     "actor / tool profiles, e.g. 'Storm-0501', 'Qakbot' or 'ransomware'."] = None,
    max_items: Annotated[int, "search: maximum number of articles and of profiles (1-25)."] = 5,
) -> dict:
    """Microsoft Threat Intelligence (included with Defender XDR): reputation of an IP address, domain or URL
    host (classification such as malicious or suspicious, score and the rules behind it, first/last seen,
    registrar, hosting / ASN), intelligence on a CVE (CVSS, Microsoft priority score, public exploits, active
    exploitation observed, remediation), or a keyword search in Microsoft threat intelligence articles and
    threat actor / tool profiles. This is global intelligence; hunt_ioc shows whether an indicator appears in
    your own tenant. File hashes: use hunt_ioc (prevalence, signer, detection name)."""
    if bool(indicator) == bool(search):
        raise InputError("Pass either indicator (IP, domain, URL or CVE) or search (one keyword).")
    if search:
        term = str(search).strip()
        if not _TERM.match(term):
            raise InputError("search must be a single term (letters, digits, '.', '-', '_'; 2-64 characters).")
        result = await _search(term, clamp_int(max_items, 1, 25, "max_items"))
    else:
        value = str(indicator).strip()
        if value.upper().startswith("CVE-"):
            result = await _vulnerability(kql.cve_id(value))
        elif _HASH.match(value) and len(value) in (32, 40, 64):
            raise InputError("Microsoft Threat Intelligence has no file hash lookup here: use hunt_ioc(indicator) for "
                             "prevalence, signer and detection name of a file.")
        else:
            _kind, host = _host_of(value)
            result = await _host(host)
    result["note"] = UNTRUSTED_NOTE
    return result
