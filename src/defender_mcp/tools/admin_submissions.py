"""Submissions to Microsoft: the 'Submissions' page of the Defender portal (Actions & submissions).
Lists email, URL and file submissions - including messages reported by users - with Microsoft's verdict, and submits
URLs for analysis (false negative: phishing / malware / spam; false positive: notJunk). Microsoft Graph beta
threatSubmission, delegated ThreatSubmission.Read.All / ThreatSubmission.ReadWrite.All. Submitting an email needs the
message itself (Graph message URL or .eml content) and stays in the Defender portal."""
from __future__ import annotations

from typing import Annotated, Literal, Optional

from .. import kql, runtime
from ..confirm import two_step
from ..errors import GraphError, InputError
from ..graph.odata import clamp_int, iso_days_ago
from ..shaping import UNTRUSTED_NOTE, compact
from ..scopes import THREAT_SUBMISSION_READ, THREAT_SUBMISSION_READWRITE
from ..util import gather_sections
from .common import ConfirmationToken, MaxItems
from .registry import admin_tool

_PATHS = {"email": "/security/threatSubmission/emailThreats", "url": "/security/threatSubmission/urlThreats",
          "file": "/security/threatSubmission/fileThreats"}
Category = Literal["phishing", "malware", "spam", "notJunk"]
_MEANING = {"phishing": "false negative: the URL is phishing and should be blocked",
            "malware": "false negative: the URL delivers malware and should be blocked",
            "spam": "false negative: the URL belongs to spam",
            "notJunk": "false positive: the URL is legitimate and should not be blocked"}


def _row(item: dict) -> dict:
    created = item.get("createdBy") or {}
    user = created.get("user") if isinstance(created, dict) else None
    result = item.get("result") or {}
    review = item.get("adminReview") or {}
    return compact({
        "id": item.get("id"), "contentType": item.get("contentType"), "category": item.get("category"),
        "source": item.get("source"), "status": item.get("status"), "createdDateTime": item.get("createdDateTime"),
        "submittedBy": (user or {}).get("email") or (user or {}).get("displayName"),
        "verdict": result.get("detail") if isinstance(result, dict) else None,
        "verdictCategory": result.get("category") if isinstance(result, dict) else None,
        "adminReview": review.get("reviewResult") if isinstance(review, dict) else None,
        "recipient": item.get("recipientEmailAddress"), "sender": item.get("sender"), "subject": item.get("subject"),
        "receivedDateTime": item.get("receivedDateTime"), "url": item.get("webUrl"), "fileName": item.get("fileName"),
    })


async def _list(kind: str, days: int) -> list:
    graph = runtime.graph()
    params = {"$filter": f"createdDateTime ge {iso_days_ago(days)}", "$top": "200"}
    try:
        res = await graph.get(_PATHS[kind], version="beta", params=params)
    except GraphError as exc:
        if exc.status != 400:
            raise
        res = await graph.get(_PATHS[kind], version="beta", params={"$top": "200"})   # filter not supported
    return list(res.get("value") or [])


@admin_tool(scopes=(THREAT_SUBMISSION_READ, THREAT_SUBMISSION_READWRITE), title="Submissions to Microsoft",
            destructive=False, idempotent=False, immediate=lambda args: args.get("operation") == "list")
async def manage_submissions(
    operation: Annotated[Literal["list", "submit_url"], "list runs immediately; submit_url needs confirmation."],
    content_type: Annotated[Literal["all", "email", "url", "file"], "list: type of submission."] = "all",
    source: Annotated[Optional[Literal["user", "administrator"]], "list: user = messages reported by users; "
                                                                   "administrator = admin submissions."] = None,
    days: Annotated[int, "list: look-back window in days (1-180)."] = 30,
    url: Annotated[Optional[str], "submit_url: the URL to submit."] = None,
    category: Annotated[Optional[Category], "submit_url: phishing, malware or spam (should be blocked) or notJunk "
                                            "(legitimate, wrongly blocked)."] = None,
    confirmation_token: ConfirmationToken = None,
    max_items: MaxItems = 50,
) -> dict:
    """Submissions to Microsoft for analysis (Defender portal: Actions & submissions > Submissions). list: email,
    URL and file submissions of the last days, including messages users reported as phishing or junk
    (source='user'), with Microsoft's verdict and the admin review, newest first. submit_url: send a URL to
    Microsoft as phishing / malware / spam or as wrongly blocked (notJunk); two-step. Block a URL in your own
    tenant with manage_indicator."""
    if operation == "list":
        d = clamp_int(days, 1, 180, "days")
        kinds = list(_PATHS) if content_type == "all" else [content_type]
        ok, errors = await gather_sections({k: _list(k, d) for k in kinds})
        rows = [_row(i) for k in kinds for i in ok.get(k) or []]
        cutoff = iso_days_ago(d)
        rows = [r for r in rows if str(r.get("createdDateTime") or "") >= cutoff and (not source or r.get("source") == source)]
        rows.sort(key=lambda r: str(r.get("createdDateTime") or ""), reverse=True)
        limit = clamp_int(max_items, 1, 300, "max_items")
        by_verdict: dict = {}
        for r in rows:
            by_verdict[r.get("verdict") or "pending"] = by_verdict.get(r.get("verdict") or "pending", 0) + 1
        out = {"operation": "list", "days": d, "count": min(len(rows), limit), "total": len(rows),
               "truncated": len(rows) > limit, "byVerdict": by_verdict, "items": rows[:limit], "note": UNTRUSTED_NOTE}
        if errors:
            out["errors"] = errors
        return out
    if not url or not category:
        raise InputError("submit_url needs url and category.")
    web_url = kql.url(url)

    async def preview() -> dict:
        return {"url": web_url, "category": category, "meaning": _MEANING[category],
                "effect": "Microsoft analyzes the URL and reports the verdict under Submissions (manage_submissions "
                          "list). The submission itself does not block or allow anything in your tenant."}

    async def execute() -> dict:
        res = await runtime.graph().post(_PATHS["url"], version="beta", json_body={
            "@odata.type": "#microsoft.graph.urlThreatSubmission", "category": category, "webUrl": web_url})
        return {"submission": _row(res if isinstance(res, dict) else {}),
                "next_steps": "manage_submissions(operation='list', content_type='url') shows the verdict later; "
                              "manage_indicator(operation='add') blocks the URL in Defender for Endpoint."}

    return await two_step(action="submission.url", target=web_url, params={"category": category},
                          token=confirmation_token, preview=preview, execute=execute)
