"""Defender for Identity health issue status."""
from __future__ import annotations

from typing import Annotated, Literal

from .. import runtime
from ..confirm import two_step
from ..graph.odata import key
from ..scopes import IDENTITY_HEALTH_READWRITE
from ..shaping import compact, pick
from .common import ConfirmationToken
from .registry import admin_tool


@admin_tool(scopes=(IDENTITY_HEALTH_READWRITE,), title="Update Defender for Identity health issue", destructive=False,
            idempotent=True)
async def update_identity_health_issue(
    issue_id: Annotated[str, "Health issue ID (get_identity_health)."],
    status: Annotated[Literal["open", "closed", "suppressed"], "New status. Suppressed issues are hidden until "
                                                              "re-opened."],
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Close, suppress or re-open one Microsoft Defender for Identity health issue. Two-step confirmation.
    Closing does not fix the cause: if the condition persists, Defender for Identity opens the issue again."""
    iid = key(issue_id, "issue_id")
    graph = runtime.graph()
    issue = await graph.get(f"/security/identities/healthIssues/{iid}")

    async def preview() -> dict:
        return {"issue": compact(pick(issue, ("id", "displayName", "severity", "status", "healthIssueType",
                                              "sensorDNSNames", "domainNames"))),
                "change": {"status": {"from": issue.get("status"), "to": status}}}

    async def execute() -> dict:
        updated = await graph.patch(f"/security/identities/healthIssues/{iid}", json_body={"status": status})
        return {"issue": compact(pick(updated or {"id": iid, "status": status}, ("id", "displayName", "status")))}

    return await two_step(action="identity_health.update", target=iid, params={"status": status},
                          token=confirmation_token, preview=preview, execute=execute)
