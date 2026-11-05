"""Error types. Every subclass of DefenderToolError carries a message that is safe to
show to the MCP client (FastMCP passes ToolError messages through even when
mask_error_details=True; everything else is masked)."""
from __future__ import annotations

from typing import Optional

try:  # pragma: no cover - depends on installed packages
    from fastmcp.exceptions import ToolError as _BaseToolError
except Exception:  # fastmcp not installed (unit tests)
    class _BaseToolError(Exception):  # type: ignore[no-redef]
        """Fallback base class when fastmcp is not installed."""


class DefenderToolError(_BaseToolError):
    """Base class for errors whose message may be shown to the client."""


class InputError(DefenderToolError):
    """Invalid tool argument."""


class NotFoundError(DefenderToolError):
    """Object does not exist or is not visible to the signed-in user."""


class AmbiguousError(DefenderToolError):
    """A name matched several objects; the caller must pick one."""


class AuthError(DefenderToolError):
    """Token missing, token exchange failed or app-only token detected."""


class ConfirmationError(DefenderToolError):
    """Invalid, expired or mismatching confirmation token."""


class GraphError(DefenderToolError):
    """Microsoft Graph or the Defender for Endpoint API returned an error status."""

    def __init__(self, status: int, code: str = "", message: str = "",
                 request_id: Optional[str] = None, hint: Optional[str] = None, service: str = "Graph") -> None:
        self.status = status
        self.code = code
        self.graph_message = message
        self.request_id = request_id
        self.hint = hint
        self.service = service
        text = f"{service} {status}"
        if code:
            text += f" {code}"
        if message:
            text += f": {message}"
        if hint:
            text += f" -- {hint}"
        if request_id:
            text += f" (request-id {request_id})"
        super().__init__(text)
