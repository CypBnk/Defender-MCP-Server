"""One shared httpx.AsyncClient per process (connection pooling for Graph and token endpoint)."""
from __future__ import annotations

from typing import Any, Optional

from . import __version__

_client: Any = None


def get_http_client(timeout_seconds: float = 30.0) -> Any:
    global _client
    if _client is None:
        import httpx

        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds, connect=10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            headers={"User-Agent": f"defender-mcp-server/{__version__}"},
            follow_redirects=False,
        )
    return _client


def is_transport_error(exc: BaseException) -> bool:
    """True for network-level errors (httpx.TransportError/TimeoutException) without importing httpx."""
    names = {cls.__name__ for cls in type(exc).__mro__}
    return bool(names & {"TransportError", "TimeoutException", "NetworkError"})


def retry_after_seconds(headers: Any) -> Optional[float]:
    raw = None
    try:
        raw = headers.get("Retry-After") or headers.get("retry-after")
    except AttributeError:
        return None
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None
