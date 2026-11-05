"""Unauthenticated operational endpoints for Container Apps probes."""
from __future__ import annotations

import time
from typing import Any

from . import __version__


def register_health_routes(mcp: Any, settings: Any, tool_count: int) -> None:
    from starlette.responses import JSONResponse

    started = time.time()

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request):  # liveness: process is up
        return JSONResponse({"status": "ok", "version": __version__})

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(_request):  # readiness: the server has no external state to check (tokens are not stored)
        return JSONResponse({"status": "ready", "version": __version__, "profile": settings.profile,
                             "tools": tool_count, "uptime_seconds": int(time.time() - started), "checks": {}})
