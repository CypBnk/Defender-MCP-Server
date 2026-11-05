"""Logging (JSON to stdout) and optional OpenTelemetry export to Application Insights."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

# Loggers that would otherwise write every HTTP request (including query strings with UPNs) at INFO.
_NOISY = ("httpx", "httpcore", "httpx2", "httpcore2", "azure", "uvicorn.access", "urllib3")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            data.update(extra)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO", fmt: str = "json") -> None:
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in _NOISY:
        logging.getLogger(name).setLevel(logging.WARNING)


def setup_telemetry(connection_string: str | None) -> bool:
    """Export traces/logs to Application Insights when a connection string is configured.
    FastMCP's own OpenTelemetry spans use the global tracer provider set here."""
    if not connection_string:
        return False
    log = logging.getLogger("defender_mcp")
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor
    except ImportError:
        log.warning("APPLICATIONINSIGHTS_CONNECTION_STRING is set but azure-monitor-opentelemetry is not installed.")
        return False
    configure_azure_monitor(connection_string=connection_string, logger_name="defender_mcp")
    log.info("OpenTelemetry export to Application Insights enabled.")
    return True


def tracer():
    """Return an OpenTelemetry tracer or None when the API is not installed."""
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    return trace.get_tracer("defender_mcp")
