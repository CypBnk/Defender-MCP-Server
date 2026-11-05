"""Test helpers: settings factory, fake Graph / Defender API and fake HTTP (no network, no third-party packages)."""
from __future__ import annotations

import copy
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from defender_mcp import runtime  # noqa: E402
from defender_mcp.confirm import Confirmer  # noqa: E402
from defender_mcp.errors import GraphError  # noqa: E402
from defender_mcp.graph.client import validate_path  # noqa: E402
from defender_mcp.settings import Secret, Settings  # noqa: E402

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
MDE1 = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07"
MDE2 = "2e5bc9d7e413ddd7902c2932e418702b84d0cc07"
AAD1 = "aaaaaaaa-0000-0000-0000-000000000001"
SIM1 = "dddddddd-0000-0000-0000-000000000001"
ACTION1 = "eeeeeeee-0000-0000-0000-000000000001"
HUNT = "/security/runHuntingQuery"


def make_settings(**overrides: Any) -> Settings:
    data = dict(tenant_id=TENANT, client_id=CLIENT, client_secret=Secret("s" * 40),
                base_url="https://mcp.example.com", environment="development")
    data.update(overrides)
    return Settings(**data)


def env(**overrides: str) -> dict:
    data = {"TENANT_ID": TENANT, "CLIENT_ID": CLIENT, "CLIENT_SECRET": "x" * 40,
            "BASE_URL": "https://mcp.example.com", "MCP_ENV": "development"}
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}


@dataclass
class Call:
    method: str
    version: str
    path: str
    params: dict
    json_body: Any
    advanced: bool
    headers: Optional[dict] = None
    timeout: Optional[float] = None


class FakeGraph:
    """Routes: (METHOD, path) or (METHOD, path, version) -> response | callable(params, body) | exception.
    Also used as fake Defender for Endpoint API (paths /api/...)."""

    def __init__(self, routes: Optional[dict] = None) -> None:
        self.routes: dict = dict(routes or {})
        self.calls: list[Call] = []

    def on(self, method: str, path: str, response: Any, version: Optional[str] = None) -> "FakeGraph":
        self.routes[(method, path, version) if version else (method, path)] = response
        return self

    def hunting(self, responder: Callable[[str], Any]) -> "FakeGraph":
        """responder(query) -> list of rows | (columns, rows) | exception."""

        def handler(_params, body):
            result = responder(body["Query"])
            if isinstance(result, BaseException):
                return result
            if isinstance(result, tuple):
                columns, rows = result
            else:
                rows = result
                columns = list(rows[0].keys()) if rows else []
            return {"schema": [{"name": c, "type": "String"} for c in columns], "results": rows}

        return self.on("POST", HUNT, handler)

    async def request(self, method: str, path: str, *, version: str = "v1.0", params: Optional[dict] = None,
                      json_body: Any = None, advanced: bool = False, idempotent: Optional[bool] = None,
                      headers: Optional[dict] = None, timeout: Optional[float] = None) -> Any:
        validate_path(path)
        self.calls.append(Call(method, version, path, dict(params or {}), json_body, advanced, dict(headers or {}),
                               timeout))
        for k in ((method, path, version), (method, path)):
            if k in self.routes:
                response = self.routes[k]
                break
        else:
            raise GraphError(404, "NotFound", f"no fake route for {method} {version} {path}")
        if callable(response):
            response = response(dict(params or {}), json_body)
        if isinstance(response, BaseException):
            raise response
        return copy.deepcopy(response)

    async def get(self, path: str, *, version: str = "v1.0", params: Optional[dict] = None, advanced: bool = False,
                  headers: Optional[dict] = None):
        return await self.request("GET", path, version=version, params=params, advanced=advanced, headers=headers)

    async def put(self, path: str, *, json_body: Any, version: str = "v1.0"):
        return await self.request("PUT", path, version=version, json_body=json_body)

    async def post(self, path: str, *, json_body: Any = None, version: str = "v1.0", idempotent: bool = False,
                   timeout: Optional[float] = None):
        return await self.request("POST", path, version=version, json_body=json_body or {}, idempotent=idempotent,
                                  timeout=timeout)

    async def patch(self, path: str, *, json_body: Any, version: str = "v1.0"):
        return await self.request("PATCH", path, version=version, json_body=json_body)

    async def delete(self, path: str, *, version: str = "v1.0"):
        return await self.request("DELETE", path, version=version)

    def paths(self, method: Optional[str] = None) -> list[str]:
        return [c.path for c in self.calls if method is None or c.method == method]

    def queries(self) -> list[str]:
        return [c.json_body["Query"] for c in self.calls if c.path == HUNT]


def configure(graph: Any, settings: Optional[Settings] = None, clock: Callable[[], float] | None = None,
              mde: Any = None, mdca: Any = None) -> Settings:
    settings = settings or make_settings()
    confirmer = Confirmer(b"k" * 32, 300, clock) if clock else Confirmer(b"k" * 32, 300)
    runtime.configure(runtime.Runtime(settings=settings, graph=graph, confirmer=confirmer, cursor_key=b"c" * 32,
                                      mde=mde, mdca=mdca))
    return settings


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None, headers: Optional[dict] = None, text: str = ""):
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}
        self.text = text
        if json_data is not None:
            import json as _json
            self.content = _json.dumps(json_data).encode()
        else:
            self.content = text.encode()

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class TransportError(Exception):
    """Mimics httpx.TransportError by class name."""


class TimeoutException(Exception):
    """Mimics httpx.TimeoutException by class name."""


class FakeHttp:
    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.requests: list[dict] = []

    async def request(self, method, url, params=None, json=None, headers=None, timeout=None):
        self.requests.append({"method": method, "url": url, "params": params, "json": json, "headers": headers,
                              "timeout": timeout})
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def post(self, url, data=None, headers=None):
        self.requests.append({"method": "POST", "url": url, "data": data, "headers": headers})
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def jwt(claims: dict) -> str:
    import base64
    import json as _json

    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


DEVICE_ROW = {"DeviceId": MDE1, "DeviceName": "pc-01.contoso.local", "OSPlatform": "Windows11", "OSVersion": "10.0",
              "OnboardingStatus": "Onboarded", "SensorHealthState": "Active", "ExposureLevel": "Medium",
              "MachineGroup": "Clients", "AadDeviceId": AAD1, "LastSeen": "2026-11-01T10:00:00Z"}


def device_responder(rows_for_device: Optional[list] = None, extra: Optional[Callable[[str], Any]] = None):
    """Hunting responder that answers DeviceInfo resolution queries with DEVICE_ROW and delegates the rest."""
    rows_for_device = [DEVICE_ROW] if rows_for_device is None else rows_for_device

    def responder(query: str):
        if query.startswith("DeviceInfo") and "arg_max(Timestamp, *) by DeviceId" in query and "MergedToDeviceId" in query \
                and "LastSeen" in query and "TotalMatches" not in query:
            return list(rows_for_device)
        if extra:
            return extra(query)
        return []

    return responder
