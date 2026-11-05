"""Registry checks and a smoke test of create_server() against stub FastMCP modules
(the real fastmcp package is exercised in CI by test_fastmcp_integration.py)."""
import inspect
import json
import logging
import os
import re
import sys
import types
import typing
import unittest

from defender_mcp import scopes
from defender_mcp.tools.registry import (all_specs, graph_scopes_for, mde_scopes_for, mdca_scopes_for, scopes_for,
                                         specs_for)
from helpers import CLIENT, TENANT, make_settings

SNAPSHOT = os.path.join(os.path.dirname(__file__), "tool_signatures.json")
DEPLOY_PS1 = os.path.join(os.path.dirname(__file__), "..", "deploy.ps1")
READ_TOOLS, ADMIN_TOOLS = 38, 12
WRITE_SCOPES = {scopes.SECURITY_INCIDENT_READWRITE, scopes.SECURITY_ALERT_READWRITE, scopes.CUSTOM_DETECTION_READWRITE,
                scopes.IDENTITY_HEALTH_READWRITE, scopes.USER_REVOKE_SESSIONS, scopes.USER_ENABLE_DISABLE,
                scopes.IDENTITY_RISKY_USER_READWRITE, scopes.MDE_MACHINE_READWRITE, scopes.MDE_MACHINE_ISOLATE,
                scopes.MDE_MACHINE_SCAN, scopes.MDE_MACHINE_COLLECT_FORENSICS, scopes.MDE_MACHINE_RESTRICT_EXECUTION,
                scopes.MDE_MACHINE_STOP_AND_QUARANTINE, scopes.MDE_TI_READWRITE, scopes.MDE_ALERT_READWRITE,
                scopes.MDCA_DISCOVERY_MANAGE}
READ_SCOPE = re.compile(r"\.Read(\.All|\.Directory)?$")   # same rule as $readPattern in deploy.ps1


def ps_list(name: str) -> list[str]:
    """Values of a PowerShell array assignment like $GRAPH_SCOPES = @('a', 'b') in deploy.ps1."""
    with open(DEPLOY_PS1, encoding="utf-8") as fh:
        text = fh.read()
    match = re.search(r"^\$" + name + r"\s*=\s*@\(([^)]*)\)", text, re.MULTILINE)
    assert match, f"${name} not found in deploy.ps1"
    return re.findall(r"'([^']+)'", match.group(1))


def signature_snapshot() -> dict:
    out = {}
    for spec in sorted(all_specs(), key=lambda s: s.name):
        params = {}
        for name, p in inspect.signature(spec.fn).parameters.items():
            params[name] = {"type": str(p.annotation).replace("typing.", ""),
                            "default": None if p.default is inspect.Parameter.empty else repr(p.default),
                            "required": p.default is inspect.Parameter.empty}
        out[spec.name] = {"kind": spec.kind, "params": params}
    return out


class RegistryTests(unittest.TestCase):
    def test_counts_and_profiles(self):
        specs = all_specs()
        self.assertEqual(sum(s.kind == "read" for s in specs), READ_TOOLS)
        self.assertEqual(sum(s.kind == "admin" for s in specs), ADMIN_TOOLS)
        self.assertEqual(len(specs_for("read")), READ_TOOLS)
        self.assertEqual(len(specs_for("full")), READ_TOOLS + ADMIN_TOOLS)

    def test_read_profile_has_no_write_scopes(self):
        self.assertFalse(WRITE_SCOPES & set(scopes_for("read")))
        self.assertTrue(WRITE_SCOPES <= set(scopes_for("full")))
        self.assertEqual(mde_scopes_for("read"), ["Machine.Read", "RemediationTask.Read"])   # AV health, risk, tasks
        # deploy.ps1 grants read permissions by name ($readPattern): every read-profile permission must match it,
        # every write permission must not.
        self.assertTrue(all(READ_SCOPE.search(n) for n in graph_scopes_for("read") + mde_scopes_for("read")))
        self.assertFalse(any(READ_SCOPE.search(scopes.split(w)[1]) for w in WRITE_SCOPES))

    def test_deploy_script_scope_lists_match_registry(self):
        """deploy.ps1 grants exactly the permissions the tools need (Graph and WindowsDefenderATP)."""
        self.assertEqual(sorted(ps_list("GRAPH_SCOPES")), graph_scopes_for("full"))
        self.assertEqual(sorted(ps_list("MDE_SCOPES")), mde_scopes_for("full"))
        self.assertEqual(sorted(ps_list("MDCA_SCOPES")), mdca_scopes_for("full"))
        self.assertEqual(mdca_scopes_for("full"), ["Discovery.manage"])     # sanction_cloud_apps only
        self.assertEqual(mdca_scopes_for("read"), [])
        with open(DEPLOY_PS1, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(f"$MDE_APP_ID = '{scopes.MDE_APP_ID}'", text)
        self.assertIn(f"$MDCA_APP_ID = '{scopes.MDCA_APP_ID}'", text)

    def test_every_parameter_is_annotated_and_described(self):
        for spec in all_specs():
            hints = typing.get_type_hints(spec.fn, include_extras=True)
            for name in inspect.signature(spec.fn).parameters:
                self.assertIn(name, hints, f"{spec.name}.{name} has no type annotation")
            self.assertGreater(len(spec.fn.__doc__.strip()), 40, f"{spec.name} needs a real description")
            self.assertEqual(spec.annotations()["readOnlyHint"], spec.kind == "read" or spec.read_only)

    def test_admin_tools_take_confirmation_token_unless_always_immediate(self):
        for spec in all_specs():
            if spec.kind != "admin":
                continue
            if spec.runs_immediately({}) and spec.immediate({"x": 1}):
                # add_comment, get_response_actions: never need a confirmation
                self.assertNotIn("confirmation_token", inspect.signature(spec.fn).parameters, spec.name)
            else:
                self.assertIn("confirmation_token", inspect.signature(spec.fn).parameters, spec.name)

    def test_descriptions_fit_copilot_studio(self):
        for spec in all_specs():
            self.assertLessEqual(len(spec.name), 64, spec.name)
            self.assertLessEqual(len(" ".join(spec.fn.__doc__.split())), 1024, spec.name)

    def test_signature_snapshot(self):
        """Tool names/parameters are the contract with Copilot Studio. Regenerate deliberately with
        python scripts/export_tool_signatures.py"""
        with open(SNAPSHOT, encoding="utf-8") as fh:
            self.assertEqual(signature_snapshot(), json.load(fh))


APP_OK = "33333333-3333-3333-3333-333333333333"


def _jwt(claims: dict) -> str:
    import base64

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


def _install_stub_fastmcp(record: dict) -> None:
    def module(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        sys.modules[name] = m
        return m

    class FastMCP:
        def __init__(self, name, instructions=None, auth=None, mask_error_details=False):
            record.update(name=name, auth=auth, mask=mask_error_details, tools={}, middlewares=[], routes={})

        def add_middleware(self, mw):
            record["middlewares"].append(type(mw).__name__)

        def tool(self, name=None, tags=None, annotations=None):
            def deco(fn):
                record["tools"][name] = {"tags": tags, "annotations": annotations, "fn": fn}
                return fn
            return deco

        def custom_route(self, path, methods):
            def deco(fn):
                record["routes"][path] = fn
                return fn
            return deco

        def http_app(self, stateless_http=False):
            record["stateless"] = stateless_http
            return "asgi-app"

    class AzureJWTVerifier:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            record["verifier_kwargs"] = kwargs

        async def verify_token(self, token):
            from defender_mcp.auth.identity import unverified_claims

            return types.SimpleNamespace(token=token, claims=unverified_claims(token))

    class RemoteAuthProvider:
        def __init__(self, **kwargs):
            record["auth_kwargs"] = kwargs
            record["auth_type"] = "RemoteAuthProvider"

    class Middleware:
        pass

    class Simple:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class ErrorHandlingMiddleware(Simple):
        pass

    class RateLimitingMiddleware(Simple):
        pass

    class JSONResponse:
        def __init__(self, content, status_code=200):
            self.content, self.status_code = content, status_code

    module("fastmcp", FastMCP=FastMCP)
    module("fastmcp.server")
    module("fastmcp.server.auth", RemoteAuthProvider=RemoteAuthProvider)
    module("fastmcp.server.auth.providers")
    module("fastmcp.server.auth.providers.azure", AzureJWTVerifier=AzureJWTVerifier)
    module("fastmcp.server.dependencies", get_access_token=lambda: None)
    module("fastmcp.server.middleware", Middleware=Middleware)
    module("fastmcp.server.middleware.error_handling", ErrorHandlingMiddleware=ErrorHandlingMiddleware)
    module("fastmcp.server.middleware.rate_limiting", RateLimitingMiddleware=RateLimitingMiddleware)
    module("starlette")
    module("starlette.responses", JSONResponse=JSONResponse)


class CreateServerStubTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import fastmcp  # noqa: F401
            raise unittest.SkipTest("real fastmcp installed; covered by test_fastmcp_integration.py")
        except ImportError:
            pass
        cls.record = {}
        cls.saved = dict(sys.modules)
        _install_stub_fastmcp(cls.record)

    @classmethod
    def tearDownClass(cls):
        for name in list(sys.modules):
            if name.split(".")[0] in {"fastmcp", "starlette"} and name not in cls.saved:
                del sys.modules[name]

    def setUp(self):
        logging.getLogger("defender_mcp").handlers.clear()

    async def test_read_profile(self):
        from defender_mcp.app import create_app

        app = create_app(make_settings(profile="read", log_format="text", log_level="WARNING"))
        r = self.record
        self.assertEqual(app, "asgi-app")
        self.assertTrue(r["stateless"])
        self.assertTrue(r["mask"])
        self.assertEqual(len(r["tools"]), READ_TOOLS)
        self.assertEqual(r["middlewares"], ["ErrorHandlingMiddleware", "AuditMiddleware", "RateLimitingMiddleware"])
        self.assertEqual(r["auth_type"], "RemoteAuthProvider")
        self.assertEqual(r["verifier_kwargs"]["required_scopes"], ["access_as_user"])
        self.assertTrue(r["tools"]["find_defender_devices"]["annotations"]["readOnlyHint"])
        self.assertNotIn("run_device_response", r["tools"])
        health = await r["routes"]["/healthz"](None)
        self.assertEqual(health.content["status"], "ok")
        ready = await r["routes"]["/readyz"](None)
        self.assertEqual(ready.status_code, 200)
        self.assertEqual(ready.content["status"], "ready")

    async def test_full_profile(self):
        from defender_mcp.app import create_server
        from defender_mcp.settings import Secret

        create_server(make_settings(profile="full", log_format="text", log_level="WARNING",
                                    jwt_signing_key=Secret("j" * 40)))
        r = self.record
        self.assertEqual(len(r["tools"]), READ_TOOLS + ADMIN_TOOLS)
        self.assertTrue(r["tools"]["run_device_response"]["annotations"]["destructiveHint"])
        self.assertEqual(r["tools"]["run_device_response"]["tags"], {"admin"})
        self.assertTrue(r["tools"]["get_response_actions"]["annotations"]["readOnlyHint"])  # admin, but read-only
        self.assertFalse(r["tools"]["update_incident"]["annotations"]["readOnlyHint"])
        self.assertEqual(r["auth_type"], "RemoteAuthProvider")


    async def test_entra_mode_validates_tokens_only(self):
        from defender_mcp.app import create_server
        from defender_mcp.tools.registry import specs_for

        create_server(make_settings(log_format="text", log_level="WARNING", allowed_client_app_ids=(APP_OK,)))
        r = self.record
        self.assertEqual(r["auth_type"], "RemoteAuthProvider")
        self.assertEqual(len(r["tools"]), len(specs_for("full")))   # default: one server with all tools
        self.assertIn("run_device_response", r["tools"])
        self.assertEqual(r["auth_kwargs"]["base_url"], "https://mcp.example.com")
        self.assertIn(TENANT, str(r["auth_kwargs"]["authorization_servers"][0]))
        self.assertEqual(r["verifier_kwargs"]["client_id"], CLIENT)
        self.assertEqual(r["verifier_kwargs"]["required_scopes"], ["access_as_user"])

        verifier = r["auth_kwargs"]["token_verifier"]
        good = dict(tid=TENANT, scp="access_as_user", azp=APP_OK, oid="u1")
        self.assertIsNotNone(await verifier.verify_token(_jwt(good)))
        self.assertIsNone(await verifier.verify_token(_jwt(dict(good, tid="44444444-4444-4444-4444-444444444444"))))
        self.assertIsNone(await verifier.verify_token(_jwt(dict(good, azp="55555555-5555-5555-5555-555555555555"))))
        app_only = {k: v for k, v in good.items() if k != "scp"}
        self.assertIsNone(await verifier.verify_token(_jwt(dict(app_only, roles=["x"]))))

    async def test_audit_middleware_logs_success_and_error(self):
        from defender_mcp.middleware import make_audit_middleware

        mw = make_audit_middleware({"run_device_response"})
        ctx = types.SimpleNamespace(message=types.SimpleNamespace(name="run_device_response",
                                                                  arguments={"device": "PC-01", "action": "isolate"}))

        async def ok(_ctx):
            return types.SimpleNamespace(is_error=False)

        async def boom(_ctx):
            raise RuntimeError("x")

        with self.assertLogs("defender_mcp.audit", level="INFO") as logs:
            await mw.on_call_tool(ctx, ok)
            with self.assertRaises(RuntimeError):
                await mw.on_call_tool(ctx, boom)
        first, second = (r.fields for r in logs.records)
        self.assertEqual((first["status"], first["phase"], first["kind"]), ("ok", "preview", "admin"))
        self.assertEqual((second["status"], second["error"]), ("error", "RuntimeError"))


class AuditRecordTests(unittest.TestCase):
    def test_read_tool_arguments_are_names_only(self):
        from defender_mcp.middleware import build_audit_record

        rec = build_audit_record("run_hunting_query", {"query": "IdentityLogonEvents | where AccountUpn == 'x'",
                                                       "timespan_days": None}, admin=False, status="ok",
                                 duration_ms=12.3, user={"oid": "o", "upn": "a@b.c"})
        self.assertEqual(rec["arguments"], ["query"])

    def test_admin_tool_arguments_are_kept_but_secrets_redacted(self):
        from defender_mcp.middleware import build_audit_record

        rec = build_audit_record("run_device_response", {"device": "PC-01", "action": "isolate",
                                                         "confirmation_token": "abc", "comment": "c" * 900},
                                 admin=True, status="ok", duration_ms=1, user={})
        self.assertEqual(rec["arguments"]["confirmation_token"], "<redacted>")
        self.assertEqual(rec["arguments"]["device"], "PC-01")
        self.assertIn("[900 chars]", rec["arguments"]["comment"])
        self.assertEqual(rec["phase"], "execute")


if __name__ == "__main__":
    unittest.main()


class AuditPhaseTests(unittest.TestCase):
    def test_immediate_calls_count_as_execute(self):
        from defender_mcp.middleware import build_audit_record
        from defender_mcp.tools.registry import all_specs

        specs = {s.name: s for s in all_specs()}
        scan = {"device": "PC-01", "action": "antivirus_scan_quick"}
        isolate = {"device": "PC-01", "action": "isolate"}
        self.assertTrue(specs["run_device_response"].runs_immediately(scan))
        self.assertFalse(specs["run_device_response"].runs_immediately(isolate))
        self.assertTrue(specs["add_comment"].runs_immediately({}))
        self.assertTrue(specs["manage_indicator"].runs_immediately({"operation": "list"}))
        self.assertFalse(specs["manage_indicator"].runs_immediately({"operation": "add"}))
        rec = build_audit_record("run_device_response", scan, admin=True, status="ok", duration_ms=1, user={},
                                 immediate=True)
        self.assertEqual(rec["phase"], "execute")
        rec = build_audit_record("run_device_response", isolate, admin=True, status="ok", duration_ms=1, user={})
        self.assertEqual(rec["phase"], "preview")
