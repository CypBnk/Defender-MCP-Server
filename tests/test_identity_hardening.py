"""Identity hardening: identity without the 'profile' scope, tenant pinning via issuer, mcp SDK check."""
import types
import unittest
from unittest import mock

from defender_mcp.auth import identity
from defender_mcp.auth.provider import token_rejection_reason
from defender_mcp.errors import AuthError
from helpers import TENANT, make_settings

OTHER = "44444444-4444-4444-4444-444444444444"
ISS = f"https://login.microsoftonline.com/{TENANT}/v2.0"


def _access(claims):
    return mock.patch.object(identity, "_access_token", return_value=types.SimpleNamespace(token="t", claims=claims))


class IdentityTests(unittest.TestCase):
    def test_tenant_from_issuer(self):
        self.assertEqual(identity.tenant_from_issuer(ISS), TENANT)
        self.assertEqual(identity.tenant_from_issuer(f"https://sts.windows.net/{TENANT}/"), TENANT)
        self.assertEqual(identity.tenant_from_issuer("https://example.com/x"), "")
        self.assertEqual(identity.tenant_from_issuer(None), "")

    def test_user_without_profile_scope_uses_sub_and_issuer(self):
        with _access({"sub": "s1", "iss": ISS, "scp": "access_as_user"}):
            user = identity.current_user()
            self.assertEqual(user["tid"], TENANT)
            self.assertIsNone(user["oid"])
            self.assertEqual(identity.user_key(), f"{TENANT}:s1")

    def test_user_key_prefers_oid(self):
        with _access({"oid": "o1", "sub": "s1", "tid": TENANT}):
            self.assertEqual(identity.user_key(), f"{TENANT}:o1")

    def test_user_key_refuses_token_without_identifier(self):
        with _access({"scp": "access_as_user"}):
            with self.assertRaises(AuthError):
                identity.user_key()

    def test_user_key_empty_outside_request(self):
        with mock.patch.object(identity, "_access_token", return_value=None):
            self.assertEqual(identity.user_key(), "")

    def test_users_get_different_rate_limit_keys(self):
        from defender_mcp.middleware import rate_limit_client_id

        with _access({"sub": "a", "iss": ISS}):
            first = rate_limit_client_id()
        with _access({"sub": "b", "iss": ISS}):
            second = rate_limit_client_id()
        self.assertNotEqual(first, second)
        self.assertNotIn("anonymous", first)


class TenantPinningTests(unittest.TestCase):
    def setUp(self):
        self.settings = make_settings()

    def test_tenant_from_issuer_when_tid_missing(self):
        self.assertIsNone(token_rejection_reason({"iss": ISS, "scp": "x"}, self.settings))
        other_iss = f"https://login.microsoftonline.com/{OTHER}/v2.0"
        self.assertEqual(token_rejection_reason({"iss": other_iss, "scp": "x"}, self.settings),
                         "token from another tenant")

    def test_tid_wins_over_issuer(self):
        self.assertEqual(token_rejection_reason({"tid": OTHER, "iss": ISS, "scp": "x"}, self.settings),
                         "token from another tenant")


class McpSdkCheckTests(unittest.TestCase):
    def test_vulnerable_versions(self):
        from defender_mcp.app import mcp_sdk_vulnerable

        for v in ("1.28.0", "1.29.0", "2.0.0", "2.0.1"):
            self.assertTrue(mcp_sdk_vulnerable(v), v)
        for v in ("1.29.1", "1.30.0", "2.1.0", "2.2.0", "3.0.0rc1"):
            self.assertFalse(mcp_sdk_vulnerable(v), v)

    def test_production_refuses_vulnerable_sdk(self):
        from defender_mcp.app import check_mcp_sdk
        from defender_mcp.settings import SettingsError

        with mock.patch("importlib.metadata.version", return_value="2.0.1"):
            with self.assertRaises(SettingsError):
                check_mcp_sdk(make_settings(environment="production"))
            self.assertEqual(check_mcp_sdk(make_settings()), "2.0.1")  # development: warning only


if __name__ == "__main__":
    unittest.main()
