import unittest

from defender_mcp.errors import InputError
from defender_mcp.graph.odata import guid, key, odata_str
from defender_mcp.settings import Secret, Settings, SettingsError
from helpers import env


class ODataTests(unittest.TestCase):
    def test_guid(self):
        self.assertEqual(guid("{AAAAAAAA-0000-0000-0000-000000000001}"), "aaaaaaaa-0000-0000-0000-000000000001")
        for bad in ("abc", "aaaaaaaa-0000-0000-0000-000000000001/wipe?x=", "", None):
            with self.assertRaises(InputError):
                guid(bad)

    def test_key(self):
        self.assertEqual(key("T_1a2b-3c"), "T_1a2b-3c")
        for bad in ("../x", "a/b", "a?b", ""):
            with self.assertRaises(InputError):
                key(bad)

    def test_odata_str_escapes(self):
        self.assertEqual(odata_str("O'Brien-PC"), "'O''Brien-PC'")
        with self.assertRaises(InputError):
            odata_str("a\nb")
        with self.assertRaises(InputError):
            odata_str("")


class SettingsTests(unittest.TestCase):
    def test_profile_only_full_or_read(self):
        with self.assertRaises(SettingsError) as ctx:
            Settings.from_env(env(MCP_PROFILE="admin"))
        self.assertIn("MCP_PROFILE", str(ctx.exception))

    def test_development_minimal(self):
        s = Settings.from_env(env())
        self.assertEqual(s.profile, "full")
        self.assertEqual(s.required_scope, "access_as_user")
        self.assertNotIn("x" * 40, repr(s))
        self.assertEqual(s.describe()["client_secret"], "set")

    def test_missing_required(self):
        with self.assertRaises(SettingsError) as ctx:
            Settings.from_env({"MCP_ENV": "development"})
        for name in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "BASE_URL"):
            self.assertIn(name, str(ctx.exception))

    def test_production_needs_signing_key_only(self):
        with self.assertRaises(SettingsError) as ctx:
            Settings.from_env(env(MCP_ENV="production"))
        text = str(ctx.exception)
        self.assertIn("JWT_SIGNING_KEY", text)
        self.assertNotIn("REDIS_URL", text)
        s = Settings.from_env(env(MCP_ENV="production", JWT_SIGNING_KEY="j" * 48,
                                  ALLOWED_CLIENT_APP_IDS="33333333-3333-3333-3333-333333333333"))
        self.assertEqual(s.allowed_client_app_ids, ("33333333-3333-3333-3333-333333333333",))

    def test_client_app_ids_validated(self):
        with self.assertRaises(SettingsError) as ctx:
            Settings.from_env(env(ALLOWED_CLIENT_APP_IDS="copilot"))
        self.assertIn("ALLOWED_CLIENT_APP_IDS", str(ctx.exception))

    def test_production_valid(self):
        s = Settings.from_env(env(MCP_ENV="production", JWT_SIGNING_KEY="j" * 48, MCP_PROFILE="full"))
        self.assertEqual(s.profile, "full")
        self.assertNotEqual(s.signing_key("cursor"), s.signing_key("confirmation"))

    def test_invalid_values(self):
        with self.assertRaises(SettingsError) as ctx:
            Settings.from_env(env(MCP_PROFILE="superuser", TENANT_ID="common", MCP_HARD_MAX_ITEMS="abc"))
        text = str(ctx.exception)
        self.assertIn("MCP_PROFILE", text)
        self.assertIn("TENANT_ID", text)
        self.assertIn("MCP_HARD_MAX_ITEMS", text)

    def test_defender_api_host_is_pinned_to_microsoft(self):
        s = Settings.from_env(env(MDE_API_HOST="EU.api.security.microsoft.com", HUNTING_TIMEOUT_SECONDS="120"))
        self.assertEqual(s.mde_api_host, "eu.api.security.microsoft.com")
        self.assertEqual(s.mde_resource, "https://api.securitycenter.microsoft.com")
        self.assertEqual(s.hunting_timeout_seconds, 120.0)
        with self.assertRaises(SettingsError) as ctx:
            Settings.from_env(env(MDE_API_HOST="api.security.microsoft.com.evil.example",
                                  MDE_RESOURCE="https://evil.example.com", HUNTING_TIMEOUT_SECONDS="5"))
        text = str(ctx.exception)
        self.assertIn("MDE_API_HOST", text)
        self.assertIn("MDE_RESOURCE", text)
        self.assertIn("HUNTING_TIMEOUT_SECONDS", text)

    def test_signing_keys_are_purpose_bound(self):
        s = Settings.from_env(env(JWT_SIGNING_KEY="j" * 48))
        self.assertNotEqual(s.signing_key("cursor"), s.signing_key("confirmation"))

    def test_secret_masked(self):
        self.assertEqual(repr(Secret("abc")), "Secret('***')")


if __name__ == "__main__":
    unittest.main()
