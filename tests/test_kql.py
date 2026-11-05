"""KQL layer: escaping, validators (no injection through tool arguments), execution and shaping."""
import unittest

from defender_mcp import kql
from defender_mcp.errors import GraphError, InputError
from helpers import MDE1, FakeGraph, configure, make_settings


class LiteralTests(unittest.TestCase):
    def test_kql_str_escapes_quotes_and_backslashes(self):
        self.assertEqual(kql.kql_str("O'Brien"), "'O\\'Brien'")
        self.assertEqual(kql.kql_str("C:\\temp\\"), "'C:\\\\temp\\\\'")
        # an injection attempt stays inside one literal
        lit = kql.kql_str("x' or 1==1 | take 1000000 //")
        self.assertTrue(lit.startswith("'x\\'"))
        self.assertTrue(lit.endswith("//'"))

    def test_kql_str_rejects_control_characters_and_empty(self):
        for bad in ("a\nb", "a\x00b", "", "   ", "x" * 300):
            with self.assertRaises(InputError, msg=repr(bad)):
                kql.kql_str(bad)

    def test_validators(self):
        self.assertEqual(kql.ip_address(" 203.0.113.7 "), "203.0.113.7")
        self.assertEqual(kql.ip_address("2001:db8::1"), "2001:db8::1")
        self.assertEqual(kql.domain("Evil.Example.COM."), "evil.example.com")
        self.assertEqual(kql.file_hash("A" * 64), ("sha256", "a" * 64))
        self.assertEqual(kql.file_hash("b" * 40), ("sha1", "b" * 40))
        self.assertEqual(kql.file_hash("c" * 32), ("md5", "c" * 32))
        self.assertEqual(kql.cve_id("cve-2024-21412"), "CVE-2024-21412")
        self.assertEqual(kql.account("CONTOSO\\max"), ("sam", "max"))
        self.assertEqual(kql.account("max@contoso.com"), ("upn", "max@contoso.com"))
        self.assertEqual(kql.account("{AAAAAAAA-0000-0000-0000-000000000001}")[0], "objectId")
        for fn, bad in ((kql.ip_address, "1.2.3"), (kql.domain, "https://x.com/a"), (kql.domain, "a b.com"),
                        (kql.file_hash, "xyz"), (kql.file_hash, "a" * 50), (kql.cve_id, "CVE-24-1"),
                        (kql.table_name, "Device Events | take 1"), (kql.device_name, "pc'01"),
                        (kql.url, "javascript:alert(1)"), (kql.account, "a' or 1==1")):
            with self.assertRaises(InputError, msg=f"{fn.__name__}({bad!r})"):
                fn(bad)
        with self.assertRaises(InputError):
            kql.file_hash("a" * 64, "sha1")

    def test_conditions(self):
        self.assertEqual(kql.device_condition("PC-01"),
                         "(DeviceName =~ 'PC-01' or DeviceName startswith 'PC-01.')")
        self.assertEqual(kql.device_condition(MDE1.upper()), f"DeviceId =~ '{MDE1}'")
        self.assertEqual(kql.account_condition("max@contoso.com"), "AccountUpn =~ 'max@contoso.com'")
        with self.assertRaises(InputError):
            kql.account_condition("max", sam=None)
        with self.assertRaises(InputError):
            kql.device_condition("aaaaaaaa-0000-0000-0000-000000000001")

    def test_days_and_query_limits(self):
        self.assertEqual(kql.days(30), 30)
        with self.assertRaises(InputError):
            kql.days(31)
        with self.assertRaises(InputError):
            kql.validate_query("x" * (kql.MAX_QUERY_CHARS + 1))
        with self.assertRaises(InputError):
            kql.validate_query("T | where a == '\x07'")
        self.assertEqual(kql.validate_query("T\n\t| take 1"), "T\n\t| take 1")

    def test_with_row_limit(self):
        self.assertEqual(kql.with_row_limit("T | take 5;  ", 51), "T | take 5\n| take 51")
        self.assertEqual(kql.with_row_limit("T // comment", 3), "T // comment\n| take 3")
        self.assertEqual(kql.with_row_limit("T | summarize count() by A | render piechart", 3),
                         "T | summarize count() by A | render piechart")


class ExecutionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.g = FakeGraph()
        configure(self.g, make_settings(hunting_timeout_seconds=77))

    async def test_rows_are_normalized_to_schema_names(self):
        self.g.on("POST", "/security/runHuntingQuery", {
            "schema": [{"name": "Timestamp", "type": "DateTime"}, {"name": "FileName", "type": "String"}],
            "results": [{"timestamp": "2026-11-01T00:00:00Z", "fileName": "cmd.exe"}]})
        columns, rows = await kql.execute("DeviceProcessEvents | take 1", timespan_days=60)
        self.assertEqual(columns, ["Timestamp", "FileName"])
        self.assertEqual(rows, [{"Timestamp": "2026-11-01T00:00:00Z", "FileName": "cmd.exe"}])
        call = self.g.calls[-1]
        self.assertEqual(call.json_body, {"Query": "DeviceProcessEvents | take 1", "Timespan": "P60D"})
        self.assertEqual(call.timeout, 77)

    async def test_hunt_truncates_and_reports(self):
        self.g.hunting(lambda q: [{"A": i, "Blob": "y" * 3000, "Empty": ""} for i in range(4)])
        res = await kql.hunt("T", max_items=3, hunt="x")
        self.assertEqual(res["count"], 3)
        self.assertTrue(res["truncated"])
        self.assertIn("hint", res)
        self.assertNotIn("Empty", res["rows"][0])
        self.assertIn("truncated", res["rows"][0]["Blob"])
        self.assertTrue(res["kql"].endswith("| take 4"))
        self.assertIn("note", res)

    async def test_kql_error_gets_hint(self):
        self.g.on("POST", "/security/runHuntingQuery",
                  GraphError(400, "BadRequest", "Failed to resolve column 'RiskScore'"))
        with self.assertRaises(GraphError) as ctx:
            await kql.execute("DeviceInfo | project RiskScore")
        self.assertIn("get_hunting_schema", str(ctx.exception))
        self.assertIn("RiskScore", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
