"""deploy.settings.example.psd1 and the settings handling in deploy.ps1 stay consistent (no PowerShell needed)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = (ROOT / "deploy.ps1").read_text(encoding="utf-8")
TEMPLATE = (ROOT / "deploy.settings.example.psd1").read_text(encoding="utf-8")

_STRING = r"'(?:[^']|'')*'"
_LINE = re.compile(r"^    (\w+) = (" + _STRING + r"|@\(\)|@\(" + _STRING + r"(?:, " + _STRING + r")*\))$")


def _settings_map() -> dict:
    body = re.search(r"\$SETTINGS_MAP = \[ordered\]@\{(.*?)\n\}", DEPLOY, re.S).group(1)
    return dict(re.findall(r"(\w+) = '([\w.]+)'", body))


def _lists() -> set:
    return set(re.findall(r"'(\w+)'", re.search(r"\$SETTINGS_LISTS = @\(([^)]*)\)", DEPLOY).group(1)))


def _template_entries() -> dict:
    lines = TEMPLATE.split("\n")
    start = next(i for i, line in enumerate(lines) if line.strip() == "@{")
    end = max(i for i, line in enumerate(lines) if line.strip() == "}")
    entries = {}
    for line in lines[start + 1:end]:
        if not line.strip() or line.strip().startswith("#"):
            continue
        m = _LINE.match(line)
        assert m, f"not a one-line 'Name = value' entry without trailing comment: {line!r}"
        assert m.group(1) not in entries, f"duplicate setting {m.group(1)}"
        entries[m.group(1)] = m.group(2)
    return entries


class DeploySettingsTests(unittest.TestCase):
    def test_template_only_data_lines(self):
        self.assertTrue(TEMPLATE.lstrip().startswith("#"))
        self.assertEqual(sum(1 for line in TEMPLATE.split("\n") if line.strip() == "@{"), 1)
        self.assertNotIn("$", TEMPLATE.split("@{", 1)[1], "variables are not allowed in a data file")
        self.assertGreater(len(_template_entries()), 20)

    def test_template_matches_settings_map(self):
        self.assertEqual(set(_template_entries()), set(_settings_map()))

    def test_list_settings_are_lists(self):
        entries, lists = _template_entries(), _lists()
        self.assertTrue(lists <= set(entries))
        for key, value in entries.items():
            self.assertEqual(value.startswith("@("), key in lists, key)

    def test_map_targets_are_script_variables(self):
        for key, target in _settings_map().items():
            self.assertRegex(target, r"^(SERVER\.[A-Za-z]+|[A-Z_]+)$", key)

    def test_saved_settings_are_known(self):
        saved = set(re.findall(r"Save-Setting '(\w+)'", DEPLOY))
        self.assertTrue(saved, "deploy.ps1 saves determined values")
        self.assertTrue(saved <= set(_settings_map()), saved - set(_settings_map()))
        self.assertNotIn("Save-ConfigLine", DEPLOY)

    def test_no_auto_placeholders_besides_auto(self):
        for key, value in _template_entries().items():
            if "<" in value:
                self.assertEqual(value, "'<auto>'", key)


    def test_no_remnants_of_removed_features(self):
        shipped = {"deploy.ps1": DEPLOY, "deploy.settings.example.psd1": TEMPLATE,
                   "infra/main.bicep": (ROOT / "infra" / "main.bicep").read_text(encoding="utf-8"),
                   ".env.example": (ROOT / ".env.example").read_text(encoding="utf-8"),
                   "scripts/smoke_test.ps1": (ROOT / "scripts" / "smoke_test.ps1").read_text(encoding="utf-8"),
                   "scripts/smoke_test.sh": (ROOT / "scripts" / "smoke_test.sh").read_text(encoding="utf-8")}
        shipped.update({str(p.relative_to(ROOT)): p.read_text(encoding="utf-8")
                        for p in (ROOT / "src").rglob("*.py")})
        removed = re.compile(r"AuthMode|AUTH_MODE|auth_mode|[Rr]edis|deploy\.config|SETTINGS_RETIRED|auth/callback|"
                             r"MCP_APP_ID_URI|appIdUri|app_id_uri|SystemAssigned|user_impersonation|riskRating|"
                             r"\b(?:in|since|until|up to|before) 2\.\d")
        hits = {name: removed.findall(text) for name, text in shipped.items() if removed.search(text)}
        self.assertEqual(hits, {})

if __name__ == "__main__":
    unittest.main()
