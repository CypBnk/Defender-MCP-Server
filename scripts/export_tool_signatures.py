"""Regenerate tests/tool_signatures.json (the tool contract seen by Copilot Studio).
Run deliberately after changing tool names or parameters, then review the diff."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The test modules import defender_mcp before helpers (isort order), so src must be importable here too.
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "src"))

from test_registry_app import SNAPSHOT, signature_snapshot  # noqa: E402

with open(SNAPSHOT, "w", encoding="utf-8") as fh:
    json.dump(signature_snapshot(), fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"wrote {SNAPSHOT}")
