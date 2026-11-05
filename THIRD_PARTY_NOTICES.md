# Third-party components

The server contains no third-party source code. The container build installs the following packages from PyPI
(`requirements.txt`); each is under its own license. After installation, the license texts are in the image
under `/opt/venv/lib/python3.12/site-packages/<package>.dist-info/`.

| Package | Purpose in the server | License | Source |
|---|---|---|---|
| fastmcp | MCP server framework, Entra token validation | Apache-2.0 | https://github.com/PrefectHQ/fastmcp |
| mcp | MCP Python SDK | MIT | https://github.com/modelcontextprotocol/python-sdk |
| httpx | HTTP client for Microsoft Graph and the Defender APIs | BSD-3-Clause | https://github.com/encode/httpx |
| uvicorn | ASGI web server | BSD-3-Clause | https://github.com/Kludex/uvicorn |
| azure-monitor-opentelemetry | Telemetry and audit log to Application Insights | MIT | https://github.com/Azure/azure-sdk-for-python |

Container base image: `python:3.12-slim` (Python under the PSF license, Debian packages under their respective
licenses).

These packages pull in further dependencies (e.g. pydantic, starlette, anyio, opentelemetry). The script
`scripts/third_party_licenses.py` produces the complete list with versions and licenses in an environment where
`requirements.txt` is installed; with `--texts` it also includes all license texts:

```bash
pip install -r requirements.txt
python scripts/third_party_licenses.py --texts > THIRD_PARTY_LICENSES.txt
```

For development and tests only, not in the image: the packages from `requirements-dev.txt` (pytest: MIT, ruff: MIT).
