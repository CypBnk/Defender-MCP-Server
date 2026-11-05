#!/usr/bin/env bash
# Check after a deployment (without user sign-in):
#   ./scripts/smoke_test.sh https://<app>.<region>.azurecontainerapps.io
set -euo pipefail
BASE="${1:?specify the base URL}"
fail() { echo "FAIL: $*"; exit 1; }

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz");  [ "$code" = 200 ] || fail "/healthz -> $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/readyz");   [ "$code" = 200 ] || fail "/readyz -> $code"
hdr=$(curl -s -D - -o /dev/null -X POST "$BASE/mcp" -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
echo "$hdr" | head -1 | grep -q " 401" || fail "/mcp without a token does not return 401"
echo "$hdr" | grep -qi "www-authenticate" || fail "no WWW-Authenticate header"
prm=$(curl -s -f "$BASE/.well-known/oauth-protected-resource/mcp" || curl -s -f "$BASE/.well-known/oauth-protected-resource") \
  || fail "no protected resource metadata"
echo "$prm" | grep -q "login.microsoftonline" || fail "authorization_servers does not point to Entra ID"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/.well-known/oauth-authorization-server")
[ "$code" != 200 ] || fail "OAuth server metadata reachable (the server must not offer OAuth endpoints of its own)"
reg=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/register" -H 'Content-Type: application/json' \
      -d '{"redirect_uris":["https://example.com/cb"]}')
case "$reg" in 2*) fail "/register reachable ($reg) (the server must not offer OAuth endpoints of its own)";; esac
echo "OK: health, readiness, 401 challenge and OAuth metadata as expected."
