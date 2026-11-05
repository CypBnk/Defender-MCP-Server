#!/usr/bin/env bash
# Creates requirements.lock with exact versions and hashes. Then run the tests and commit the
# lock file; the Dockerfile then installs exactly these versions.
set -euo pipefail
cd "$(dirname "$0")/.."
uv pip compile requirements.txt --generate-hashes --python-version 3.12 -o requirements.lock
echo "requirements.lock updated - please run the tests and review the diff."
