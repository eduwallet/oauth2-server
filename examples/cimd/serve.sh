#!/usr/bin/env bash
set -euo pipefail
PORT=${1:-8000}
cd "$(dirname "$0")"
python3 -m http.server "$PORT"
