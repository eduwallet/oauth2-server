#!/usr/bin/env bash
set -euo pipefail
PORT=${1:-8000}
cd "$(dirname "$0")"
PY=$(mktemp)
cat > "$PY" <<PY
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/client.json':
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','max-age=60')
            self.end_headers()
            host = self.headers.get('Host')
            scheme = 'http'
            base = f"{scheme}://{host}"
            payload = {
                "client_id": f"{base}/client.json",
                "redirect_uris": [f"{base}/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "openid profile",
            }
            self.wfile.write(json.dumps(payload).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', %d), Handler)
    print(server.server_address[1], flush=True)
    server.serve_forever()
PY

# Inject actual port value into the temporary python script
python3 - <<PYCODE
from pathlib import Path
p = Path('$PY')
s = p.read_text()
s = s % int('$PORT')
p.write_text(s)
PYCODE

python3 "$PY"
rm -f "$PY"
