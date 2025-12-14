# CIMD Example

This folder contains a tiny example metadata document and a simple web server to serve it locally for testing.

Files:
- `client.json` - sample metadata document
- `serve.sh` - small helper script to start a static server

How to run:

1. Start the metadata server:

```sh
cd examples/cimd
./serve.sh 8000
```

2. Start the oauth2-server configured to allow HTTP metadata (for testing):

```sh
CIMD_ENABLED=true CIMD_HTTP_PERMITTED=true API_KEY=changeme ./bin/oauth2-server
```

3. Use a browser or curl to trigger an authorization request and set `client_id` to `http://localhost:8000/client.json`.

Notes:
- Use `CIMD_HTTP_PERMITTED=true` only for local testing. In production metadata endpoints should be HTTPS.
- See `docs/CIMD.md` for more details and security recommendations.
