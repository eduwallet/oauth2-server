# Client-Initiated Metadata Discovery (CIMD)

This document explains how the server implements CIMD (client-initiated metadata discovery), how to configure it, and how to run the example in `examples/cimd`.

## Overview

CIMD allows a client to reference its metadata by URL (the `client_id` is a URL). The server fetches that metadata, validates it against policy, and registers the client on-the-fly.

## Configuration

Environment variables (also supported through YAML `pkg/config`):

- `CIMD_ENABLED` (bool) — enable CIMD handling (default: `false`).
- `CIMD_HTTP_PERMITTED` (bool) — allow `http://` metadata URLs for testing (default: `false`).
- `CIMD_QUERY_PERMITTED` (bool) — allow query string in metadata URLs (default: `false`).
- `CIMD_ALLOWLIST` (comma-separated) — host allowlist; if set, metadata hosts not on the allowlist are rejected.
- `CIMD_METADATA_POLICY_ENABLED` (bool) — enable the metadata policy checks.
- `CIMD_METADATA_POLICY` (string) — simple semicolon-separated policy (examples below).
- `CIMD_CACHE_MAX_SECONDS` (int) — max TTL for cached metadata documents.
- `CIMD_ALWAYS_RETRIEVED` (bool) — when true always fetch the metadata instead of using cache.
- `CIMD_FETCH_LIMIT` (int) — maximum number of metadata fetches allowed per host in the configured window (default: 60).
- `CIMD_FETCH_WINDOW_SECONDS` (int) — window in seconds for the fetch limit (default: 60).

Security notes:
- By default only `https` metadata URLs are allowed. Use `CIMD_HTTP_PERMITTED=true` only for local testing.
- Metadata documents MUST NOT include a `client_secret`.
- The server performs policy checks; configure `CIMD_METADATA_POLICY` to enforce required fields or grant types.
- Rate-limiting is applied per-host to prevent abuse.

## Policy examples

- `required_fields:client_id,redirect_uris;required_grant_types:authorization_code` — requires those fields.
- `forbidden_fields:client_secret` — ensures sensitive fields are absent.

## Example

`examples/cimd` contains a small static metadata document (`client.json`) and a helper `serve.sh` to run a local HTTP server (for tests you can set `CIMD_HTTP_PERMITTED=true`).

Usage:

1. Start metadata server:

```sh
cd examples/cimd
./serve.sh 8000
```

2. Start the oauth2 server with CIMD enabled (for testing only):

```sh
CIMD_ENABLED=true CIMD_HTTP_PERMITTED=true API_KEY=changeme ./bin/oauth2-server
```

3. Trigger an authorization request where `client_id` is `http://localhost:8000/client.json` (the server will fetch and register it automatically).

## Implementation notes

- Metadata fetches are cached (TTL from `Cache-Control`/`Expires` or `CIMD_CACHE_MAX_SECONDS` cap).
- The server enforces an allowlist and a small metadata policy language.
- When a metadata document is accepted, the registered client is stored with `DiscoveredByMetadataDocument=true` and cache metadata is saved.

## Next steps

- Consider adding configurable per-host rate-limits and monitoring for fetch operations.
- Document recommended allowlist patterns for production.
- Consider adding signed metadata support in the future.
