#!/usr/bin/env python3
"""
Mock OAuth2/OIDC Provider for Testing Proxy Mode
Simulates an upstream identity provider for proxy tests
"""

import json
import time
import base64
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import uuid

# Configuration
PORT = 9999
ISSUER = f"http://localhost:{PORT}"

# In-memory storage
tokens = {}
users = {
    "john.doe": {
        "password": "password123",
        "sub": "john.doe",
        "email": "upstream@example.com",
        "name": "John Doe",
        "given_name": "John",
        "family_name": "Doe",
        "preferred_username": "john.doe",
        "email_verified": True,
        "edumember_is_member_of": ["urn:collab:group:test.surfteams.nl:nl:surfnet:diensten:admins"]
    },
    "testuser": {
        "password": "testpass",
        "sub": "testuser",
        "email": "testuser@example.com",
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "preferred_username": "testuser",
        "email_verified": True,
    }
}


class MockOAuth2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def _set_headers(self, status=200, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def _json_response(self, data, status=200):
        self._set_headers(status)
        self.wfile.write(json.dumps(data).encode())

    def _error_response(self, error, description, status=400):
        self._json_response({
            "error": error,
            "error_description": description
        }, status)

    def do_OPTIONS(self):
        self._set_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # Health check
        if path == '/health' or path == '/':
            self._json_response({"status": "ok", "service": "mock-oauth2-provider"})
            return

        # Discovery endpoints
        if path == '/.well-known/openid-configuration':
            self._json_response({
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "userinfo_endpoint": f"{ISSUER}/userinfo",
                "jwks_uri": f"{ISSUER}/jwks",
                "introspection_endpoint": f"{ISSUER}/introspect",
                "revocation_endpoint": f"{ISSUER}/revoke",
                "device_authorization_endpoint": f"{ISSUER}/device",
                "scopes_supported": ["openid", "profile", "email", "offline_access"],
                "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
                "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "client_credentials", "password", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "given_name", "family_name", "preferred_username"],
                "code_challenge_methods_supported": ["plain", "S256"]
            })
            return

        if path == '/jwks':
            # Return minimal JWKS (not actually used in proxy tests)
            self._json_response({"keys": []})
            return

        # Authorization endpoint (simulate user login)
        if path == '/authorize':
            # Parse query parameters
            query_params = parse_qs(parsed_path.query)
            redirect_uri = query_params.get('redirect_uri', [None])[0]
            state = query_params.get('state', [None])[0]
            scope = query_params.get('scope', ['openid'])[0]
            claims = query_params.get('claims', [None])[0]
            
            if not redirect_uri:
                self._error_response("invalid_request", "Missing redirect_uri")
                return
            
            # Log claims if provided
            if claims:
                print(f"Mock provider received claims: {claims}", flush=True)
            
            # Generate authorization code
            auth_code = f"mock_code_{secrets.token_urlsafe(20)}"
            
            # Build redirect URL with code
            separator = '&' if '?' in redirect_uri else '?'
            redirect_url = f"{redirect_uri}{separator}code={auth_code}"
            if state:
                redirect_url += f"&state={state}"
            
            # Send redirect
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            return

        # Userinfo endpoint
        if path == '/userinfo':
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self._error_response("invalid_token", "Missing or invalid authorization header", 401)
                return

            access_token = auth_header[7:]
            token_data = tokens.get(access_token)
            
            if not token_data:
                self._error_response("invalid_token", "Token not found", 401)
                return

            if token_data.get('expires_at', 0) < time.time():
                self._error_response("invalid_token", "Token expired", 401)
                return

            user_data = token_data.get('user_data', {})
            # Return all user data fields to include requested claims
            response_data = {
                "sub": user_data.get("sub"),
                "email": user_data.get("email"),
                "name": user_data.get("name"),
                "given_name": user_data.get("given_name"),
                "family_name": user_data.get("family_name"),
                "preferred_username": user_data.get("preferred_username"),
                "email_verified": user_data.get("email_verified", False)
            }
            # Add any additional claims from user data
            for key, value in user_data.items():
                if key not in response_data:
                    response_data[key] = value
            self._json_response(response_data)
            return

        self._error_response("not_found", "Endpoint not found", 404)

    def do_POST(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(body)

        # Extract single values from lists
        def get_param(name):
            return params.get(name, [None])[0]

        # Token endpoint
        if path == '/token':
            grant_type = get_param('grant_type')

            # Authorization code flow
            if grant_type == 'authorization_code':
                code = get_param('code')
                # Accept mock_code_, test-auth-code, and mock_auth_code_ (for various test scenarios)
                if not code or (not code.startswith('mock_code_') and not code.startswith('mock_auth_code_') and code != 'test-auth-code'):
                    self._error_response("invalid_grant", f"Invalid authorization code: {code}")
                    return

                # Generate tokens
                access_token = f"mock_access_{secrets.token_urlsafe(32)}"
                refresh_token = f"mock_refresh_{secrets.token_urlsafe(32)}"
                id_token = self._generate_id_token(users["john.doe"]["sub"])

                # Store token with user data
                tokens[access_token] = {
                    "user_data": users["john.doe"],
                    "scope": "openid profile email",
                    "expires_at": time.time() + 3600
                }
                tokens[refresh_token] = {
                    "user_data": users["john.doe"],
                    "scope": "openid profile email",
                    "expires_at": time.time() + 86400
                }

                self._json_response({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": refresh_token,
                    "id_token": id_token,
                    "scope": "openid profile email"
                })
                return

            # Password grant (for device flow and testing)
            elif grant_type == 'password':
                username = get_param('username')
                password = get_param('password')

                user = users.get(username)
                if not user or user['password'] != password:
                    self._error_response("invalid_grant", "Invalid username or password")
                    return

                access_token = f"mock_access_{secrets.token_urlsafe(32)}"
                refresh_token = f"mock_refresh_{secrets.token_urlsafe(32)}"
                id_token = self._generate_id_token(user['sub'])

                tokens[access_token] = {
                    "user_data": user,
                    "scope": "openid profile email",
                    "expires_at": time.time() + 3600
                }
                tokens[refresh_token] = {
                    "user_data": user,
                    "scope": "openid profile email",
                    "expires_at": time.time() + 86400
                }

                self._json_response({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": refresh_token,
                    "id_token": id_token,
                    "scope": "openid profile email"
                })
                return

            # Refresh token grant
            elif grant_type == 'refresh_token':
                refresh_token = get_param('refresh_token')
                token_data = tokens.get(refresh_token)

                if not token_data:
                    self._error_response("invalid_grant", "Invalid refresh token")
                    return

                access_token = f"mock_access_{secrets.token_urlsafe(32)}"
                new_refresh_token = f"mock_refresh_{secrets.token_urlsafe(32)}"

                tokens[access_token] = {
                    "user_data": token_data['user_data'],
                    "scope": token_data['scope'],
                    "expires_at": time.time() + 3600
                }
                tokens[new_refresh_token] = token_data

                self._json_response({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": new_refresh_token,
                    "scope": token_data['scope']
                })
                return

            # Client credentials
            elif grant_type == 'client_credentials':
                access_token = f"mock_access_{secrets.token_urlsafe(32)}"
                
                tokens[access_token] = {
                    "user_data": {},
                    "scope": get_param('scope') or "api",
                    "expires_at": time.time() + 3600
                }

                self._json_response({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": tokens[access_token]['scope']
                })
                return

            # Device code grant
            elif grant_type == 'urn:ietf:params:oauth:grant-type:device_code':
                device_code = get_param('device_code')
                if not device_code or not device_code.startswith('mock_device_'):
                    self._error_response("invalid_grant", "Invalid device code")
                    return

                access_token = f"mock_access_{secrets.token_urlsafe(32)}"
                refresh_token = f"mock_refresh_{secrets.token_urlsafe(32)}"
                id_token = self._generate_id_token("user123")

                tokens[access_token] = {
                    "user_data": users["john.doe"],
                    "scope": "openid profile email",
                    "expires_at": time.time() + 3600
                }
                tokens[refresh_token] = {
                    "user_data": users["john.doe"],
                    "scope": "openid profile email",
                    "expires_at": time.time() + 86400
                }

                self._json_response({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": refresh_token,
                    "id_token": id_token,
                    "scope": "openid profile email"
                })
                return

            # Token exchange grant (RFC 8693)
            elif grant_type == 'urn:ietf:params:oauth:grant-type:token-exchange':
                subject_token = get_param('subject_token')
                subject_token_type = get_param('subject_token_type')
                requested_token_type = get_param('requested_token_type')
                audience = get_param('audience')
                scope = get_param('scope')

                # Validate subject token
                if not subject_token:
                    self._error_response("invalid_request", "Missing subject_token")
                    return

                # Verify the subject token exists and is valid
                token_data = tokens.get(subject_token)
                if not token_data:
                    self._error_response("invalid_grant", "Invalid subject token")
                    return

                if token_data.get('expires_at', 0) < time.time():
                    self._error_response("invalid_grant", "Subject token expired")
                    return

                # Generate new access token for the requested audience
                access_token = f"mock_access_{secrets.token_urlsafe(32)}"
                
                # Preserve user data from subject token
                user_data = token_data.get('user_data', {})
                new_scope = scope or token_data.get('scope', 'openid profile email')
                
                tokens[access_token] = {
                    "user_data": user_data,
                    "scope": new_scope,
                    "audience": audience,
                    "expires_at": time.time() + 3600
                }

                response = {
                    "access_token": access_token,
                    "issued_token_type": requested_token_type or "urn:ietf:params:oauth:token-type:access_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": new_scope
                }

                # Include audience if specified
                if audience:
                    response["audience"] = audience

                self._json_response(response)
                return

                self._json_response({
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": refresh_token,
                    "id_token": id_token,
                    "scope": "openid profile email"
                })
                return

            self._error_response("unsupported_grant_type", f"Grant type '{grant_type}' not supported")
            return

        # Introspection endpoint
        if path == '/introspect':
            token = get_param('token')
            token_data = tokens.get(token)

            if not token_data:
                self._json_response({"active": False})
                return

            is_active = token_data.get('expires_at', 0) > time.time()
            
            response = {
                "active": is_active,
                "scope": token_data.get('scope', ''),
                "client_id": "mock_client",
                "username": token_data.get('user_data', {}).get('preferred_username'),
                "token_type": "Bearer",
                "exp": int(token_data.get('expires_at', 0)),
                "sub": token_data.get('user_data', {}).get('sub')
            }

            self._json_response(response)
            return

        # Device authorization endpoint
        if path == '/device':
            client_id = get_param('client_id')
            scope = get_param('scope') or 'openid profile'

            device_code = f"mock_device_{secrets.token_urlsafe(20)}"
            user_code = secrets.token_hex(4).upper()

            self._json_response({
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": f"{ISSUER}/device/verify",
                "verification_uri_complete": f"{ISSUER}/device/verify?user_code={user_code}",
                "expires_in": 900,
                "interval": 5
            })
            return

        # Device verification endpoint (user enters code)
        if path == '/device/verify':
            user_code = get_param('user_code')
            # In a real scenario, this would verify the user code and complete the flow
            # For testing, we just acknowledge it
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body>Authorized Successfully</body></html>')
            return

        # Revocation endpoint
        if path == '/revoke':
            token = get_param('token')
            if token in tokens:
                del tokens[token]
            self._set_headers(200)
            return

        self._error_response("not_found", "Endpoint not found", 404)

    def _generate_id_token(self, sub):
        """Generate a mock ID token (not cryptographically valid, just for testing)"""
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": ISSUER,
            "sub": sub,
            "aud": "mock_client",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nonce": secrets.token_urlsafe(16)
        }
        
        # Base64 encode (not signed, just for testing)
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = base64.urlsafe_b64encode(b'mock_signature').decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"


def run_server():
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, MockOAuth2Handler)
    print(f'Mock OAuth2 Provider running on port {PORT}...', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down mock provider...', flush=True)
        httpd.shutdown()


if __name__ == '__main__':
    run_server()
