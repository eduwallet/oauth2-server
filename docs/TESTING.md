# Testing Guide

## Running Tests

```bash
# Run all tests
make test

# Run specific test script
make test-script SCRIPT=test_attestation_privileged_audience.sh

# Run tests with coverage
make test-coverage
```

## Test Scripts

The `tests/` directory contains comprehensive automated test scripts for validating various OAuth2/OIDC flows, attestation-based authentication, and advanced features. Each test script includes detailed validation steps and expected results.

### `test_attestation_privileged_audience.sh` - Privileged Client Audience Inclusion Test

Validates that attestation-enabled clients automatically receive privileged clients in their audience for token introspection capabilities.

```bash
# Run the privileged audience inclusion test
make test-script SCRIPT=test_attestation_privileged_audience.sh
```

**Test Flow:**
1. **Client Registration**: Registers an attestation-enabled client with trust anchor configuration
2. **Grant Type Verification**: Confirms `client_credentials` grant type is automatically added
3. **Audience Verification**: Validates privileged client (`server-owned-client`) is included in audience array
4. **Token Acquisition**: Obtains access token for the privileged client
5. **Introspection Validation**: Confirms privileged client can successfully introspect attestation client tokens

**Expected Results:**
- ✅ Attestation client registration succeeds with trust anchor
- ✅ `client_credentials` grant type automatically added to grant types
- ✅ Privileged client included in the client's audience array
- ✅ Privileged client token acquisition works
- ✅ Audience-based token introspection functions correctly

### `test_introspection_jwt_client_assertion.sh` - JWT Client Assertion Introspection Test

Validates JWT client assertion authentication for RFC 7662 token introspection with privileged client access.

```bash
# Run the JWT client assertion introspection test
make test-script SCRIPT=test_introspection_jwt_client_assertion.sh
```

**Test Flow:**
1. **Trust Anchor Upload**: Uploads X.509 trust anchor certificate for attestation validation
2. **Client Registration**: Registers attestation-enabled client with JWT client assertion authentication
3. **JWT Assertion Creation**: Generates signed JWT with attestation claims and certificate chain
4. **Token Acquisition**: Obtains access token using JWT client assertion authentication
5. **Privileged Client Setup**: Acquires privileged client token for introspection access
6. **Token Introspection**: Validates privileged client can introspect attestation client tokens
7. **Response Verification**: Confirms introspection response includes attestation metadata

**Expected Results:**
- ✅ Trust anchor certificate upload succeeds
- ✅ Attestation client registration with JWT assertion method works
- ✅ JWT assertion generation with attestation claims succeeds
- ✅ Token acquisition using JWT client assertion authentication works
- ✅ Privileged client token acquisition for introspection succeeds
- ✅ Token introspection by privileged client functions correctly
- ✅ Introspection response includes attestation metadata for attested tokens

### `test_auth_code_pkce.sh` - Authorization Code Flow with PKCE

Tests the complete OAuth2 authorization code flow with Proof Key for Code Exchange (PKCE) security enhancement.

```bash
# Run the PKCE authorization code flow test
make test-script SCRIPT=test_auth_code_pkce.sh
```

**Test Flow:**
1. **Client Registration**: Registers a client with authorization code grant type
2. **PKCE Setup**: Generates code verifier and challenge using S256 method
3. **Authorization Request**: Initiates authorization request with PKCE parameters
4. **User Authentication**: Simulates user login and consent
5. **Code Exchange**: Exchanges authorization code for tokens using PKCE verification
6. **Token Validation**: Verifies access token and refresh token are valid

**Expected Results:**
- ✅ Client registration succeeds
- ✅ PKCE code challenge and verifier generated correctly
- ✅ Authorization code obtained successfully
- ✅ Token exchange with PKCE verification succeeds
- ✅ Access and refresh tokens are valid and functional

### `test_client_registration.sh` - Dynamic Client Registration

Validates the OAuth2 Dynamic Client Registration Protocol (RFC 7591) implementation.

```bash
# Run the dynamic client registration test
make test-script SCRIPT=test_client_registration.sh
```

**Test Flow:**
1. **Client Registration Request**: Sends registration request with client metadata
2. **Registration Processing**: Server processes and validates registration data
3. **Client ID Assignment**: Generates unique client identifier
4. **Metadata Storage**: Stores client configuration and credentials
5. **Registration Response**: Returns client configuration with registration access token
6. **Client Validation**: Verifies registered client can authenticate and obtain tokens

**Expected Results:**
- ✅ Client registration request accepted
- ✅ Unique client ID generated and returned
- ✅ Client metadata properly stored
- ✅ Registration access token provided for future updates
- ✅ Registered client can successfully authenticate

### `test_complete_flow.sh` - Complete OAuth2 Authorization Code Flow

Tests the full OAuth2 authorization code grant flow from start to finish.

```bash
# Run the complete OAuth2 flow test
make test-script SCRIPT=test_complete_flow.sh
```

**Test Flow:**
1. **Client Setup**: Registers client with authorization code grant type
2. **Authorization Request**: Initiates authorization request with required parameters
3. **User Authentication**: Simulates user login process
4. **Consent Grant**: User grants consent for requested scopes
5. **Authorization Code**: Server issues authorization code
6. **Token Exchange**: Client exchanges code for access and refresh tokens
7. **Token Usage**: Validates tokens work for protected resource access
8. **Refresh Token**: Tests token renewal using refresh token

**Expected Results:**
- ✅ Authorization request processed successfully
- ✅ User authentication and consent completed
- ✅ Authorization code issued and valid
- ✅ Token exchange succeeds with proper validation
- ✅ Access token works for resource access
- ✅ Refresh token enables token renewal

### `test_device_flow.sh` - Device Authorization Grant

Tests the OAuth2 Device Authorization Grant (RFC 8628) for input-constrained devices.

```bash
# Run the device authorization grant test
make test-script SCRIPT=test_device_flow.sh
```

**Test Flow:**
1. **Device Authorization Request**: Device requests authorization without user interaction
2. **User Code Generation**: Server generates user code and verification URI
3. **User Interaction**: User visits verification URI and enters device code
4. **Device Polling**: Device polls token endpoint for authorization status
5. **Token Issuance**: Server issues tokens once user completes authorization
6. **Token Validation**: Verifies issued tokens are valid and functional

**Expected Results:**
- ✅ Device authorization request accepted
- ✅ User code and verification URI generated
- ✅ User verification process works
- ✅ Device polling succeeds after user authorization
- ✅ Access and refresh tokens issued correctly
- ✅ Tokens are valid for resource access

### `test_proxy_device_flow.sh` - Proxy Mode Device Authorization Grant

Tests the OAuth2 Device Authorization Grant (RFC 8628) in proxy mode, forwarding requests to upstream providers with code mapping and token exchange.

```bash
# Run the proxy device authorization grant test
make test-script SCRIPT=test_proxy_device_flow.sh
```

**Test Flow:**
1. **Proxy Configuration**: Sets up server in proxy mode with upstream provider supporting device authorization
2. **Device Authorization Request**: Device requests authorization in proxy mode
3. **Upstream Forwarding**: Server forwards request to upstream device authorization endpoint
4. **Code Mapping**: Maps proxy device/user codes to upstream codes for correlation
5. **User Verification**: User verifies at upstream provider using upstream user code
6. **Token Polling**: Device polls proxy server for authorization status
7. **Token Exchange**: Proxy server handles device_code grant type and returns upstream tokens directly
8. **Introspection Validation**: Confirms proxy tokens work with expected introspection limitations

**Expected Results:**
- ✅ Proxy mode device authorization request accepted
- ✅ Request successfully forwarded to upstream provider
- ✅ Proxy device/user codes mapped to upstream codes
- ✅ User verification redirects to upstream verification URI
- ✅ Device polling succeeds after upstream user authorization
- ✅ Tokens issued from upstream provider through proxy
- ✅ Token introspection functions with proxy-specific behavior (may not include full upstream metadata)

### `test_introspection.sh` - Token Introspection

Validates RFC 7662 Token Introspection endpoint functionality.

```bash
# Run the token introspection test
make test-script SCRIPT=test_introspection.sh
```

**Test Flow:**
1. **Token Acquisition**: Obtains access token through client credentials flow
2. **Introspection Request**: Client requests token introspection with proper authentication
3. **Token Validation**: Server validates token and client authorization
4. **Metadata Retrieval**: Returns comprehensive token metadata and claims
5. **Response Verification**: Validates introspection response contains correct information
6. **Inactive Token Test**: Tests introspection of expired/revoked tokens

**Expected Results:**
- ✅ Token introspection request authenticated
- ✅ Active token returns full metadata
- ✅ Token claims and scopes correctly reported
- ✅ Inactive tokens properly identified
- ✅ Client authorization enforced

### `test_oauth2_flow.sh` - Basic OAuth2 Flows

Tests fundamental OAuth2 grant types and basic server functionality.

```bash
# Run the basic OAuth2 flows test
make test-script SCRIPT=test_oauth2_flow.sh
```

**Test Flow:**
1. **Client Credentials Flow**: Tests machine-to-machine authentication
2. **Authorization Code Setup**: Prepares for authorization code flow testing
3. **Token Validation**: Verifies token format and basic claims
4. **Scope Handling**: Tests scope parameter processing
5. **Error Handling**: Validates proper error responses for invalid requests
6. **Endpoint Discovery**: Confirms OAuth2 discovery endpoints work

**Expected Results:**
- ✅ Client credentials grant succeeds
- ✅ Token format and claims are valid
- ✅ Scope parameters processed correctly
- ✅ Error responses follow OAuth2 standards
- ✅ Discovery endpoints return proper metadata

### `test_privileged_introspection.sh` - Privileged Client Introspection

Tests privileged client capabilities for introspecting tokens from other clients.

```bash
# Run the privileged introspection test
make test-script SCRIPT=test_privileged_introspection.sh
```

**Test Flow:**
1. **Privileged Client Setup**: Configures privileged client with admin credentials
2. **Regular Client Token**: Obtains token from regular client
3. **Privileged Introspection**: Privileged client introspects regular client token
4. **Access Verification**: Confirms privileged client can access token metadata
5. **Security Validation**: Ensures proper authorization controls are enforced
6. **Audit Logging**: Verifies introspection attempts are logged

**Expected Results:**
- ✅ Privileged client authentication succeeds
- ✅ Cross-client token introspection works
- ✅ Token metadata accessible to privileged client
- ✅ Security boundaries maintained
- ✅ Introspection events properly logged

### `test_public_client_flow.sh` - Public Client Flows

Tests OAuth2 flows for public clients (no client secret).

```bash
# Run the public client flows test
make test-script SCRIPT=test_public_client_flow.sh
```

**Test Flow:**
1. **Public Client Registration**: Registers client without secret
2. **PKCE Requirement**: Ensures PKCE is enforced for public clients
3. **Authorization Code Flow**: Completes flow with PKCE but no client secret
4. **Token Exchange**: Exchanges code for tokens without client authentication
5. **Security Validation**: Confirms proper security measures for public clients
6. **Scope Limitation**: Tests scope restrictions for public clients

**Expected Results:**
- ✅ Public client registration succeeds
- ✅ PKCE enforcement for public clients
- ✅ Authorization flow completes without client secret
- ✅ Token exchange works for public clients
- ✅ Security measures properly implemented

### `test_scope_handling.sh` - Scope Validation and Handling

Tests OAuth2 scope parameter processing and validation.

```bash
# Run the scope handling test
make test-script SCRIPT=test_scope_handling.sh
```

**Test Flow:**
1. **Scope Request**: Client requests specific scopes in authorization/token requests
2. **Scope Validation**: Server validates requested scopes against allowed scopes
3. **Scope Grant**: User/consent process includes scope approval
4. **Token Scopes**: Issued tokens contain granted scopes
5. **Scope Enforcement**: Protected resources enforce token scopes
6. **Scope Reduction**: Tests scope reduction in token exchange scenarios

**Expected Results:**
- ✅ Scope parameters parsed correctly
- ✅ Invalid scopes rejected appropriately
- ✅ Token scopes match granted scopes
- ✅ Resource access respects token scopes
- ✅ Scope reduction works in token exchange

### `test_token_exchange.sh` - Token Exchange Functionality

Tests RFC 8693 OAuth2 Token Exchange implementation.

```bash
# Run the token exchange test
make test-script SCRIPT=test_token_exchange.sh
```

**Test Flow:**
1. **Subject Token Acquisition**: Obtains initial access token as subject
2. **Token Exchange Request**: Requests new token using subject token
3. **Exchange Processing**: Server validates and processes exchange request
4. **New Token Issuance**: Issues new token with specified parameters
5. **Token Validation**: Verifies exchanged token has correct claims and scopes
6. **Delegation Chain**: Tests token exchange delegation scenarios

**Expected Results:**
- ✅ Token exchange request accepted
- ✅ Subject token validation succeeds
- ✅ New token issued with correct parameters
- ✅ Token claims properly transferred
- ✅ Delegation and impersonation work correctly

### `test_refresh_token_basic.sh` - Basic Refresh Token Functionality

Tests fundamental refresh token operations and renewal.

```bash
# Run the basic refresh token test
make test-script SCRIPT=test_refresh_token_basic.sh
```

**Test Flow:**
1. **Client Registration**: Registers client with refresh token grant type
2. **Initial Token Acquisition**: Completes authorization code flow to get initial tokens
3. **Token Renewal**: Uses refresh token to obtain new access token
4. **Token Validation**: Verifies new token is valid and different from original
5. **Multiple Renewals**: Tests repeated refresh operations
6. **Refresh Token Persistence**: Confirms refresh token remains valid across renewals

**Expected Results:**
- ✅ Client registration with refresh token support succeeds
- ✅ Initial authorization code flow completes
- ✅ Refresh token issued alongside access token
- ✅ Token renewal using refresh token works
- ✅ New access tokens are valid and unique
- ✅ Refresh token remains valid for multiple uses

### `test_refresh_token_exchange.sh` - Advanced Refresh Token Exchange

Tests complex refresh token exchange scenarios between multiple clients.

```bash
# Run the refresh token exchange test
make test-script SCRIPT=test_refresh_token_exchange.sh
```

**Test Flow:**
1. **Multi-Client Setup**: Registers multiple clients for cross-client scenarios
2. **Refresh Token Acquisition**: Obtains refresh tokens for different clients
3. **Token Exchange Request**: Uses refresh tokens as subjects in exchange requests
4. **Cross-Client Exchange**: Tests exchanging refresh tokens between different clients
5. **Audience Validation**: Verifies exchanged tokens have correct audience claims
6. **Token Functionality**: Confirms exchanged tokens work for intended purposes

**Expected Results:**
- ✅ Multiple client registration succeeds
- ✅ Refresh token acquisition works for all clients
- ✅ Token exchange with refresh token as subject succeeds
- ✅ Cross-client refresh token exchange functions correctly
- ✅ Exchanged tokens have proper audience configuration
- ✅ Exchanged tokens are functional for target audiences

### `test_userinfo.sh` - UserInfo Endpoint Validation

Tests OpenID Connect UserInfo endpoint functionality.

```bash
# Run the UserInfo endpoint test
make test-script SCRIPT=test_userinfo.sh
```

**Test Flow:**
1. **OIDC Flow Completion**: Completes OpenID Connect authorization code flow
2. **Access Token Acquisition**: Obtains access token with openid scope
3. **UserInfo Request**: Requests user information using access token
4. **Claim Validation**: Verifies returned claims match authenticated user
5. **Scope Enforcement**: Tests that appropriate claims are returned based on scopes
6. **Security Validation**: Confirms proper token validation and authorization

**Expected Results:**
- ✅ OpenID Connect flow completes successfully
- ✅ Access token obtained with appropriate scopes
- ✅ UserInfo endpoint returns correct user claims
- ✅ Claims respect granted scopes
- ✅ Token validation and authorization enforced

### `test_validation.sh` - Request Validation

Tests comprehensive input validation and error handling.

```bash
# Run the validation test
make test-script SCRIPT=test_validation.sh
```

**Test Flow:**
1. **Invalid Parameter Testing**: Tests various invalid request parameters
2. **Malformed Request Handling**: Validates server response to malformed requests
3. **Security Validation**: Tests protection against common attack vectors
4. **Error Response Format**: Verifies proper OAuth2 error response format
5. **Boundary Testing**: Tests edge cases and boundary conditions
6. **Input Sanitization**: Confirms proper input validation and sanitization

**Expected Results:**
- ✅ Invalid requests properly rejected
- ✅ Appropriate error responses returned
- ✅ Security vulnerabilities mitigated
- ✅ Error messages follow OAuth2 standards
- ✅ Input validation prevents malicious requests

### `test_proxy_attestation_client.sh` - Proxy Mode Attestation

Tests attestation-based client authentication in proxy mode.

```bash
# Run the proxy attestation test
make test-script SCRIPT=test_proxy_attestation_client.sh
```

**Test Flow:**
1. **Proxy Configuration**: Sets up server in proxy mode with upstream provider
2. **Attestation Client Setup**: Registers client with attestation requirements
3. **Attestation Verification**: Client authenticates using attestation credentials
4. **Proxy Token Issuance**: Server issues proxy-controlled tokens
5. **Upstream Communication**: Validates proxying to upstream provider
6. **Token Mapping**: Tests mapping between proxy and upstream tokens

**Expected Results:**
- ✅ Proxy mode configuration succeeds
- ✅ Attestation verification works in proxy mode
- ✅ Proxy tokens issued correctly
- ✅ Upstream provider communication succeeds
- ✅ Token mapping functions properly

### Additional Test Scripts

The following test scripts provide additional validation coverage:

- **`test_attestation_auth.sh`**: Comprehensive attestation authentication testing
- **`test_attestation_integration.sh`**: End-to-end attestation integration validation
- **`test_authorization_introspection.sh`**: Authorization-introspection endpoint testing
- **`test_complete_flow.sh`**: Full OAuth2 flow validation (detailed above)
- **`test_device_code.sh`**: Device code grant flow testing
- **`test_public_client_flow.sh`**: Public client authentication flows
- **`test_scope_handling.sh`**: OAuth2 scope parameter validation
- **`test_token_exchange.sh`**: RFC 8693 token exchange implementation
- **`test_trust_anchor.sh`**: Trust anchor certificate management testing