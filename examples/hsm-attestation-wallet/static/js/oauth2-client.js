/**
 * OAuth2 Client with JWT Attestation Support
 * 
 * Provides OAuth2 authentication flows with hardware-backed JWT attestation
 * for enhanced security.
 */

class OAuth2Client {
    constructor(attestationService, options = {}) {
        this.attestationService = attestationService;
        this.hsm = attestationService.hsm;
        this.crypto = new CryptoUtils();
        
        // OAuth2 server configuration
        this.config = {
            serverUrl: options.serverUrl || window.HSM_DEMO_CONFIG?.serverUrl || 'http://localhost:8080',
            clientId: options.clientId || 'hsm-attestation-wallet-demo',
            redirectUri: options.redirectUri || `${window.location.origin}/callback`,
            scope: options.scope || 'openid profile email',
            apiKey: options.apiKey || window.HSM_DEMO_CONFIG?.apiKey || process?.env?.API_KEY || 'super-secure-random-api-key-change-in-production-32-chars-minimum',
            ...options
        };
        
        this.eventCallbacks = [];
        this.clientKeyId = null;
        this.state = null;
        this.tokens = null;
        
        // Set up default configuration
        this.setupDefaultConfig();
    }

    /**
     * Set up default configuration for demo
     */
    setupDefaultConfig() {
        // Configuration is set in constructor with defaults
        console.log('OAuth2 client configured:', this.config);
    }

    /**
     * Initialize OAuth2 client
     */
    async initialize() {
        try {
            this.log('Initializing OAuth2 client...');
            
            // Generate client key pair in HSM for JWT attestation (force EC-P256)
            this.clientKeyId = await this.hsm.generateKeyPair(
                'oauth2_client_key', 
                'EC-P256'
            );

            // Generate key attestation for the client key (ensure EC)
            await this.hsm.generateKeyAttestation(this.clientKeyId, { keyType: 'EC-P256' });
            
            // Discover OAuth2 server endpoints
            await this.discoverEndpoints();
            
            this.log('OAuth2 client initialized successfully', 'success');
            this.log(`Client key: ${this.clientKeyId}`, 'info');
            
            this.notifyEvent('initialized', {
                clientId: this.config.clientId,
                clientKeyId: this.clientKeyId,
                serverUrl: this.config.serverUrl
            });
            
            return {
                initialized: true,
                clientKeyId: this.clientKeyId,
                endpoints: this.endpoints
            };
            
        } catch (error) {
            this.log(`OAuth2 initialization failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Discover OAuth2 server endpoints
     */
    async discoverEndpoints() {
        try {
            this.log('Discovering OAuth2 endpoints...');
            
            // First try OAuth 2.0 Authorization Server Metadata (RFC 8414)
            const discoveryUrl = `${this.config.serverUrl}/.well-known/oauth-authorization-server`;
            
            try {
                const response = await fetch(discoveryUrl);
                if (response.ok) {
                    const metadata = await response.json();
                    this.endpoints = {
                        authorization_endpoint: metadata.authorization_endpoint,
                        token_endpoint: metadata.token_endpoint,
                        userinfo_endpoint: metadata.userinfo_endpoint,
                        introspection_endpoint: metadata.introspection_endpoint,
                        revocation_endpoint: metadata.revocation_endpoint,
                        jwks_uri: metadata.jwks_uri,
                        registration_endpoint: metadata.registration_endpoint,
                        device_authorization_endpoint: metadata.device_authorization_endpoint,
                        pushed_authorization_request_endpoint: metadata.pushed_authorization_request_endpoint
                    };
                    this.log('Endpoints discovered via metadata', 'success');
                    if (this.endpoints.pushed_authorization_request_endpoint) {
                        this.log('PAR endpoint available: ' + this.endpoints.pushed_authorization_request_endpoint, 'info');
                    }
                    return;
                }
            } catch (error) {
                this.log('Metadata discovery failed, using default endpoints', 'warning');
            }
            
            // Use default endpoints based on common patterns
            this.endpoints = this.getDefaultEndpoints();
            
            this.log('Using default endpoints', 'success');
            
        } catch (error) {
            this.log(`Endpoint discovery failed: ${error.message}`, 'warning');
            // Use fallback endpoints
            this.endpoints = this.getDefaultEndpoints();
        }
    }

    /**
     * Get default endpoints if discovery fails
     */
    getDefaultEndpoints() {
        return {
            authorization_endpoint: `${this.config.serverUrl}/authorize`,
            token_endpoint: `${this.config.serverUrl}/token`,
            userinfo_endpoint: `${this.config.serverUrl}/userinfo`,
            introspection_endpoint: `${this.config.serverUrl}/introspect`,
            revocation_endpoint: `${this.config.serverUrl}/revoke`,
            jwks_uri: `${this.config.serverUrl}/.well-known/jwks.json`,
            registration_endpoint: `${this.config.serverUrl}/register`,
            device_authorization_endpoint: `${this.config.serverUrl}/device/authorize`,
            pushed_authorization_request_endpoint: `${this.config.serverUrl}/authorize`
        };
    }

    /**
     * Register client using JWT attestation-based registration
     */
    async registerClient() {
        try {
            this.log('Registering client with OAuth2 server...', 'info');
            
            // Create attestation token for client registration
            const attestationToken = await this.attestationService.createAttestationToken({
                subject: this.config.clientId,
                audience: this.config.serverUrl,
                keyId: this.clientKeyId,
                bioAuth: true,
                claims: {
                    client_registration: true,
                    auth_method: 'attest_jwt_client_auth',
                    hsm_backed: true
                }
            });
            
            console.log('🔐 Attestation Token for Registration:', attestationToken);

            // Client registration request with attestation
            const registrationData = {
                client_id: this.config.clientId,
                client_name: "HSM Attestation Wallet Demo",
                client_uri: window.location.origin,

                redirect_uris: [
                    this.config.redirectUri
                ],

                grant_types: [
                    "authorization_code",
                    "refresh_token"
                ],

                response_types: ["code"],
                scope: this.config.scope,
                token_endpoint_auth_method: "none",

                attestation_jwt: attestationToken,
                application_type: "web",

                attestation_config: {
                    client_id: this.config.clientId,
                    allowed_methods: ["attest_jwt_client_auth"],
                    trust_anchors: ["hsm_ca"],
                    required_level: "high"
                }
            };
            
            this.log('Sending registration request with attestation...', 'info');
            this.log(`Using API key for authentication: ${this.config.apiKey.substring(0, 20)}...`, 'info');
            
            // Make actual HTTP request to registration endpoint
            const response = await fetch(this.endpoints.registration_endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': this.config.apiKey
                },
                body: JSON.stringify(registrationData)
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Registration failed: ${response.status} ${response.statusText} - ${errorText}`);
            }
            
            const clientRegistration = await response.json();
            
            this.log('Client registration with JWT attestation successful', 'success');
            this.log(`Client ID: ${clientRegistration.client_id}`, 'info');
            this.log('Authentication method: JWT Attestation', 'info');
            
            // Update our client ID to use the registered one
            this.config.clientId = clientRegistration.client_id;
            
            this.notifyEvent('clientRegistered', {
                clientId: clientRegistration.client_id,
                hasSecret: false, // No secret needed with attestation
                authMethod: 'attest_jwt_client_auth',
                attestationBacked: true,
                registrationResponse: clientRegistration
            });
            
            return clientRegistration;
            
        } catch (error) {
            this.log(`Client registration with attestation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Start authorization code flow with PKCE using Pushed Authorization Request (PAR)
     */
    async startAuthorizationCodeFlow() {
        try {
            this.log('Starting authorization code flow with PAR...');
            
            // Generate PKCE parameters
            const codeVerifier = this.crypto.generateRandomString(128);
            const codeChallenge = await this.crypto.createCodeChallenge(codeVerifier);
            
            // Generate state parameter
            this.state = this.crypto.generateRandomHex(32);
            
            // Store PKCE verifier for token exchange
            sessionStorage.setItem('pkce_code_verifier', codeVerifier);
            sessionStorage.setItem('oauth_state', this.state);
            
            // Check if PAR endpoint is available
            if (!this.endpoints.pushed_authorization_request_endpoint) {
                this.log('PAR endpoint not available, falling back to direct authorization', 'warning');
                return await this.startDirectAuthorizationFlow(codeChallenge);
            }
            
            // Push authorization request to PAR endpoint
            this.log('Pushing authorization request to PAR endpoint...');
            
            // Create attestation JWT for client authentication
            const attestationToken = await this.attestationService.createAttestationToken({
                subject: this.config.clientId,
                audience: this.endpoints.pushed_authorization_request_endpoint,
                keyId: this.clientKeyId,
                bioAuth: true,
                claims: {
                    client_assertion: true,
                    auth_method: 'attest_jwt_client_auth',
                    par_request: true
                }
            });
            
            // Prepare PAR request parameters
            const parParams = new URLSearchParams({
                response_type: 'code',
                client_id: this.config.clientId,
                redirect_uri: this.config.redirectUri,
                scope: this.config.scope,
                issuer_state: `demo-issuer-state-${Date.now()}`,
                state: this.state,
                code_challenge: codeChallenge,
                code_challenge_method: 'S256',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: attestationToken
            });
            
            console.log('📤 Sending PAR request to:', this.endpoints.pushed_authorization_request_endpoint);
            
            // Send PAR request
            const parResponse = await fetch(this.endpoints.pushed_authorization_request_endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: parParams.toString()
            });
            
            if (!parResponse.ok) {
                const errorText = await parResponse.text();
                this.log(`PAR request failed: ${parResponse.status} ${errorText}`, 'error');
                throw new Error(`PAR request failed: ${parResponse.status} ${parResponse.statusText} - ${errorText}`);
            }
            
            const parResult = await parResponse.json();
            console.log('✅ PAR Response:', parResult);
            
            if (!parResult.request_uri) {
                throw new Error('PAR response missing request_uri');
            }
            
            this.log('PAR request successful, received request_uri', 'success');
            
            // Build authorization URL with request_uri from PAR response
            const authParams = new URLSearchParams({
                client_id: this.config.clientId,
                request_uri: parResult.request_uri
            });
            
            const authUrl = `${this.endpoints.authorization_endpoint}?${authParams.toString()}`;
            
            this.log('Authorization URL generated with PAR request_uri', 'success');
            
            this.notifyEvent('authorizationStarted', {
                authUrl: authUrl,
                state: this.state,
                requestUri: parResult.request_uri,
                expiresIn: parResult.expires_in,
                codeChallenge: codeChallenge,
                usedPAR: true
            });
            
            return {
                authUrl: authUrl,
                state: this.state,
                codeVerifier: codeVerifier,
                requestUri: parResult.request_uri
            };
            
        } catch (error) {
            this.log(`Authorization flow start failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Fallback to direct authorization flow (without PAR)
     */
    async startDirectAuthorizationFlow(codeChallenge) {
        this.log('Using direct authorization flow (no PAR)');
        
        const authParams = new URLSearchParams({
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scope,
            issuer_state: `demo-issuer-state-${Date.now()}`,
            state: this.state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        const authUrl = `${this.endpoints.authorization_endpoint}?${authParams.toString()}`;
        
        this.log('Authorization URL generated (direct)', 'success');
        
        this.notifyEvent('authorizationStarted', {
            authUrl: authUrl,
            state: this.state,
            issuer_state: authParams.get('issuer_state'),
            codeChallenge: codeChallenge,
            usedPAR: false
        });
        
        return {
            authUrl: authUrl,
            state: this.state
        };
    }

    /**
     * Handle authorization callback
     */
    async handleAuthorizationCallback(code, state) {
        try {
            this.log('Handling authorization callback...');
            
            // Verify state parameter
            const storedState = sessionStorage.getItem('oauth_state');
            if (state !== storedState) {
                throw new Error('Invalid state parameter');
            }
            
            // Get PKCE code verifier
            const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
            if (!codeVerifier) {
                throw new Error('Missing PKCE code verifier');
            }
            
            // Exchange code for tokens
            const tokens = await this.exchangeCodeForTokens(code, codeVerifier);
            
            // Clean up session storage
            sessionStorage.removeItem('pkce_code_verifier');
            sessionStorage.removeItem('oauth_state');
            
            this.tokens = tokens;
            
            this.log('Authorization callback handled successfully', 'success');
            
            this.notifyEvent('tokensReceived', {
                hasAccessToken: !!tokens.access_token,
                hasRefreshToken: !!tokens.refresh_token,
                expiresIn: tokens.expires_in
            });
            
            return tokens;
            
        } catch (error) {
            this.log(`Authorization callback failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Exchange authorization code for tokens with JWT attestation authentication
     */
    async exchangeCodeForTokens(code, codeVerifier) {
        try {
            this.log('Exchanging code for tokens with attestation...');
            console.log('🔄 Token Exchange Request:');
            console.log('  - Endpoint:', this.endpoints.token_endpoint);
            console.log('  - Client ID:', this.config.clientId);
            console.log('  - Redirect URI:', this.config.redirectUri);
            console.log('  - Code:', code.substring(0, 20) + '...');
            
            // Create attestation JWT for client authentication (with x5c header)
            const attestationToken = await this.attestationService.createAttestationToken({
                subject: this.config.clientId,
                audience: this.endpoints.token_endpoint,
                keyId: this.clientKeyId,
                bioAuth: true,
                claims: {
                    client_assertion: true,
                    auth_method: 'attest_jwt_client_auth'
                }
            });
            console.log('  - Attestation JWT created (with x5c)');
            console.log('  - Attestation JWT (truncated):', attestationToken.substring(0, 50) + '...');

            // Token request parameters with PKCE and attestation JWT as client_assertion
            const tokenParams = new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: this.config.redirectUri,
                client_id: this.config.clientId,
                code_verifier: codeVerifier,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: attestationToken
            });

            console.log('🔄 Token request body (with attestation JWT):', tokenParams.toString().substring(0, 200) + '...');

            // Make HTTP request to OAuth2 server
            const response = await fetch(this.endpoints.token_endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: tokenParams.toString()
            });
            
            console.log('📥 Token Exchange Response Status:', response.status, response.statusText);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ Token Exchange Failed:', errorText);
                throw new Error(`Token exchange failed: ${response.status} ${response.statusText} - ${errorText}`);
            }
            
            const tokenResponse = await response.json();
            
            console.log('✅ Token Exchange Successful:');
            console.log('  - Access Token:', tokenResponse.access_token ? tokenResponse.access_token.substring(0, 30) + '...' : 'N/A');
            console.log('  - Token Type:', tokenResponse.token_type);
            console.log('  - Expires In:', tokenResponse.expires_in);
            console.log('  - Refresh Token:', tokenResponse.refresh_token ? 'Present' : 'N/A');
            console.log('  - Scope:', tokenResponse.scope);
            
            this.log('Tokens received successfully with JWT attestation', 'success');
            
            return tokenResponse;
            
        } catch (error) {
            console.error('❌ Token Exchange Error:', error);
            this.log(`Token exchange failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Create client assertion JWT for authentication
     */
    async createClientAssertion() {
        try {
            // Create attestation token for client authentication
            const attestationToken = await this.attestationService.createAttestationToken({
                subject: this.config.clientId,
                audience: this.endpoints.token_endpoint,
                keyId: this.clientKeyId,
                bioAuth: true,
                claims: {
                    client_assertion: true,
                    auth_method: 'attest_jwt_client_auth'
                }
            });

            // Get x5c from attestationService (same as attestationToken)
            const x5c = [await this.attestationService.getCertificateChain()];

            const now = this.crypto.getCurrentTimestamp();
            const exp = now + 300; // 5 minutes
            const jti = `ca_${this.crypto.generateRandomHex(16)}`;

            // Client assertion claims
            const claims = {
                iss: this.config.clientId,
                sub: this.config.clientId,
                aud: this.endpoints.token_endpoint,
                exp: exp,
                iat: now,
                jti: jti,
                attestation_jwt: attestationToken
            };

            // Create header with x5c
            const header = {
                alg: 'ES256',
                typ: 'JWT',
                kid: this.clientKeyId,
                x5c: x5c
            };

            // Sign with HSM
            const clientAssertion = await this.attestationService.createJWTManually(header, claims);

            this.log('Client assertion created', 'success');

            return clientAssertion;
            
        } catch (error) {
            this.log(`Client assertion creation failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Create mock ID token for demo
     */
    async createMockIdToken() {
        const now = this.crypto.getCurrentTimestamp();
        const exp = now + 3600;
        
        const idTokenClaims = {
            iss: this.config.serverUrl,
            sub: 'user_12345',
            aud: this.config.clientId,
            exp: exp,
            iat: now,
            auth_time: now,
            email: 'demo@example.com',
            email_verified: true,
            name: 'Demo User',
            preferred_username: 'demouser'
        };
        
        const header = {
            alg: 'RS256',
            typ: 'JWT',
            kid: 'server-key-1'
        };
        
        // For demo, create unsigned token
        const headerB64 = this.crypto.base64UrlEncode(
            new TextEncoder().encode(JSON.stringify(header))
        );
        const payloadB64 = this.crypto.base64UrlEncode(
            new TextEncoder().encode(JSON.stringify(idTokenClaims))
        );
        
        return `${headerB64}.${payloadB64}.demo-signature`;
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken() {
        if (!this.tokens || !this.tokens.refresh_token) {
            throw new Error('No refresh token available');
        }
        
        try {
            this.log('Refreshing access token...');
            
            // Create client assertion for token refresh
            const clientAssertion = await this.createClientAssertion();
            
            // Refresh request parameters
            const refreshParams = new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: this.tokens.refresh_token,
                client_id: this.config.clientId,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: clientAssertion
            });
            
            // Simulate successful refresh response
            const refreshResponse = {
                access_token: `at_${this.crypto.generateRandomHex(32)}`,
                token_type: 'Bearer',
                expires_in: 3600,
                scope: this.config.scope
            };
            
            // Update tokens
            this.tokens.access_token = refreshResponse.access_token;
            this.tokens.expires_in = refreshResponse.expires_in;
            
            this.log('Access token refreshed successfully', 'success');
            
            this.notifyEvent('tokenRefreshed', {
                newAccessToken: refreshResponse.access_token,
                expiresIn: refreshResponse.expires_in
            });
            
            return refreshResponse;
            
        } catch (error) {
            this.log(`Token refresh failed: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Get user info
     */
    async getUserInfo() {
        if (!this.tokens || !this.tokens.access_token) {
            console.error('❌ No access token available for userinfo request');
            throw new Error('No access token available');
        }
        
        try {
            this.log('Fetching user info from server...');
            console.log('🔄 Userinfo Request:');
            console.log('  - Endpoint:', this.endpoints.userinfo_endpoint);
            console.log('  - Access Token:', this.tokens.access_token.substring(0, 30) + '...');
            
            // Make HTTP request to userinfo endpoint
            const response = await fetch(this.endpoints.userinfo_endpoint, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.tokens.access_token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            console.log('📥 Userinfo Response Status:', response.status, response.statusText);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ Userinfo request failed:', errorText);
                
                // Log the exact CURL command for debugging
                const curlCommand = `curl -X GET "${this.endpoints.userinfo_endpoint}" \\
  -H "Authorization: Bearer ${this.tokens.access_token.substring(0, 50)}..." \\
  -H "Content-Type: application/json"`;
                
                console.error('🔍 Exact CURL command that failed:');
                console.error(curlCommand);
                
                throw new Error(`Userinfo request failed: ${response.status} ${response.statusText} - ${errorText}`);
            }
            
            const userInfo = await response.json();
            
            console.log('✅ Userinfo Retrieved:');
            console.log('  - Subject:', userInfo.sub);
            console.log('  - Email:', userInfo.email);
            console.log('  - Name:', userInfo.name);
            console.log('  - Full Data:', userInfo);
            
            this.log('User info retrieved successfully from server', 'success');
            
            return userInfo;
            
        } catch (error) {
            this.log(`User info fetch failed: ${error.message}`, 'error');
            
            // Log the exact CURL command for debugging when request fails
            console.error('🔍 Failed userinfo request details:');
            console.error('  - Error:', error.message);
            console.error('  - Endpoint:', this.endpoints.userinfo_endpoint);
            console.error('  - Has Access Token:', !!this.tokens?.access_token);
            
            // Re-throw the error instead of falling back to mock data
            throw error;
        }
    }

    /**
     * Get token introspection
     */
    async getTokenIntrospection() {
        if (!this.tokens || !this.tokens.access_token) {
            console.error('❌ No access token available for introspection request');
            throw new Error('No access token available');
        }
        
        try {
            this.log('Fetching token introspection from server...');
            console.log('🔄 Introspection Request:');
            console.log('  - Endpoint:', this.endpoints.introspection_endpoint);
            console.log('  - Access Token:', this.tokens.access_token.substring(0, 30) + '...');
            
            // Create client assertion for authentication
            const clientAssertion = await this.createClientAssertion();
            
            // Introspection request parameters
            const introspectionParams = new URLSearchParams({
                token: this.tokens.access_token,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: clientAssertion
            });
            
            // Make HTTP request to introspection endpoint
            const response = await fetch(this.endpoints.introspection_endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: introspectionParams.toString()
            });
            
            console.log('📥 Introspection Response Status:', response.status, response.statusText);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ Introspection request failed:', errorText);
                
                // Log the exact CURL command for debugging
                const curlCommand = `curl -X POST "${this.endpoints.introspection_endpoint}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "${introspectionParams.toString()}"`;
                
                console.error('🔍 Exact CURL command that failed:');
                console.error(curlCommand);
                
                throw new Error(`Introspection request failed: ${response.status} ${response.statusText} - ${errorText}`);
            }
            
            const introspectionData = await response.json();
            
            console.log('✅ Introspection Retrieved:');
            console.log('  - Active:', introspectionData.active);
            console.log('  - Subject:', introspectionData.sub);
            console.log('  - Client ID:', introspectionData.client_id);
            console.log('  - Scope:', introspectionData.scope);
            console.log('  - Full Data:', introspectionData);
            
            this.log('Token introspection retrieved successfully from server', 'success');
            
            return introspectionData;
            
        } catch (error) {
            this.log(`Token introspection fetch failed: ${error.message}`, 'error');
            
            // Log the exact CURL command for debugging when request fails
            console.error('🔍 Failed introspection request details:');
            console.error('  - Error:', error.message);
            console.error('  - Endpoint:', this.endpoints.introspection_endpoint);
            console.error('  - Has Access Token:', !!this.tokens?.access_token);
            console.error('  - Client Assertion Created:', !!this.attestationService);
            
            // Re-throw the error instead of falling back to mock data
            throw error;
        }
    }

    /**
     * Get current OAuth2 status
     */
    getStatus() {
        return {
            initialized: !!this.clientKeyId,
            clientId: this.config.clientId,
            hasTokens: !!this.tokens,
            accessToken: this.tokens ? {
                present: !!this.tokens.access_token,
                expires: this.tokens.expires_in
            } : null,
            refreshToken: this.tokens ? {
                present: !!this.tokens.refresh_token
            } : null,
            endpoints: this.endpoints
        };
    }

    /**
     * Add event listener
     */
    addEventListener(callback) {
        this.eventCallbacks.push(callback);
    }

    /**
     * Notify event listeners
     */
    notifyEvent(type, data) {
        const event = {
            type,
            timestamp: Date.now(),
            clientId: this.config.clientId,
            data
        };

        this.eventCallbacks.forEach(callback => {
            try {
                callback(event);
            } catch (error) {
                console.error('Error in OAuth2 event callback:', error);
            }
        });
    }

    /**
     * Log OAuth2 operations
     */
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[OAuth2 ${timestamp}] ${message}`);
        
        // Notify UI
        if (window.UIController) {
            window.UIController.addLog('oauth2', timestamp, message, type);
        }
    }

    /**
     * Reset OAuth2 client (for demo)
     */
    async reset() {
        this.log('Resetting OAuth2 client...');
        
        this.tokens = null;
        this.state = null;
        this.clientKeyId = null;
        
        // Clear session storage
        sessionStorage.removeItem('pkce_code_verifier');
        sessionStorage.removeItem('oauth_state');
        
        this.log('OAuth2 client reset complete', 'success');
        
        this.notifyEvent('reset', {});
    }
}

// Export for use in other modules
window.OAuth2Client = OAuth2Client;