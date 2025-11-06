package handlers

import (
	"net/http"
	"oauth2-server/internal/attestation"
	"oauth2-server/internal/metrics"
	"oauth2-server/pkg/config"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/sirupsen/logrus"
)

// TokenHandler manages OAuth2 token requests using pure fosite implementation
type TokenHandler struct {
	OAuth2Provider     fosite.OAuth2Provider
	Configuration      *config.Config
	Log                *logrus.Logger
	Metrics            *metrics.MetricsCollector
	AttestationManager *attestation.VerifierManager
}

// NewTokenHandler creates a new TokenHandler
func NewTokenHandler(
	provider fosite.OAuth2Provider,
	config *config.Config,
	logger *logrus.Logger,
	metricsCollector *metrics.MetricsCollector,
	attestationManager *attestation.VerifierManager,
) *TokenHandler {
	return &TokenHandler{
		OAuth2Provider:     provider,
		Configuration:      config,
		Log:                logger,
		Metrics:            metricsCollector,
		AttestationManager: attestationManager,
	}
}

// ServeHTTP implements the http.Handler interface for the token endpoint
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.HandleTokenRequest(w, r)
}

// HandleTokenRequest processes OAuth2 token requests using pure fosite
func (h *TokenHandler) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ Failed to parse form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Debug logging
	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	h.Log.Printf("🔍 Token request - Grant Type: %s, Client ID: %s", grantType, clientID)

	// Check for attestation-based authentication
	if err := h.handleAttestationAuthentication(r); err != nil {
		h.Log.Printf("❌ Attestation authentication failed: %v", err)
		if h.Metrics != nil {
			h.Metrics.RecordTokenRequest(grantType, clientID, "attestation_error")
		}
		http.Error(w, "Attestation authentication failed", http.StatusUnauthorized)
		return
	}

	// Let fosite handle ALL token requests natively, including device code flow and refresh tokens
	// Use a consistent session for all requests - fosite will manage session retrieval for refresh tokens
	session := &openid.DefaultSession{}

	accessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		h.Log.Printf("❌ NewAccessRequest failed: %v", err)
		if h.Metrics != nil {
			h.Metrics.RecordTokenRequest(grantType, "unknown", "error")
		}
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Let fosite create the access response
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Printf("❌ NewAccessResponse failed: %v", err)
		h.Log.Printf("🔍 Access request details - Client: %s, Grant: %s, Scopes: %v",
			accessRequest.GetClient().GetID(),
			accessRequest.GetGrantTypes(),
			accessRequest.GetGrantedScopes())
		if h.Metrics != nil {
			clientID := accessRequest.GetClient().GetID()
			h.Metrics.RecordTokenRequest(grantType, clientID, "error")
		}
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Let fosite write the response
	h.OAuth2Provider.WriteAccessResponse(ctx, w, accessRequest, accessResponse)

	// Record metrics for successful token issuance
	if h.Metrics != nil {
		clientID := accessRequest.GetClient().GetID()
		grantType := grantType
		h.Metrics.RecordTokenRequest(grantType, clientID, "success")

		// Record token issuance metrics
		h.Metrics.RecordTokenIssued("access_token", grantType)
		if refreshToken := accessResponse.GetExtra("refresh_token"); refreshToken != nil {
			h.Metrics.RecordTokenIssued("refresh_token", grantType)
		}
		if authCode := accessResponse.GetExtra("code"); authCode != nil {
			h.Metrics.RecordTokenIssued("authorization_code", grantType)
		}
	}

	h.Log.Printf("✅ Token request handled successfully by fosite")
}

// handleAttestationAuthentication handles attestation-based client authentication
func (h *TokenHandler) handleAttestationAuthentication(r *http.Request) error {
	// Skip if attestation manager is not available
	if h.AttestationManager == nil {
		return nil
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		// Client ID might be in Authorization header for some auth methods
		return nil
	}

	// Check if attestation is enabled for this client
	if !h.AttestationManager.IsAttestationEnabled(clientID) {
		return nil // Attestation not required for this client
	}

	// Determine the authentication method
	authMethod := h.determineAuthMethod(r)
	if authMethod == "" {
		return nil // No attestation method detected
	}

	h.Log.Printf("🔍 Processing attestation auth - Client: %s, Method: %s", clientID, authMethod)

	// Get the appropriate verifier
	verifier, err := h.AttestationManager.GetVerifier(clientID, authMethod)
	if err != nil {
		return err
	}

	// Perform attestation verification based on method
	var result *attestation.AttestationResult

	switch authMethod {
	case "attest_jwt_client_auth":
		// Extract JWT from client_assertion parameter
		clientAssertion := r.FormValue("client_assertion")
		if clientAssertion == "" {
			return fosite.ErrInvalidRequest.WithHint("Missing client_assertion for JWT attestation")
		}

		if jwtVerifier, ok := verifier.(attestation.AttestationVerifier); ok {
			result, err = jwtVerifier.VerifyAttestation(clientAssertion)
		} else {
			return fosite.ErrServerError.WithHint("Invalid JWT verifier")
		}

	case "attest_tls_client_auth":
		// For TLS attestation, we need the TLS connection state
		if tlsVerifier, ok := verifier.(attestation.TLSAttestationVerifier); ok {
			result, err = tlsVerifier.VerifyAttestation(r)
		} else {
			return fosite.ErrServerError.WithHint("Invalid TLS verifier")
		}

	default:
		return fosite.ErrInvalidRequest.WithHintf("Unsupported attestation method: %s", authMethod)
	}

	if err != nil {
		h.Log.Printf("❌ Attestation verification failed: %v", err)
		return fosite.ErrInvalidClient.WithHint("Attestation verification failed")
	}

	if !result.Valid {
		h.Log.Printf("❌ Invalid attestation result")
		return fosite.ErrInvalidClient.WithHint("Invalid attestation")
	}

	h.Log.Printf("✅ Attestation verification successful - Client: %s, Trust Level: %s", 
		result.ClientID, result.TrustLevel)

	// Store attestation result in request context for later use
	r = r.WithContext(attestation.WithAttestationResult(r.Context(), result))

	return nil
}

// determineAuthMethod determines the attestation authentication method from the request
func (h *TokenHandler) determineAuthMethod(r *http.Request) string {
	// Check for JWT attestation
	clientAssertionType := r.FormValue("client_assertion_type")
	if clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		// Check if this is an attestation JWT by looking for attestation claims
		clientAssertion := r.FormValue("client_assertion")
		if strings.Contains(clientAssertion, "att_") {
			return "attest_jwt_client_auth"
		}
	}

	// Check for TLS attestation
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// This could be TLS client certificate authentication
		// We need to check if it's specifically for attestation
		return "attest_tls_client_auth"
	}

	return ""
}
