package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"oauth2-server/internal/attestation"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
)

type fositeClientKey string
type proxyTokenKey string

// AttestationClientAuthStrategy implements a composite client authentication strategy
// that handles attestation-based authentication and standard OAuth2 client authentication
type AttestationClientAuthStrategy struct {
	AttestationManager *attestation.VerifierManager
	Storage            store.Storage
	Config             *config.Config
}

// NewAttestationClientAuthStrategy creates a new composite client authentication strategy
func NewAttestationClientAuthStrategy(attestationManager *attestation.VerifierManager, storage store.Storage, config *config.Config) fosite.ClientAuthenticationStrategy {
	strategy := &AttestationClientAuthStrategy{
		AttestationManager: attestationManager,
		Storage:            storage,
		Config:             config,
	}
	return strategy.AuthenticateClient
}

// AuthenticateClient implements the fosite.ClientAuthenticationStrategy interface
// It handles attestation authentication and standard OAuth2 client authentication methods
func (s *AttestationClientAuthStrategy) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
	clientID := form.Get("client_id")

	// Check if this is a proxy token creation request - skip authentication in that case
	if ctx.Value(proxyTokenKey("proxy_token")) != nil {
		if clientID != "" {
			client, err := s.Storage.GetClient(ctx, clientID)
			if err != nil {
				return nil, fosite.ErrInvalidClient.WithHint("Unknown client")
			}
			// Ensure client_credentials is in grant types for proxy token creation
			grantTypes := client.GetGrantTypes()
			hasClientCredentials := false
			for _, gt := range grantTypes {
				if gt == "client_credentials" {
					hasClientCredentials = true
					break
				}
			}
			if !hasClientCredentials {
				// Create a wrapper client with client_credentials added
				grantWrappedClient := &GrantTypeWrapper{
					Client:          client,
					extraGrantTypes: []string{"client_credentials"},
				}
				// For public clients, also make them appear confidential for proxy tokens
				if client.IsPublic() {
					wrappedClient := &PublicClientWrapper{
						Client: grantWrappedClient,
					}
					return wrappedClient, nil
				}
				return grantWrappedClient, nil
			}
			// For public clients, wrap to make them appear confidential
			if client.IsPublic() {
				wrappedClient := &PublicClientWrapper{
					Client: client,
				}
				return wrappedClient, nil
			}
			return client, nil
		}
	}

	// Check if this is a proxy token creation request - return the client from context if available
	if client := ctx.Value(fositeClientKey("client")); client != nil {
		if fositeClient, ok := client.(fosite.Client); ok {
			// For proxy tokens, wrap public clients to make them appear confidential
			if ctx.Value(proxyTokenKey("proxy_token")) != nil && fositeClient.IsPublic() {
				wrappedClient := &PublicClientWrapper{
					Client: fositeClient,
				}
				return wrappedClient, nil
			}
			return fositeClient, nil
		}
	}

	// First, try attestation authentication if client ID is provided
	if clientID != "" && s.AttestationManager != nil && s.AttestationManager.IsAttestationEnabled(clientID) {
		authMethod := s.determineAuthMethod(form)
		if authMethod != "" {
			// Try attestation authentication
			client, err := s.authenticateWithAttestation(ctx, form, authMethod)
			if err == nil && client != nil {
				return client, nil
			}
			// If attestation fails, continue to standard auth methods
		}
	}

	// Fall back to standard OAuth2 client authentication methods
	return s.authenticateStandard(ctx, r, form)
}

// GrantTypeWrapper wraps a fosite client to add extra grant types
type GrantTypeWrapper struct {
	fosite.Client
	extraGrantTypes []string
}

// GetGrantTypes returns the client's grant types plus any extra ones
func (w *GrantTypeWrapper) GetGrantTypes() fosite.Arguments {
	original := w.Client.GetGrantTypes()
	return append(original, w.extraGrantTypes...)
}

// PublicClientWrapper wraps a fosite client to override IsPublic for proxy token creation
type PublicClientWrapper struct {
	fosite.Client
}

// IsPublic returns false for proxy token creation to allow client_credentials grant
func (w *PublicClientWrapper) IsPublic() bool {
	return false
}

// AttestationClientWrapper wraps a fosite client to override IsPublic for attestation-authenticated clients
type AttestationClientWrapper struct {
	fosite.Client
	attestationAuthenticated bool
}

// IsPublic returns false for attestation-authenticated clients to allow client_credentials grant
func (w *AttestationClientWrapper) IsPublic() bool {
	if w.attestationAuthenticated {
		return false
	}
	return w.Client.IsPublic()
}

// authenticateWithAttestation handles attestation-based client authentication
func (s *AttestationClientAuthStrategy) authenticateWithAttestation(ctx context.Context, form url.Values, authMethod string) (fosite.Client, error) {
	clientID := form.Get("client_id")

	// Get the appropriate verifier
	verifier, err := s.AttestationManager.GetVerifier(clientID, authMethod)
	if err != nil {
		return nil, err
	}

	// Perform attestation verification based on method
	var result *attestation.AttestationResult

	switch authMethod {
	case "attest_jwt_client_auth":
		// Extract JWT from client_assertion parameter
		clientAssertion := form.Get("client_assertion")
		if clientAssertion == "" {
			return nil, fosite.ErrInvalidRequest.WithHint("Missing client_assertion for JWT attestation")
		}

		if jwtVerifier, ok := verifier.(attestation.AttestationVerifier); ok {
			result, err = jwtVerifier.VerifyAttestation(clientAssertion)
		} else {
			return nil, fosite.ErrServerError.WithHint("Invalid JWT verifier")
		}

	case "attest_tls_client_auth":
		// For TLS attestation, we would need the TLS connection state
		// This would require access to the http.Request
		// For now, we'll skip TLS attestation in this strategy
		return nil, fosite.ErrInvalidRequest.WithHint("TLS attestation not supported")

	default:
		return nil, fosite.ErrInvalidRequest.WithHintf("Unsupported attestation method: %s", authMethod)
	}

	if err != nil {
		return nil, fosite.ErrInvalidClient.WithHint("Attestation verification failed")
	}

	if !result.Valid {
		return nil, fosite.ErrInvalidClient.WithHint("Invalid attestation")
	}

	// Get the client from store
	client, err := s.Storage.GetClient(ctx, result.ClientID)
	if err != nil {
		return nil, fosite.ErrInvalidClient.WithHint("Unknown client")
	}

	// Store attestation result in request context for later use
	attestation.WithAttestationResult(ctx, result)

	// Wrap the client to override IsPublic for attestation authentication
	wrappedClient := &AttestationClientWrapper{
		Client:                   client,
		attestationAuthenticated: true,
	}

	return wrappedClient, nil
}

// authenticateStandard handles standard OAuth2 client authentication methods
func (s *AttestationClientAuthStrategy) authenticateStandard(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
	clientID := form.Get("client_id")

	// Method 1: HTTP Basic Authentication
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			if decoded, err := base64.StdEncoding.DecodeString(auth[6:]); err == nil {
				if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 {
					reqClientID, clientSecret := parts[0], parts[1]

					// If client_id was provided in form, it must match the one in Basic auth
					if clientID != "" && clientID != reqClientID {
						return nil, fosite.ErrInvalidClient.WithHint("Client ID mismatch between form and authorization header")
					}

					clientID = reqClientID

					client, err := s.Storage.GetClient(ctx, clientID)
					if err != nil {
						return nil, fosite.ErrInvalidClient.WithHint("Unknown client")
					}

					// Verify client secret using proper bcrypt validation
					if !utils.ValidateSecret(clientSecret, client.GetHashedSecret()) {
						return nil, fosite.ErrInvalidClient.WithHint("Invalid client credentials")
					}

					return client, nil
				}
			}
		}
	}

	// Method 2: client_secret_post
	if clientID != "" {
		clientSecret := form.Get("client_secret")
		if clientSecret != "" {
			client, err := s.Storage.GetClient(ctx, clientID)
			if err != nil {
				return nil, fosite.ErrInvalidClient.WithHint("Unknown client")
			}

			// Verify client secret using proper bcrypt validation
			if !utils.ValidateSecret(clientSecret, client.GetHashedSecret()) {
				return nil, fosite.ErrInvalidClient.WithHint("Invalid client credentials")
			}

			return client, nil
		}
	}

	// Method 3: private_key_jwt (non-attestation)
	if clientID != "" {
		clientAssertionType := form.Get("client_assertion_type")
		clientAssertion := form.Get("client_assertion")

		if clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && clientAssertion != "" {
			// This is private_key_jwt authentication (not attestation)
			// Verify the JWT signature and claims
			if err := s.Storage.ClientAssertionJWTValid(ctx, clientID); err != nil {
				return nil, fosite.ErrInvalidClient.WithHint("Invalid client assertion")
			}

			client, err := s.Storage.GetClient(ctx, clientID)
			if err != nil {
				return nil, fosite.ErrInvalidClient.WithHint("Unknown client")
			}

			return client, nil
		}
	}

	// Method 4: Public client (no authentication required)
	if clientID != "" {
		client, err := s.Storage.GetClient(ctx, clientID)
		if err != nil {
			return nil, fosite.ErrInvalidClient.WithHint("Unknown client")
		}

		// Check if client is public (no secret required)
		if client.IsPublic() || len(client.GetHashedSecret()) == 0 {
			return client, nil
		}
	}

	return nil, fosite.ErrInvalidClient.WithHint("Client authentication failed")
}

// determineAuthMethod determines the attestation authentication method from the form
func (s *AttestationClientAuthStrategy) determineAuthMethod(form url.Values) string {
	clientID := form.Get("client_id")

	// Check for JWT attestation
	clientAssertionType := form.Get("client_assertion_type")
	if clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		clientAssertion := form.Get("client_assertion")

		// Check if the client is configured for attestation-based authentication
		if s.AttestationManager != nil && s.AttestationManager.IsAttestationEnabled(clientID) {
			supportedMethods, err := s.AttestationManager.GetSupportedMethods(clientID)
			if err == nil {
				// Check if attest_jwt_client_auth is supported
				for _, method := range supportedMethods {
					if method == "attest_jwt_client_auth" {
						return "attest_jwt_client_auth"
					}
				}
			}
		}

		// Also check if JWT contains attestation-specific claims
		if strings.Contains(clientAssertion, "att_") {
			return "attest_jwt_client_auth"
		}
	}

	return ""
}
