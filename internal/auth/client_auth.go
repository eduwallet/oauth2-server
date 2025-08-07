package auth

import (
//	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

//	"oauth2-server/internal/store"

	"github.com/ory/fosite"
)

// // AuthenticateClient authenticates a client using client credentials
// func AuthenticateClient(clientID, clientSecret string, clientStore *store.ClientStore) (fosite.Client, error) {
// 	if clientID == "" || clientSecret == "" {
// 		return nil, errors.New("client credentials are required")
// 	}

// 	// Get client from store with context
// 	ctx := context.Background()
// 	client, err := clientStore.GetClient(ctx, clientID)
// 	if err != nil {
// 		return nil, errors.New("client not found")
// 	}

// 	// Validate client credentials
// 	if err := clientStore.ValidateClientCredentials(clientID, clientSecret); err != nil {
// 		return nil, err
// 	}

// 	return client, nil
// }

// ExtractClientCredentials extracts client credentials from request
func ExtractClientCredentials(r *http.Request) (string, string, error) {
	// Check for Basic Authentication in Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Basic" {
			// Decode Basic auth
			payload, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return "", "", errors.New("invalid basic auth encoding")
			}

			// Split username:password
			creds := strings.SplitN(string(payload), ":", 2)
			if len(creds) != 2 {
				return "", "", errors.New("invalid basic auth format")
			}

			return creds[0], creds[1], nil
		}
	}

	// Check for client credentials in request body
	if err := r.ParseForm(); err != nil {
		return "", "", errors.New("failed to parse form")
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID == "" {
		return "", "", errors.New("client_id is required")
	}

	// Some flows allow public clients (no secret required)
	return clientID, clientSecret, nil
}

// ClientHasGrantType checks if client is authorized for a specific grant type
func ClientHasGrantType(client fosite.Client, grantType string) bool {
	for _, gt := range client.GetGrantTypes() {
		if gt == grantType {
			return true
		}
	}
	return false
}

// ClientHasScope checks if client is authorized for specific scopes
func ClientHasScope(client fosite.Client, scope string) bool {
	if scope == "" {
		return true
	}

	requestedScopes := strings.Fields(scope)
	clientScopes := client.GetScopes()

	for _, requested := range requestedScopes {
		found := false
		for _, clientScope := range clientScopes {
			if clientScope == requested {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Validate Audience checks if the client is authorized for a specific audience
func ClientHasAudience(client fosite.Client, audience string) bool {
	if audience == "" {
		return true
	}

	clientAudiences := client.GetAudience()
	for _, aud := range clientAudiences {
		if aud == audience {
			return true
		}
	}
	return false
}
