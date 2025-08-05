package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	mathrand "math/rand"
	"net/http"
	"oauth2-server/internal/config"
	"oauth2-server/internal/storage"
)

func (h *Handlers) writeTokenResponse(w http.ResponseWriter, response TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

func (h *Handlers) writeError(w http.ResponseWriter, error, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:            error,
		ErrorDescription: description,
	})
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		mathrand.Read(bytes)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func generateUserCode() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 8)
	for i := range code {
		code[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(code[:4]) + "-" + string(code[4:])
}

func (h *Handlers) findClient(clientID string) *config.ClientConfig {
	// Try dynamic clients first
	dynamicClient, err := h.Storage.GetDynamicClient(clientID)
	if err == nil && dynamicClient != nil {
		return dynamicClient
	}

	// Fallback to static clients from config
	return findClientByID(clientID, h.Config)
}

func (h *Handlers) isUserAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return false
	}
	_, err = h.Storage.GetSession(cookie.Value)
	return err == nil
}

func (h *Handlers) validateUser(username, password string) bool {
	for _, user := range h.Config.Users {
		if user.Username == username && user.Password == password {
			return true
		}
	}
	return false
}

func (h *Handlers) getCurrentUserID(r *http.Request) string {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	session, err := h.Storage.GetSession(cookie.Value)
	if err != nil {
		return ""
	}
	return session.UserID
}

func (h *Handlers) findUserByID(userID string) *config.UserConfig {
	for _, user := range h.Config.Users {
		if user.ID == userID {
			return &user
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isClientInTokenAudience checks if the client is authorized to exchange the given token
func isClientInTokenAudience(clientID string, tokenInfo *storage.TokenInfo) bool {
	// If the token has no specific audience, allow the original client and any configured exchanges
	if len(tokenInfo.Audience) == 0 {
		// Allow the original client that the token was issued to
		if tokenInfo.ClientID == clientID {
			return true
		}
		// For tokens without explicit audience, we could allow exchange by any authenticated client
		// This is a policy decision - you might want to be more restrictive
		return true
	}

	// Check if the requesting client is explicitly listed in the token's audience
	for _, aud := range tokenInfo.Audience {
		if aud == clientID {
			return true
		}
	}

	// Also allow the original client that the token was issued to
	if tokenInfo.ClientID == clientID {
		return true
	}

	return false
}

// isValidAudienceForExchange validates if the requested audience is valid for token exchange
func isValidAudienceForExchange(requestedAudience string, tokenInfo *storage.TokenInfo, clientID string) bool {
	// The requesting client should be able to request tokens for audiences that:
	// 1. Are the same as existing audiences in the token
	// 2. Are the client itself
	// 3. Are explicitly allowed by policy (you can extend this)

	// Allow client to request tokens for itself
	if requestedAudience == clientID {
		return true
	}

	// Allow if the requested audience is already in the token's audience
	for _, aud := range tokenInfo.Audience {
		if aud == requestedAudience {
			return true
		}
	}

	// You could add additional policy checks here, such as:
	// - Checking a whitelist of allowed audiences
	// - Validating against client configuration
	// - Applying domain-based rules

	return false
}

// determineTokenExchangeScope determines the scope for token exchange
func determineTokenExchangeScope(originalScope []string, requestedScope []string) []string {
	if len(requestedScope) == 0 {
		return originalScope
	}

	var allowedScopes []string
	for _, requested := range requestedScope {
		for _, original := range originalScope {
			if requested == original {
				allowedScopes = append(allowedScopes, requested)
				break
			}
		}
	}
	return allowedScopes
}

// RFC 8693 compliant: Check if client is authorized to exchange the given token
func isClientAuthorizedForTokenExchange(clientID string, tokenInfo *storage.TokenInfo, config *config.Config) bool {
	// Policy 1: Allow the original client that issued the token
	if tokenInfo.ClientID == clientID {
		return true
	}

	// Policy 2: Check if the requesting client is in the subject token's audience
	// (This is optional - some deployments may want this restriction)
	for _, aud := range tokenInfo.Audience {
		if aud == clientID {
			return true
		}
	}

	// Policy 3: Check client-specific token exchange permissions
	client := findClientByID(clientID, config)
	if client != nil && client.AllowTokenExchange {
		return true
	}

	// Policy 4: For tokens without explicit audience, allow broader access
	// This is a policy decision based on your security requirements
	if len(tokenInfo.Audience) == 0 {
		// Default: allow any authenticated client for tokens without audience
		// You can make this more restrictive based on your needs
		return true
	}

	return false
}

// RFC 8693 compliant: Check if client is authorized for the requested audience
func isClientAuthorizedForAudience(clientID string, requestedAudience string, config *config.Config) bool {
	// Policy 1: Client can always request tokens for itself
	if requestedAudience == clientID {
		return true
	}

	// Policy 2: Check client's allowed audiences configuration
	client := findClientByID(clientID, config)
	if client != nil && len(client.AllowedAudiences) > 0 {
		for _, allowedAud := range client.AllowedAudiences {
			if allowedAud == requestedAudience {
				return true
			}
		}
		// If client has explicit allowed audiences, only allow those
		return false
	}

	// Policy 3: Default policy for clients without explicit audience restrictions
	// You can customize this based on your requirements

	// Example: More restrictive - only allow same domain
	// if strings.Contains(requestedAudience, ".") && strings.Contains(clientID, ".") {
	//     clientDomain := strings.Split(clientID, ".")[len(strings.Split(clientID, "."))-1]
	//     audienceDomain := strings.Split(requestedAudience, ".")[len(strings.Split(requestedAudience, "."))-1]
	//     return clientDomain == audienceDomain
	// }

	// For now, be permissive for clients without explicit restrictions
	return true
}

// isClientAuthorizedToUseRefreshToken checks if a client can use a given refresh token
func isClientAuthorizedToUseRefreshToken(clientID string, tokenInfo *storage.TokenInfo) bool {
	// Policy 1: Allow the original client that the token was issued to
	if tokenInfo.ClientID == clientID {
		return true
	}

	// Policy 2: Allow if the requesting client is in the token's audience
	for _, aud := range tokenInfo.Audience {
		if aud == clientID {
			return true
		}
	}

	// Policy 3: For tokens without explicit audience, you might have different rules
	// This is more permissive - you can make it more restrictive based on your needs
	if len(tokenInfo.Audience) == 0 {
		// Option A: Only allow original client (more secure)
		// return tokenInfo.ClientID == clientID

		// Option B: Allow any authenticated client (more permissive)
		// return true

		// Option C: Check if client has delegation permissions (recommended)
		return tokenInfo.ClientID == clientID
	}

	return false
}

func findClientByID(clientID string, config *config.Config) *config.ClientConfig {
	for i := range config.Clients {
		if config.Clients[i].ID == clientID {
			return &config.Clients[i]
		}
	}
	return nil
}
