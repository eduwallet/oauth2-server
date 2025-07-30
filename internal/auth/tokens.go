package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"oauth2-server/internal/models"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
)

// GenerateAccessToken generates and stores an access token for the given user and client
func GenerateAccessToken(tokenStore *store.TokenStore, userID, clientID string, scopes []string, audiences []string) (string, error) {
	// Generate a random token (in a real implementation, you'd use JWT)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	// Create a base64 encoded token with metadata
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Format: at_<base64token>_<timestamp>
	timestamp := time.Now().Unix()
	tokenValue := fmt.Sprintf("at_%s_%d", token, timestamp)

	if err := tokenStore.StoreToken(tokenValue, "access_token", clientID, userID, scopes, audiences); err != nil {
		return "", err
	}

	return tokenValue, nil
}

// GenerateRefreshToken generates and stores a refresh token for the given user and client
func GenerateRefreshToken(tokenStore *store.TokenStore, userID, clientID string, scopes []string, audiences []string) (string, error) {
	// Generate a random refresh token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random refresh token: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)
	timestamp := time.Now().Unix()
	tokenValue := fmt.Sprintf("rt_%s_%d", token, timestamp)

	if err := tokenStore.StoreToken(tokenValue, "refresh_token", clientID, userID, scopes, audiences); err != nil {
		return "", err
	}

	return tokenValue, nil
}

// GenerateAuthorizationCode generates and stores an authorization code
func GenerateAuthorizationCode(tokenStore *store.TokenStore, userID, clientID string) (string, error) {
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", fmt.Errorf("failed to generate random authorization code: %w", err)
	}

	code := base64.URLEncoding.EncodeToString(codeBytes)
	codeValue := fmt.Sprintf("ac_%s", code)
	if err := tokenStore.StoreToken(codeValue, "authorization_code", clientID, userID, nil, nil); err != nil {
		return "", err
	}

	return codeValue, nil
}

// GenerateDeviceCode generates and stores a device code
func GenerateDeviceCode(tokenStore *store.TokenStore, userID, clientID string, expiresIn time.Duration) (string, error) {
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", fmt.Errorf("failed to generate random device code: %w", err)
	}

	code := base64.URLEncoding.EncodeToString(codeBytes)
	codeValue := fmt.Sprintf("dc_%s", code)
	if err := tokenStore.StoreToken(codeValue, "device_code", clientID, userID, nil, nil); err != nil {
		return "", err
	}

	return codeValue, nil
}

// GenerateUserCode generates a user-friendly code for device flow
func GenerateUserCode() (string, error) {
	// Generate a short, user-friendly code
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude confusing characters
	const length = 8

	result := make([]byte, length)
	for i := range result {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random user code: %w", err)
		}
		result[i] = charset[randomIndex.Int64()]
	}

	// Format as XXXX-XXXX for better readability
	code := string(result)
	return fmt.Sprintf("%s-%s", code[:4], code[4:]), nil
}

// TokenInfo represents information about a token
type TokenInfo struct {
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
	Scope     string    `json:"scope"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Active    bool      `json:"active"`
	IssuedAt  time.Time `json:"iat"`
	Issuer    string    `json:"iss"`
	Audience  []string  `json:"aud"`
}

// StoreToken stores a token using the TokenStore (for custom tokens)
func StoreToken(tokenStore *store.TokenStore, tokenValue, tokenType, clientID, userID string, scopes []string, audiences []string) error {
	return tokenStore.StoreToken(tokenValue, tokenType, clientID, userID, scopes, audiences)
}

// ValidateToken validates a token and returns token information using the TokenStore
func ValidateToken(tokenStore *store.TokenStore, token string) (*store.TokenInfo, error) {
	log.Printf("Validating token: %s", token)
	tokenInfo, err := tokenStore.ValidateToken(token)
	if err != nil {
		log.Printf("❌ Token validation failed: %v", err)
		return nil, err
	}
	return tokenInfo, nil
}

// RevokeToken revokes a token using the TokenStore
func RevokeToken(tokenStore *store.TokenStore, token string) error {
	return tokenStore.RevokeToken(token)
}

// ValidateAccessToken validates an access token (simplified implementation)
func ValidateAccessToken(token string) error {
	if token == "" {
		return errors.New("empty token")
	}

	// For demo purposes, accept any non-empty token
	// In a real implementation, you'd validate JWT signatures, expiration, etc.
	if len(token) < 10 {
		return errors.New("invalid token format")
	}

	// Check if it's an access token
	if !strings.HasPrefix(token, "at_") {
		return errors.New("not an access token")
	}

	return nil
}

// ValidateRefreshToken validates a refresh token
func ValidateRefreshToken(token string) error {
	if token == "" {
		return errors.New("empty refresh token")
	}

	if len(token) < 10 {
		return errors.New("invalid refresh token format")
	}

	// Check if it's a refresh token
	if !strings.HasPrefix(token, "rt_") {
		return errors.New("not a refresh token")
	}

	return nil
}

// ValidateAuthorizationCode validates an authorization code
func ValidateAuthorizationCode(code string) error {
	if code == "" {
		return errors.New("empty authorization code")
	}

	if len(code) < 10 {
		return errors.New("invalid authorization code format")
	}

	// Check if it's an authorization code
	if !strings.HasPrefix(code, "ac_") {
		return errors.New("not an authorization code")
	}

	return nil
}

// ExtractBearerToken extracts the token from Authorization header
func ExtractBearerToken(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization header format")
	}
	return parts[1], nil
}

// IntrospectToken performs token introspection (RFC 7662)
func IntrospectToken(tokenStore *store.TokenStore, token string) (*models.IntrospectionResponse, error) {
	tokenInfo, err := ValidateToken(tokenStore, token)
	if err != nil {
		return &models.IntrospectionResponse{
			Active: false,
		}, nil
	}

	response := &models.IntrospectionResponse{
		Active:    tokenInfo.Active,
		TokenType: tokenInfo.TokenType,
		Scope:     utils.JoinStrings(tokenInfo.Scopes),
		ClientID:  tokenInfo.ClientID,
		Username:  tokenInfo.UserID,
		Exp:       tokenInfo.ExpiresAt.Unix(),
		Iat:       tokenInfo.IssuedAt.Unix(),
		Iss:       tokenInfo.Issuer,
		Aud:       tokenInfo.Audience,
		Sub:       tokenInfo.UserID,
	}

	return response, nil
}

// IsTokenExpired checks if a token is expired based on its timestamp
func IsTokenExpired(token string) bool {
	// Extract timestamp from token format: prefix_token_timestamp
	parts := strings.Split(token, "_")
	if len(parts) < 3 {
		return true // Invalid format, consider expired
	}

	// For demo purposes, tokens expire after 1 hour
	// In real implementation, extract expiration from JWT claims
	return false // For demo, tokens don't expire
}

// RefreshAccessToken generates a new access token using a refresh token
func RefreshAccessToken(tokenStore *store.TokenStore, refreshToken, clientID, userID string, accessTokenExpiresIn, refreshTokenExpiresIn time.Duration) (string, string, error) {
	// Retrieve the refresh token from the store to get its scopes
	tokenData, err := tokenStore.GetToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("refresh token not found: %w", err)
	}

	// Validate refresh token
	if err := ValidateRefreshToken(refreshToken); err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Use the scopes from the refresh token
	scopes := tokenData.Scopes
	audiences := tokenData.Audience

	// Generate new access token with the same scopes as the refresh token
	newAccessToken, err := GenerateAccessToken(tokenStore, userID, clientID, scopes, audiences)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	// Generate new refresh token (optional, some implementations keep the same one)
	newRefreshToken, err := GenerateRefreshToken(tokenStore, userID, clientID, scopes, audiences)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	return newAccessToken, newRefreshToken, nil
}
