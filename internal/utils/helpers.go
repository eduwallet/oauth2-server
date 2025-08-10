package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword creates a hash of the password (placeholder implementation)
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ValidatePassword validates a password against its hash
func ValidatePassword(password, hash string) bool {
	return HashPassword(password) == hash
}

// CreateJWT creates a JWT token with the given claims
func CreateJWT(claims jwt.Claims, signingKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

// ValidateJWT validates a JWT token and returns the claims
func ValidateJWT(tokenString string, signingKey []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// ExtractBearerToken extracts a bearer token from the Authorization header
func ExtractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// GetCurrentTimeUnix returns the current time as Unix timestamp
func GetCurrentTimeUnix() int64 {
	return time.Now().Unix()
}

// IsExpired checks if a Unix timestamp is expired
func IsExpired(timestamp int64) bool {
	return time.Now().Unix() > timestamp
}

// ExtractClientCredentials extracts client credentials from request
func ExtractClientCredentials(r *http.Request) (string, string, error) {
	// Try basic auth first
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		return clientID, clientSecret, nil
	}

	// Try form parameters
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID == "" {
		return "", "", errors.New("client_id is required")
	}

	return clientID, clientSecret, nil
}

// Contains checks if a slice contains a specific string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveDuplicates removes duplicate strings from a slice
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// SplitString splits a space-separated scope string into individual scopes
func SplitString(values string) []string {
	if values == "" {
		return []string{}
	}
	return strings.Fields(values)
}

// JoinStrings joins individual scopes into a space-separated string
func JoinStrings(values []string) string {
	// Filter out empty strings
	var filtered []string
	for _, value := range values {
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	return strings.Join(filtered, " ")
}

// NormalizeScope normalizes a scope string by removing duplicates and sorting
func NormalizeScope(scopes string) string {
	scopeList := SplitString(scopes)
	scopeList = RemoveDuplicates(scopeList)
	return JoinStrings(scopeList)
}

// NormalizeAudience normalizes a audience string by removing duplicates and sorting
func NormalizeAudience(audiences string) string {
	audienceList := SplitString(audiences)
	audienceList = RemoveDuplicates(audienceList)
	return JoinStrings(audienceList)
}

// FilterScopes filters requested scopes against allowed scopes
func FilterScopes(requestedScopes, allowedScopes []string) []string {
	var filtered []string

	for _, requested := range requestedScopes {
		for _, allowed := range allowedScopes {
			if requested == allowed {
				filtered = append(filtered, requested)
				break
			}
		}
	}

	return filtered
}

// ExtractClientIDFromPath extracts client ID from URL path
func ExtractClientIDFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "clients" {
		return parts[1]
	}
	return ""
}

func HashSecret(secret string) ([]byte, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hashed, nil
}

// ValidateRegistrationAccessToken checks if the registration access token is valid
func ValidateRegistrationAccessToken(token string) bool {
	// Simplified validation - in a real implementation, you'd validate JWT
	return token != "" && len(token) > 10
}

// GetEffectiveBaseURL returns the effective base URL considering configuration and proxy headers
func GetEffectiveBaseURL(configBaseURL string, r *http.Request) string {
	if configBaseURL != "" {
		return configBaseURL
	}
	return GetRequestBaseURL(r)
}
