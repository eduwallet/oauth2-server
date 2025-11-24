package utils

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateState generates a state parameter for OAuth2 flows
func GenerateState() string {
	state, _ := GenerateRandomString(32)
	return state
}

// GenerateNonce generates a nonce for OpenID Connect
func GenerateNonce() string {
	nonce, _ := GenerateRandomString(32)
	return nonce
}
