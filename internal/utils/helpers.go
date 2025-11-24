package utils

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func HashSecret(secret string) ([]byte, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hashed, nil
}

// ValidateSecret validates a secret against its bcrypt hash
func ValidateSecret(secret string, hashedSecret []byte) bool {
	return bcrypt.CompareHashAndPassword(hashedSecret, []byte(secret)) == nil
}

// GetEffectiveBaseURL returns the effective base URL considering configuration and proxy headers
func GetEffectiveBaseURL(configBaseURL string, r *http.Request) string {
	if configBaseURL != "" {
		return configBaseURL
	}
	return GetRequestBaseURL(r)
}
