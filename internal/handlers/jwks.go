package handlers

import (
	"encoding/json"
	"net/http"
)

// JWKSHandler manages JSON Web Key Set requests
type JWKSHandler struct {
}

// NewJWKSHandler creates a new JWKS handler
func NewJWKSHandler() *JWKSHandler {
	return &JWKSHandler{}
}

// ServeHTTP handles JWKS requests (/.well-known/jwks.json)
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "oauth2-server-key",
				"alg": "RS256",
				"n":   "example-modulus",
				"e":   "AQAB",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}
