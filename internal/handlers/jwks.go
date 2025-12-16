package handlers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"oauth2-server/internal/utils"
)

// JWKSHandler manages JSON Web Key Set requests
// It can expose a runtime RSA public key provided via a GetPrivateKey function
// which returns the server's private key (or public key) when available.
type JWKSHandler struct {
	GetPrivateKey func(context.Context) (interface{}, error)
}

// NewJWKSHandler creates a new JWKS handler that can use an optional key getter
func NewJWKSHandler(getter func(context.Context) (interface{}, error)) *JWKSHandler {
	return &JWKSHandler{GetPrivateKey: getter}
}

// ServeHTTP handles JWKS requests (/.well-known/jwks.json)
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Debug: log whether a key getter is configured
	log.Printf("🔍 JWKS: GetPrivateKey configured: %t", h.GetPrivateKey != nil)

	// If no key getter is configured, return a conservative placeholder
	if h.GetPrivateKey == nil {
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
		return
	}

	// Obtain private key and derive public key
	privKeyIface, err := h.GetPrivateKey(context.Background())
	if err != nil || privKeyIface == nil {
		log.Printf("❌ JWKS: failed to get private key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed to retrieve key"}`))
		return
	}

	var pub *rsa.PublicKey
	switch k := privKeyIface.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *rsa.PublicKey:
		pub = k
	default:
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"unsupported key type"}`))
		return
	}

	// Encode modulus and exponent
	nBase64 := utils.EncodeBigIntToBase64URL(pub.N)
	eBig := big.NewInt(int64(pub.E))
	eBase64 := utils.EncodeBigIntToBase64URL(eBig)

	// Compute kid using shared helper
	kid := utils.ComputeKIDFromPublicKey(pub)

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   nBase64,
		"e":   eBase64,
	}

	jwks := map[string]interface{}{"keys": []map[string]interface{}{jwk}}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}
