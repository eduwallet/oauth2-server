package handlers

import (
	"context"
	"net/http"
	"oauth2-server/internal/attestation"
	"strings"

	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// storeAttestationInSession stores attestation results in session claims
func (h *TokenHandler) storeAttestationInSession(ctx context.Context, session *openid.DefaultSession) {
	// Check if attestation was performed and store the result in session claims
	if attestationResult, hasAttestation := attestation.GetAttestationResult(ctx); hasAttestation && attestationResult.Valid {
		h.Log.Debugf("🔍 Storing attestation result in session claims: hasAttestation=%t, valid=%t", hasAttestation, attestationResult.Valid)

		// Initialize claims if nil
		if session.Claims == nil {
			session.Claims = &jwt.IDTokenClaims{}
		}
		if session.Claims.Extra == nil {
			session.Claims.Extra = make(map[string]interface{})
		}

		// Store attestation information in session claims (this gets persisted with the token)
		attestationInfo := map[string]interface{}{
			"attestation_verified":    true,
			"attestation_trust_level": attestationResult.TrustLevel,
			"attestation_issued_at":   attestationResult.IssuedAt.Unix(),
			"attestation_expires_at":  attestationResult.ExpiresAt.Unix(),
		}

		// Extract additional attestation details from claims if available
		if attestationResult.Claims != nil {
			if keyId, ok := attestationResult.Claims["att_device_id"].(string); ok && keyId != "" {
				attestationInfo["attestation_key_id"] = keyId
			} else if issuerKeyId, ok := attestationResult.Claims["iss"].(string); ok && strings.Contains(issuerKeyId, "hsm:") {
				// Extract key ID from issuer claim like "hsm:hsm_ae26b334"
				parts := strings.Split(issuerKeyId, ":")
				if len(parts) == 2 {
					attestationInfo["attestation_key_id"] = parts[1]
				}
			}
			if hsmBacked, ok := attestationResult.Claims["att_hardware_backed"].(bool); ok {
				attestationInfo["hsm_backed"] = hsmBacked
			}
			if bioAuth, ok := attestationResult.Claims["att_biometric"].(bool); ok {
				attestationInfo["bio_authenticated"] = bioAuth
			}
		}

		session.Claims.Extra["attestation"] = attestationInfo
		h.Log.Debugf("✅ Stored attestation info in session claims")
	} else {
		h.Log.Debugf("⚠️ Not storing attestation: hasAttestation=%t, valid=%t", hasAttestation, false)
	}
}

// storeIssuerStateInSession stores issuer_state in session claims if available
func (h *TokenHandler) storeIssuerStateInSession(r *http.Request, session *openid.DefaultSession) {
	// Store issuer_state in session claims if available (for authorization code flow)
	authCode := r.FormValue("code")
	h.Log.Printf("🔍 storeIssuerStateInSession called with authCode: %s", authCode)
	if authCode != "" && h.AuthCodeToStateMap != nil {
		h.Log.Printf("🔍 AuthCodeToStateMap has %d entries", len(*h.AuthCodeToStateMap))
		for k, v := range *h.AuthCodeToStateMap {
			h.Log.Printf("🔍 Map entry: %s -> %s", k[:10]+"...", v[:10]+"...")
		}
		if issuerState, exists := (*h.AuthCodeToStateMap)[authCode]; exists {
			h.Log.Printf("🔍 Found issuer_state in map: %s", issuerState)

			// Initialize claims if nil
			if session.Claims == nil {
				session.Claims = &jwt.IDTokenClaims{}
			}
			if session.Claims.Extra == nil {
				session.Claims.Extra = make(map[string]interface{})
			}

			session.Claims.Extra["issuer_state"] = issuerState
			h.Log.Printf("✅ Stored issuer_state in session claims")
			// Clean up the authorization code mapping
			delete(*h.AuthCodeToStateMap, authCode)
		} else {
			h.Log.Printf("⚠️ issuer_state not found in AuthCodeToStateMap for authCode: %s", authCode)
		}
	} else {
		h.Log.Printf("⚠️ No authCode or AuthCodeToStateMap is nil")
	}
}
