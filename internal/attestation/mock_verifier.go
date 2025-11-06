package attestation

import (
	"time"
)

// MockVerifier is a simple implementation for testing and development
type MockVerifier struct {
	clientID string
}

// NewMockVerifier creates a new mock attestation verifier
func NewMockVerifier(clientID string) *MockVerifier {
	return &MockVerifier{
		clientID: clientID,
	}
}

// VerifyAttestation implements the AttestationVerifier interface
func (m *MockVerifier) VerifyAttestation(token string) (*AttestationResult, error) {
	// Simple mock implementation - always succeeds for testing
	result := &AttestationResult{
		Valid:      true,
		ClientID:   m.clientID,
		Issuer:     "mock-issuer",
		Subject:    m.clientID,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		TrustLevel: "medium",
		Claims: map[string]interface{}{
			"mock":      true,
			"client_id": m.clientID,
			"token":     token,
		},
	}
	
	return result, nil
}