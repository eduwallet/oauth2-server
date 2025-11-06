package attestation

import (
	"context"
)

// Context key for storing attestation results
type contextKey string

const attestationResultKey contextKey = "attestation_result"

// WithAttestationResult stores an attestation result in the context
func WithAttestationResult(ctx context.Context, result *AttestationResult) context.Context {
	return context.WithValue(ctx, attestationResultKey, result)
}

// GetAttestationResult retrieves an attestation result from the context
func GetAttestationResult(ctx context.Context) (*AttestationResult, bool) {
	result, ok := ctx.Value(attestationResultKey).(*AttestationResult)
	return result, ok
}

// HasAttestationResult checks if the context contains an attestation result
func HasAttestationResult(ctx context.Context) bool {
	_, ok := GetAttestationResult(ctx)
	return ok
}
