package attestation

import (
	"net/http"
	"time"
)

// AttestationVerifier defines the interface for verifying client attestations
type AttestationVerifier interface {
	// VerifyAttestation verifies an attestation token and returns the result
	VerifyAttestation(token string) (*AttestationResult, error)
}

// TLSAttestationVerifier defines the interface for TLS-based attestation verification
type TLSAttestationVerifier interface {
	// VerifyAttestation verifies TLS-based attestation using the HTTP request
	VerifyAttestation(r *http.Request) (*AttestationResult, error)
}

// AttestationResult contains the result of attestation verification
// AttestationResult represents the result of attestation verification
type AttestationResult struct {
	Valid         bool                   `json:"valid"`
	ClientID      string                 `json:"client_id"`
	Issuer        string                 `json:"issuer,omitempty"`
	Subject       string                 `json:"subject,omitempty"`
	Audiences     []string               `json:"audiences,omitempty"`
	IssuedAt      time.Time              `json:"issued_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Claims        map[string]interface{} `json:"claims,omitempty"`
	TrustLevel    string                 `json:"trust_level"`
	Confirmation  interface{}            `json:"confirmation,omitempty"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
}

// TrustAnchor represents a trusted certificate authority for attestation verification
type TrustAnchor struct {
	Name            string `yaml:"name" json:"name"`
	Type            string `yaml:"type" json:"type"` // tpm, hsm, android, ios
	CertificatePath string `yaml:"certificate_path" json:"certificate_path"`
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	Description     string `yaml:"description" json:"description"`
}

// AttestationConfig represents the configuration for attestation verification
type AttestationConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	Experimental bool          `yaml:"experimental" json:"experimental"`
	TrustAnchors []TrustAnchor `yaml:"trust_anchors" json:"trust_anchors"`
	Verification struct {
		ClockSkewToleranceSeconds   int  `yaml:"clock_skew_tolerance_seconds" json:"clock_skew_tolerance_seconds"`
		NonceCacheDurationSeconds   int  `yaml:"nonce_cache_duration_seconds" json:"nonce_cache_duration_seconds"`
		RequireFreshAttestation     bool `yaml:"require_fresh_attestation" json:"require_fresh_attestation"`
		MaxAttestationAgeSeconds    int  `yaml:"max_attestation_age_seconds" json:"max_attestation_age_seconds"`
	} `yaml:"verification" json:"verification"`
	SupportedFormats []string `yaml:"supported_formats" json:"supported_formats"`
}

// ClientAttestationConfig represents attestation configuration for a specific client
type ClientAttestationConfig struct {
	AttestorType            string   `yaml:"attestor_type" json:"attestor_type"`
	TrustAnchor             string   `yaml:"trust_anchor" json:"trust_anchor"`
	RequiredClaims          []string `yaml:"required_claims" json:"required_claims"`
	AllowDebugAttestation   bool     `yaml:"allow_debug_attestation" json:"allow_debug_attestation"`
}

// AttestationError represents attestation-specific errors
type AttestationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func (e *AttestationError) Error() string {
	if e.Detail != "" {
		return e.Message + ": " + e.Detail
	}
	return e.Message
}

// Common attestation error codes
var (
	ErrInvalidAttestationFormat = &AttestationError{
		Code:    "invalid_attestation_format",
		Message: "The attestation format is not supported or malformed",
	}
	
	ErrAttestationExpired = &AttestationError{
		Code:    "attestation_expired",
		Message: "The attestation has expired",
	}
	
	ErrInvalidSignature = &AttestationError{
		Code:    "invalid_signature",
		Message: "The attestation signature is invalid",
	}
	
	ErrUntrustedAttestor = &AttestationError{
		Code:    "untrusted_attestor",
		Message: "The attestation is not from a trusted source",
	}
	
	ErrMissingRequiredClaims = &AttestationError{
		Code:    "missing_required_claims",
		Message: "The attestation is missing required claims",
	}
	
	ErrNonceReplayDetected = &AttestationError{
		Code:    "nonce_replay_detected",
		Message: "The attestation nonce has been used before",
	}
)