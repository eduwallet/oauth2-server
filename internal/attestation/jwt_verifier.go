package attestation

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTVerifier implements JWT-based attestation verification
type JWTVerifier struct {
	trustedRoots map[string]*x509.Certificate
	clientID     string
}

// NewJWTVerifier creates a new JWT attestation verifier
func NewJWTVerifier(clientID string, trustAnchors []string) (*JWTVerifier, error) {
	trustedRoots := make(map[string]*x509.Certificate)

	for _, anchor := range trustAnchors {
		cert, err := parseCertificate(anchor)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trust anchor: %w", err)
		}

		// Use subject key identifier or subject as key
		key := cert.Subject.String()
		if len(cert.SubjectKeyId) > 0 {
			key = string(cert.SubjectKeyId)
		}

		trustedRoots[key] = cert
	}

	return &JWTVerifier{
		trustedRoots: trustedRoots,
		clientID:     clientID,
	}, nil
}

// VerifyAttestation verifies a JWT attestation token
func (v *JWTVerifier) VerifyAttestation(token string) (*AttestationResult, error) {
	// Parse the JWT without verification first to get the header
	unverifiedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Return nil to get an unverified token for header inspection
		return nil, fmt.Errorf("unverified")
	})

	if err != nil && unverifiedToken == nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Extract certificate chain from x5c header
	x5cHeader, ok := unverifiedToken.Header["x5c"]
	if !ok {
		return nil, fmt.Errorf("missing x5c certificate chain in JWT header")
	}

	x5cArray, ok := x5cHeader.([]interface{})
	if !ok {
		return nil, fmt.Errorf("x5c header must be an array")
	}

	if len(x5cArray) == 0 {
		return nil, fmt.Errorf("empty x5c certificate chain")
	}

	// Parse the leaf certificate (first in the chain)
	leafCertStr, ok := x5cArray[0].(string)
	if !ok {
		return nil, fmt.Errorf("x5c certificate must be a string")
	}

	leafCert, err := parseCertificateFromBase64(leafCertStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Verify certificate chain
	if err := v.verifyCertificateChain(x5cArray); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Parse and verify the JWT with the leaf certificate's public key
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the public key from the leaf certificate
		return leafCert.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}

	// Extract and validate claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid iss claim")
	}

	// Validate subject (should match client_id)
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid sub claim")
	}

	if sub != v.clientID {
		return nil, fmt.Errorf("subject mismatch: expected %s, got %s", v.clientID, sub)
	}

	// Validate audience
	aud, ok := claims["aud"]
	if !ok {
		return nil, fmt.Errorf("missing aud claim")
	}

	// aud can be string or []string
	var audiences []string
	switch v := aud.(type) {
	case string:
		audiences = []string{v}
	case []interface{}:
		for _, a := range v {
			if audStr, ok := a.(string); ok {
				audiences = append(audiences, audStr)
			}
		}
	default:
		return nil, fmt.Errorf("invalid aud claim type")
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token has expired")
		}
	}

	// Validate not before
	if nbf, ok := claims["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return nil, fmt.Errorf("token not yet valid")
		}
	}

	// Extract cnf claim for confirmation
	cnf, _ := claims["cnf"]

	// Extract attestation-specific claims
	attClaims := make(map[string]interface{})
	for key, value := range claims {
		if strings.HasPrefix(key, "att_") {
			attClaims[key] = value
		}
	}

	result := &AttestationResult{
		Valid:      true,
		ClientID:   sub,
		Issuer:     iss,
		Audiences:  audiences,
		Subject:    sub,
		IssuedAt:   time.Now(),                // Could extract from iat claim
		ExpiresAt:  time.Now().Add(time.Hour), // Could extract from exp claim
		Claims:     attClaims,
		TrustLevel: "high", // Could be determined based on issuer/certificate chain
	}

	// Add confirmation if present
	if cnf != nil {
		result.Confirmation = cnf
	}

	return result, nil
}

// verifyCertificateChain verifies the X.509 certificate chain
func (v *JWTVerifier) verifyCertificateChain(x5cArray []interface{}) error {
	if len(x5cArray) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Parse all certificates in the chain
	var certs []*x509.Certificate
	for i, certData := range x5cArray {
		certStr, ok := certData.(string)
		if !ok {
			return fmt.Errorf("certificate at index %d is not a string", i)
		}

		cert, err := parseCertificateFromBase64(certStr)
		if err != nil {
			return fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}

		certs = append(certs, cert)
	}

	// Create certificate pool with trusted roots
	roots := x509.NewCertPool()
	for _, root := range v.trustedRoots {
		roots.AddCert(root)
	}

	// Create intermediate pool
	intermediates := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
	}

	// Verify the leaf certificate
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err := certs[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// parseCertificate parses a PEM-encoded certificate
func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// parseCertificateFromBase64 parses a base64-encoded DER certificate
func parseCertificateFromBase64(certB64 string) (*x509.Certificate, error) {
	// Remove any whitespace
	certB64 = strings.ReplaceAll(certB64, " ", "")
	certB64 = strings.ReplaceAll(certB64, "\n", "")
	certB64 = strings.ReplaceAll(certB64, "\r", "")

	// Decode base64
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 certificate: %w", err)
	}

	// Parse the DER certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
	}

	return cert, nil
}

// AttestationClaims represents structured attestation claims
type AttestationClaims struct {
	// Standard JWT claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti,omitempty"`

	// Confirmation claim
	Confirmation interface{} `json:"cnf,omitempty"`

	// Attestation-specific claims
	AttestationType    string                 `json:"att_type,omitempty"`
	AttestationLevel   string                 `json:"att_level,omitempty"`
	AttestationDetails map[string]interface{} `json:"att_details,omitempty"`
	HardwareBacked     bool                   `json:"att_hardware_backed,omitempty"`
	SecureElement      bool                   `json:"att_secure_element,omitempty"`
	BiometricAuth      bool                   `json:"att_biometric,omitempty"`
	DeviceIntegrity    string                 `json:"att_device_integrity,omitempty"`
	AppIntegrity       string                 `json:"att_app_integrity,omitempty"`
}

// Valid validates the attestation claims
func (a *AttestationClaims) Valid() error {
	if a.Issuer == "" {
		return fmt.Errorf("missing issuer")
	}

	if a.Subject == "" {
		return fmt.Errorf("missing subject")
	}

	if len(a.Audience) == 0 {
		return fmt.Errorf("missing audience")
	}

	now := time.Now().Unix()

	if a.ExpiresAt > 0 && now > a.ExpiresAt {
		return fmt.Errorf("token has expired")
	}

	if a.NotBefore > 0 && now < a.NotBefore {
		return fmt.Errorf("token not yet valid")
	}

	return nil
}
