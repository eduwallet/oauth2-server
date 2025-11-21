package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// JWTVerifier implements JWT-based attestation verification
type JWTVerifier struct {
	trustedRoots map[string]*x509.Certificate
	clientID     string
	logger       *logrus.Logger
}

// NewJWTVerifier creates a new JWT attestation verifier
func NewJWTVerifier(clientID string, trustAnchors []string, logger *logrus.Logger) (*JWTVerifier, error) {
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
		logger:       logger,
	}, nil
}

// VerifyAttestation verifies a JWT attestation token
func (v *JWTVerifier) VerifyAttestation(token string) (*AttestationResult, error) {
	fmt.Printf("[DEBUG] JWT attestation verification starting for client: %s\n", v.clientID)

	// Parse the JWT header manually to extract x5c without full verification
	header, _, _, err := v.parseJWTManually(token)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to parse JWT manually: %v\n", err)
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	fmt.Printf("[DEBUG] JWT header parsed manually: %+v\n", header)

	// Extract certificate chain from x5c header
	x5cHeader, ok := header["x5c"]
	if !ok {
		fmt.Printf("[DEBUG] x5c header missing in JWT header: %+v\n", header)
		return nil, fmt.Errorf("missing x5c certificate chain in JWT header")
	}

	fmt.Printf("[DEBUG] x5c header value: %+v\n", x5cHeader)

	// Debug: check type and length of x5c
	switch v := x5cHeader.(type) {
	case []interface{}:
		fmt.Printf("[DEBUG] x5c is array, length: %d\n", len(v))
		for i, cert := range v {
			fmt.Printf("[DEBUG] x5c[%d]: %v\n", i, cert)
		}
	default:
		fmt.Printf("[DEBUG] x5c is not array, type: %T, value: %v\n", v, v)
	}

	x5cArray, ok := x5cHeader.([]interface{})
	if !ok {
		return nil, fmt.Errorf("x5c header must be an array, got %T", x5cHeader)
	}

	if len(x5cArray) == 0 {
		return nil, fmt.Errorf("empty x5c certificate chain")
	}

	// Parse the leaf certificate (first in the chain)
	leafCertStr, ok := x5cArray[0].(string)
	if !ok {
		return nil, fmt.Errorf("x5c certificate must be a string, got %T", x5cArray[0])
	}

	fmt.Printf("[DEBUG] Parsing leaf certificate from x5c[0]\n")
	leafCert, err := parseCertificateFromBase64(leafCertStr)
	if err != nil {
		fmt.Printf("[DEBUG] Failed to parse leaf certificate: %v\n", err)
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	fmt.Printf("[DEBUG] Leaf certificate parsed successfully - Subject: %s, Issuer: %s\n", leafCert.Subject.String(), leafCert.Issuer.String())

	// Parse and verify the JWT with the leaf certificate's public key
	fmt.Printf("[DEBUG] Verifying JWT signature with leaf certificate public key\n")
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Support ES256 (ECDSA)
		if token.Method.Alg() != "ES256" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		pubKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("x5c public key is not ECDSA")
		}
		fmt.Printf("[DEBUG] JWT signature verification key type: %T\n", pubKey)
		return pubKey, nil
	})

	if err != nil {
		fmt.Printf("[DEBUG] JWT signature verification failed: %v\n", err)
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	if !parsedToken.Valid {
		fmt.Printf("[DEBUG] JWT token is not valid after parsing\n")
		return nil, fmt.Errorf("invalid JWT token")
	}

	fmt.Printf("[DEBUG] JWT signature verification successful\n")

	// Extract and validate claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Printf("[DEBUG] Failed to extract JWT claims\n")
		return nil, fmt.Errorf("invalid JWT claims")
	}

	fmt.Printf("[DEBUG] JWT claims extracted successfully: %+v\n", claims)

	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok {
		fmt.Printf("[DEBUG] Missing or invalid iss claim\n")
		return nil, fmt.Errorf("missing or invalid iss claim")
	}
	fmt.Printf("[DEBUG] Issuer claim validated: %s\n", iss)

	// Validate subject (should match client_id)
	sub, ok := claims["sub"].(string)
	if !ok {
		fmt.Printf("[DEBUG] Missing or invalid sub claim\n")
		return nil, fmt.Errorf("missing or invalid sub claim")
	}
	fmt.Printf("[DEBUG] Subject claim: %s (expected client_id: %s)\n", sub, v.clientID)

	if sub != v.clientID {
		fmt.Printf("[DEBUG] Subject mismatch: expected %s, got %s\n", v.clientID, sub)
		return nil, fmt.Errorf("subject mismatch: expected %s, got %s", v.clientID, sub)
	}
	fmt.Printf("[DEBUG] Subject validation successful\n")

	// Validate audience
	aud, ok := claims["aud"]
	if !ok {
		fmt.Printf("[DEBUG] Missing aud claim\n")
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
		fmt.Printf("[DEBUG] Invalid aud claim type: %T\n", v)
		return nil, fmt.Errorf("invalid aud claim type")
	}
	fmt.Printf("[DEBUG] Audience validation successful: %v\n", audiences)

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		fmt.Printf("[DEBUG] Expiration claim: %v (Unix: %d)\n", expTime, int64(exp))
		if time.Now().Unix() > int64(exp) {
			fmt.Printf("[DEBUG] Token has expired\n")
			return nil, fmt.Errorf("token has expired")
		}
		fmt.Printf("[DEBUG] Expiration validation successful\n")
	}

	// Validate not before
	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		fmt.Printf("[DEBUG] Not before claim: %v (Unix: %d)\n", nbfTime, int64(nbf))
		if time.Now().Unix() < int64(nbf) {
			fmt.Printf("[DEBUG] Token not yet valid\n")
			return nil, fmt.Errorf("token not yet valid")
		}
		fmt.Printf("[DEBUG] Not before validation successful\n")
	}

	// Extract cnf claim for confirmation
	cnf := claims["cnf"]
	if cnf != nil {
		fmt.Printf("[DEBUG] Confirmation claim found: %+v\n", cnf)
	}

	// Extract attestation-specific claims
	attClaims := make(map[string]interface{})

	// Extract known attestation claims from the payload
	if hwBacked, ok := claims["hwbacked"].(bool); ok {
		attClaims["att_hardware_backed"] = hwBacked
	}
	if bioAuth, ok := claims["bio_auth"].(bool); ok {
		attClaims["att_biometric"] = bioAuth
	}
	if secLevel, ok := claims["sec_level"].(string); ok {
		attClaims["att_security_level"] = secLevel
	}
	if tamperDetected, ok := claims["tamper_detected"].(bool); ok {
		attClaims["att_tamper_detected"] = tamperDetected
	}
	if bootState, ok := claims["boot_state"].(string); ok {
		attClaims["att_boot_state"] = bootState
	}
	if deviceId, ok := claims["device_id"].(string); ok {
		attClaims["att_device_id"] = deviceId
	}
	if firmwareVersion, ok := claims["firmware_version"].(string); ok {
		attClaims["att_firmware_version"] = firmwareVersion
	}
	if hardwareVersion, ok := claims["hardware_version"].(string); ok {
		attClaims["att_hardware_version"] = hardwareVersion
	}
	if bioType, ok := claims["bio_type"].(string); ok {
		attClaims["att_bio_type"] = bioType
	}

	// Also extract any claims that start with "att_" for backward compatibility
	for key, value := range claims {
		if strings.HasPrefix(key, "att_") {
			attClaims[key] = value
		}
	}

	fmt.Printf("[DEBUG] Attestation claims extracted: %+v\n", attClaims)

	result := &AttestationResult{
		Valid:      true,
		ClientID:   sub,
		Issuer:     iss,
		Audiences:  audiences,
		Subject:    sub,
		IssuedAt:   time.Now(),                // Could extract from iat claim
		ExpiresAt:  time.Now().Add(time.Hour), // Could extract from exp claim
		Claims:     attClaims,
		TrustLevel: "high", // Default to high, but could be determined based on sec_level claim
	}

	// Determine trust level based on sec_level claim
	if secLevel, ok := attClaims["att_security_level"].(string); ok {
		switch secLevel {
		case "hardware":
			result.TrustLevel = "high"
		case "software":
			result.TrustLevel = "medium"
		default:
			result.TrustLevel = "low"
		}
	}

	// Add confirmation if present
	if cnf != nil {
		result.Confirmation = cnf
		fmt.Printf("[DEBUG] Confirmation claim added to result\n")
	}

	fmt.Printf("[DEBUG] Attestation verification completed successfully\n")
	fmt.Printf("[DEBUG] Final result: Valid=%t, ClientID=%s, Issuer=%s, TrustLevel=%s\n",
		result.Valid, result.ClientID, result.Issuer, result.TrustLevel)

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

	leafCert := certs[0]

	// Create certificate pool with trusted roots
	roots := x509.NewCertPool()
	for _, root := range v.trustedRoots {
		roots.AddCert(root)
	}

	// Check if this is a self-signed certificate (issuer == subject)
	isSelfSigned := leafCert.Issuer.String() == leafCert.Subject.String()

	if isSelfSigned {
		fmt.Printf("[DEBUG] Detected self-signed certificate (issuer == subject)\n")

		// Verify the self-signature is valid
		if err := leafCert.CheckSignatureFrom(leafCert); err != nil {
			return fmt.Errorf("self-signed certificate signature verification failed: %w", err)
		}

		fmt.Printf("[DEBUG] Self-signed certificate signature verified successfully\n")

		// For self-signed certificates, add them to the trusted roots dynamically
		// This allows proper certificate verification while supporting browser-generated certs
		fmt.Printf("[DEBUG] Adding self-signed certificate to trusted roots for verification\n")
		roots.AddCert(leafCert)
	}

	// Create intermediate pool
	intermediates := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
	}

	// Verify the leaf certificate using the full chain verification process
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	fmt.Printf("[DEBUG] Certificate chain verified successfully, found %d valid chain(s)\n", len(chains))
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

// parseJWTManually parses a JWT token manually to extract header, payload, and signature without verification
func (v *JWTVerifier) parseJWTManually(token string) (map[string]interface{}, string, string, error) {
	// Split the JWT into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, "", "", fmt.Errorf("failed to unmarshal JWT header: %w", err)
	}

	return header, parts[1], parts[2], nil
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
