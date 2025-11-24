package attestation

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// TLSVerifier implements TLS certificate-based attestation verification
type TLSVerifier struct {
	trustedRoots map[string]*x509.Certificate
	clientID     string
}

// NewTLSVerifier creates a new TLS attestation verifier
func NewTLSVerifier(clientID string, trustAnchors []string) (*TLSVerifier, error) {
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

	return &TLSVerifier{
		trustedRoots: trustedRoots,
		clientID:     clientID,
	}, nil
}

// VerifyAttestation verifies TLS certificate-based attestation
func (v *TLSVerifier) VerifyAttestation(r *http.Request) (*AttestationResult, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("no TLS connection information available")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificates provided")
	}

	// Get the leaf certificate
	leafCert := r.TLS.PeerCertificates[0]

	// Verify certificate chain
	if err := v.verifyCertificateChain(r.TLS.PeerCertificates); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Extract client identity from certificate
	clientID := v.extractClientID(leafCert)
	if clientID == "" {
		return nil, fmt.Errorf("unable to extract client ID from certificate")
	}

	// Verify client ID matches expected
	if clientID != v.clientID {
		return nil, fmt.Errorf("client ID mismatch: expected %s, got %s", v.clientID, clientID)
	}

	// Extract attestation information from certificate extensions
	claims := v.extractAttestationClaims(leafCert)

	// Determine trust level based on certificate properties
	trustLevel := v.determineTrustLevel(leafCert, r.TLS)

	result := &AttestationResult{
		Valid:      true,
		ClientID:   clientID,
		Issuer:     leafCert.Issuer.String(),
		Subject:    leafCert.Subject.String(),
		IssuedAt:   leafCert.NotBefore,
		ExpiresAt:  leafCert.NotAfter,
		Claims:     claims,
		TrustLevel: trustLevel,
	}

	return result, nil
}

// verifyCertificateChain verifies the X.509 certificate chain
func (v *TLSVerifier) verifyCertificateChain(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("empty certificate chain")
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

// extractClientID extracts the client ID from the certificate
func (v *TLSVerifier) extractClientID(cert *x509.Certificate) string {
	// Try different sources for client ID:

	// 1. Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// 2. Subject Alternative Names
	for _, name := range cert.DNSNames {
		if name != "" {
			return name
		}
	}

	for _, uri := range cert.URIs {
		if uri.String() != "" {
			return uri.String()
		}
	}

	// 3. Organization Unit (sometimes used for client IDs)
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}

	// 4. Serial Number as fallback
	return cert.SerialNumber.String()
}

// extractAttestationClaims extracts attestation information from certificate extensions
func (v *TLSVerifier) extractAttestationClaims(cert *x509.Certificate) map[string]interface{} {
	claims := make(map[string]interface{})

	// Basic certificate information
	claims["cert_serial"] = cert.SerialNumber.String()
	claims["cert_issuer"] = cert.Issuer.String()
	claims["cert_subject"] = cert.Subject.String()
	claims["cert_not_before"] = cert.NotBefore.Unix()
	claims["cert_not_after"] = cert.NotAfter.Unix()

	// Key information
	claims["cert_key_algorithm"] = cert.PublicKeyAlgorithm.String()

	// Certificate policies
	if len(cert.PolicyIdentifiers) > 0 {
		policies := make([]string, len(cert.PolicyIdentifiers))
		for i, oid := range cert.PolicyIdentifiers {
			policies[i] = oid.String()
		}
		claims["cert_policies"] = policies
	}

	// Extended Key Usage
	if len(cert.ExtKeyUsage) > 0 {
		extKeyUsage := make([]string, len(cert.ExtKeyUsage))
		for i, usage := range cert.ExtKeyUsage {
			extKeyUsage[i] = extKeyUsageToString(usage)
		}
		claims["cert_ext_key_usage"] = extKeyUsage
	}

	// Parse custom extensions for attestation data
	for _, ext := range cert.Extensions {
		// Look for attestation-related OIDs
		switch ext.Id.String() {
		case "1.3.6.1.4.1.11129.2.1.17": // Example: Android attestation extension
			claims["android_attestation"] = true
		case "1.2.840.113635.100.8.2": // Example: Apple attestation extension
			claims["apple_attestation"] = true
		default:
			// Store unknown extensions for potential future use
			if ext.Critical {
				claims[fmt.Sprintf("critical_ext_%s", ext.Id.String())] = ext.Value
			}
		}
	}

	return claims
}

// determineTrustLevel determines the trust level based on certificate properties
func (v *TLSVerifier) determineTrustLevel(cert *x509.Certificate, tlsState *tls.ConnectionState) string {
	trustLevel := "medium" // Default trust level

	// Increase trust level based on various factors

	// 1. Hardware-backed keys (would need to check certificate extensions or policies)
	if v.isHardwareBacked(cert) {
		trustLevel = "high"
	}

	// 2. Strong cryptographic algorithms
	if v.hasStrongCrypto(cert, tlsState) {
		if trustLevel == "medium" {
			trustLevel = "high"
		}
	}

	// 3. Trusted issuer
	if v.isTrustedIssuer(cert) {
		if trustLevel == "medium" {
			trustLevel = "high"
		}
	}

	// 4. Recent issuance (not old certificates)
	if time.Since(cert.NotBefore) > 365*24*time.Hour {
		// Certificate is more than a year old, lower trust
		if trustLevel == "high" {
			trustLevel = "medium"
		}
	}

	return trustLevel
}

// isHardwareBacked checks if the certificate indicates hardware-backed keys
func (v *TLSVerifier) isHardwareBacked(cert *x509.Certificate) bool {
	// Check certificate policies or extensions that indicate hardware backing
	// This is implementation-specific based on the CA and device type

	for _, oid := range cert.PolicyIdentifiers {
		// Example OIDs that might indicate hardware backing
		switch oid.String() {
		case "1.3.6.1.4.1.11129.2.1.17": // Android hardware attestation
			return true
		case "1.2.840.113635.100.8.2": // Apple secure enclave
			return true
		}
	}

	return false
}

// hasStrongCrypto checks if strong cryptographic algorithms are used
func (v *TLSVerifier) hasStrongCrypto(cert *x509.Certificate, tlsState *tls.ConnectionState) bool {
	// Check certificate signature algorithm
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return true
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	default:
		return false
	}
}

// isTrustedIssuer checks if the certificate issuer is highly trusted
func (v *TLSVerifier) isTrustedIssuer(cert *x509.Certificate) bool {
	issuer := cert.Issuer.String()

	// Check against a list of highly trusted issuers
	trustedIssuers := []string{
		// Add specific trusted issuer DNs here
		"CN=Device Attestation CA,O=Trusted Corp",
		"CN=Hardware Security Module CA,O=Enterprise",
	}

	for _, trusted := range trustedIssuers {
		if issuer == trusted {
			return true
		}
	}

	return false
}

// extKeyUsageToString converts ExtKeyUsage to string representation
func extKeyUsageToString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageTimeStamping:
		return "timeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocspSigning"
	default:
		return fmt.Sprintf("unknown(%d)", int(usage))
	}
}

// TLSAttestationConfig represents TLS-specific attestation configuration
type TLSAttestationConfig struct {
	RequireClientCert     bool     `yaml:"require_client_cert"`
	TrustedIssuers        []string `yaml:"trusted_issuers"`
	RequireHardwareBacked bool     `yaml:"require_hardware_backed"`
	MinTrustLevel         string   `yaml:"min_trust_level"`
	MaxCertAge            string   `yaml:"max_cert_age"`
}
