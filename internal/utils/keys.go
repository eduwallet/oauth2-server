package utils

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// EncodeBigIntToBase64URL encodes a big.Int to base64url without padding
func EncodeBigIntToBase64URL(n *big.Int) string {
	b := n.Bytes()
	return base64.RawURLEncoding.EncodeToString(b)
}

// ComputeKIDFromPublicKey computes a kid for an RSA public key using
// base64url(sha256(n || e)). This matches the logic used by the JWKS handler.
func ComputeKIDFromPublicKey(pub *rsa.PublicKey) string {
	eBig := big.NewInt(int64(pub.E))
	thumbSrc := append(pub.N.Bytes(), eBig.Bytes()...)
	thumb := sha256.Sum256(thumbSrc)
	return base64.RawURLEncoding.EncodeToString(thumb[:])
}

// ComputeKIDFromKey accepts either an *rsa.PrivateKey or *rsa.PublicKey
// and returns the computed kid. Returns an error for unsupported types.
func ComputeKIDFromKey(key interface{}) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return ComputeKIDFromPublicKey(&k.PublicKey), nil
	case *rsa.PublicKey:
		return ComputeKIDFromPublicKey(k), nil
	default:
		return "", fmt.Errorf("unsupported key type for kid computation")
	}
}

// GetPrivateKeyFromContext is a tiny helper to call a key getter with context.
// It exists to keep callsites concise; it returns the key or an error.
func GetPrivateKeyFromContext(getter func(context.Context) (interface{}, error)) (interface{}, error) {
	if getter == nil {
		return nil, fmt.Errorf("no key getter provided")
	}
	return getter(context.Background())
}
