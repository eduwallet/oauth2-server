package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// SecretManager handles encryption/decryption of sensitive client data
type SecretManager struct {
	masterKey []byte // Should come from secure key management system
}

// NewSecretManager creates a new secret manager with the given master key
func NewSecretManager(masterKey []byte) *SecretManager {
	return &SecretManager{
		masterKey: masterKey,
	}
}

// EncryptSecret encrypts a plaintext secret using AES-256-GCM
func (sm *SecretManager) EncryptSecret(plainText string) (string, error) {
	block, err := aes.NewCipher(sm.masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)

	// Return base64 encoded result
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptSecret decrypts an encrypted secret back to plaintext
func (sm *SecretManager) DecryptSecret(encryptedText string) (string, error) {
	// Step 1: Decode the base64 encrypted text back to bytes
	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Step 2: Create the AES cipher with the master key
	block, err := aes.NewCipher(sm.masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Step 3: Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Step 4: Extract nonce from the beginning of ciphertext
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := cipherText[:nonceSize]     // First nonceSize bytes are the nonce
	cipherText = cipherText[nonceSize:] // Rest is the actual encrypted data

	// Step 5: Decrypt the ciphertext
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plainText), nil
}
