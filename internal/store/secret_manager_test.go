package store

import (
	"testing"
)

func TestSecretManager_EncryptDecrypt(t *testing.T) {
	// Test key (32 bytes for AES-256)
	key := "abcdefghijklmnopqrstuvwxyz123456" // exactly 32 bytes
	sm := NewSecretManager([]byte(key))

	plaintext := "test-secret-123"

	// Test encryption
	encrypted, err := sm.EncryptSecret(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt secret: %v", err)
	}

	if encrypted == "" {
		t.Fatal("Encrypted secret is empty")
	}

	if encrypted == plaintext {
		t.Fatal("Encrypted secret is identical to plaintext")
	}

	// Test decryption
	decrypted, err := sm.DecryptSecret(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt secret: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Decrypted secret does not match original. Got: %s, Expected: %s", decrypted, plaintext)
	}
}

func TestSecretManager_DifferentKeys(t *testing.T) {
	key1 := "abcdefghijklmnopqrstuvwxyz123456" // exactly 32 bytes
	key2 := "123456789012abcdefghijklmnopqr"   // exactly 32 bytes

	sm1 := NewSecretManager([]byte(key1))
	sm2 := NewSecretManager([]byte(key2))

	plaintext := "test-secret-123"

	// Encrypt with key1
	encrypted, err := sm1.EncryptSecret(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt secret: %v", err)
	}

	// Try to decrypt with key2 (should fail)
	_, err = sm2.DecryptSecret(encrypted)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong key")
	}
}

func TestSecretManager_InvalidCiphertext(t *testing.T) {
	key := "abcdefghijklmnopqrstuvwxyz123456789012"
	sm := NewSecretManager([]byte(key))

	// Test with invalid base64
	_, err := sm.DecryptSecret("invalid-base64!")
	if err == nil {
		t.Fatal("Expected error for invalid base64")
	}

	// Test with valid base64 but invalid ciphertext
	_, err = sm.DecryptSecret("dGhpcy1pcy1pbnZhbGlk")
	if err == nil {
		t.Fatal("Expected error for invalid ciphertext")
	}
}
