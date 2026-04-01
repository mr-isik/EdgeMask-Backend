package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// encryptionService implements domain.EncryptionService using AES-256-GCM.
// The master key is loaded from the server's environment, NEVER from the DB.
type encryptionService struct {
	gcm cipher.AEAD
}

// NewEncryptionService creates a new AES-GCM encryption service.
// masterKey must be exactly 32 bytes (256 bits) for AES-256.
func NewEncryptionService(masterKey string) (domain.EncryptionService, error) {
	keyBytes := []byte(masterKey)
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes, got %d", len(keyBytes))
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create AES cipher: %s", domain.ErrEncryption, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create GCM: %s", domain.ErrEncryption, err)
	}

	return &encryptionService{gcm: gcm}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext (nonce prepended to ciphertext).
func (s *encryptionService) Encrypt(plaintext string) (string, error) {
	// Generate random nonce
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%w: failed to generate nonce: %s", domain.ErrEncryption, err)
	}

	// Encrypt: nonce is prepended to ciphertext
	ciphertext := s.gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext.
func (s *encryptionService) Decrypt(ciphertextB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("%w: invalid base64: %s", domain.ErrDecryption, err)
	}

	nonceSize := s.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("%w: ciphertext too short", domain.ErrDecryption)
	}

	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := s.gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("%w: decryption failed: %s", domain.ErrDecryption, err)
	}

	return string(plaintext), nil
}
