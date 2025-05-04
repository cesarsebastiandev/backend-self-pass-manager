package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

func EncryptAES(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DeriveKeyFromPassword(password string) []byte {
	// Perform SHA-256 hash on the password to guarantee a 32-byte length
	hash := sha256.Sum256([]byte(password))
	return hash[:] // Return 32 bytes suitable for AES-256
}

func Decrypt(encrypted string, password string) (string, error) {
	// Derive a 32-byte key from the password
	key := DeriveKeyFromPassword(password)

	// Decode the encrypted text from base64
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	// Create an AES block cipher with the derived key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Use GCM for AES authenticated encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract the nonce and ciphertext
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("Data is too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt and verify the authenticity of the message
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
