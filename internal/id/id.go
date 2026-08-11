package id

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func New(prefix string) (string, error) {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return prefix + "_" + strings.ToLower(encoding.EncodeToString(raw)), nil
}

func Token(bytes int) (string, error) {
	if bytes < 16 {
		return "", fmt.Errorf("token entropy must be at least 16 bytes")
	}
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return strings.ToLower(encoding.EncodeToString(raw)), nil
}
