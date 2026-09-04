package securebox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const prefix = "v1:"

type Box struct {
	aead      cipher.AEAD
	digestKey [sha256.Size]byte
}

func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must contain exactly 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	digestKey, err := hkdf.Key(sha256.New, key, nil, "nginx-atlas:securebox:keyed-digest:v1", sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("derive keyed digest key: %w", err)
	}
	box := &Box{aead: aead}
	copy(box.digestKey[:], digestKey)
	clear(digestKey)
	return box, nil
}

func ParseKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("master key is empty")
	}
	decoders := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, decode := range decoders {
		key, err := decode(value)
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}
	return nil, errors.New("master key must be 32 bytes encoded as base64url, base64, or hexadecimal")
}

func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generate master key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

func (b *Box) Seal(purpose string, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("refusing to encrypt an empty secret")
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := b.aead.Seal(nil, nonce, plaintext, []byte(purpose))
	payload := append(nonce, sealed...)
	return prefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (b *Box) Open(purpose, value string) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("unsupported ciphertext version")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	nonceSize := b.aead.NonceSize()
	if len(payload) <= nonceSize {
		return nil, errors.New("ciphertext is truncated")
	}
	plaintext, err := b.aead.Open(nil, payload[:nonceSize], payload[nonceSize:], []byte(purpose))
	if err != nil {
		return nil, errors.New("decrypt secret: authentication failed")
	}
	return plaintext, nil
}

func (b *Box) KeyedDigest(purpose string, value []byte) []byte {
	mac := hmac.New(sha256.New, b.digestKey[:])
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}
