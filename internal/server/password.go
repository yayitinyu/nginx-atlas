package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/id"
)

const (
	adminPasswordIterations = 310_000
	adminPasswordSaltBytes  = 16
	adminPasswordHashBytes  = 32
	adminSessionTTL         = 12 * time.Hour
)

func hashAdminPassword(password string) (string, error) {
	salt := make([]byte, adminPasswordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	digest := pbkdf2SHA256([]byte(password), salt, adminPasswordIterations, adminPasswordHashBytes)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", adminPasswordIterations,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest)), nil
}

func verifyAdminPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100_000 || iterations > 2_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 12 || len(salt) > 64 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != adminPasswordHashBytes {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	if iterations <= 0 || keyLength <= 0 {
		return nil
	}
	hashLength := sha256.Size
	blocks := (keyLength + hashLength - 1) / hashLength
	derived := make([]byte, 0, blocks*hashLength)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for iteration := 1; iteration < iterations; iteration++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for index := range t {
				t[index] ^= u[index]
			}
		}
		derived = append(derived, t...)
	}
	return derived[:keyLength]
}

func (s *Server) createAdminSession() (string, time.Time, error) {
	token, err := id.Token(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().UTC().Add(adminSessionTTL)
	hash := sha256.Sum256([]byte(token))
	s.sessionMu.Lock()
	if s.adminSessions == nil {
		s.adminSessions = make(map[[32]byte]time.Time)
	}
	for key, expiry := range s.adminSessions {
		if time.Now().After(expiry) {
			delete(s.adminSessions, key)
		}
	}
	s.adminSessions[hash] = expiresAt
	s.sessionMu.Unlock()
	return token, expiresAt, nil
}

func (s *Server) clearAdminSessions() {
	s.sessionMu.Lock()
	s.adminSessions = make(map[[32]byte]time.Time)
	s.sessionMu.Unlock()
}
