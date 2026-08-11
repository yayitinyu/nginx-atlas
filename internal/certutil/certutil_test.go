package certutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestValidateCertificateBundle(t *testing.T) {
	now := time.Now().UTC()
	certPEM, keyPEM := makeCertificate(t, "api.example.com", now.Add(-time.Hour), now.Add(48*time.Hour), nil)
	info, err := Validate(certPEM, keyPEM, "api.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if info.FingerprintSHA256 == "" || !info.NotAfter.After(now) {
		t.Fatal("certificate metadata is incomplete")
	}
	if _, err := Validate(certPEM, keyPEM, "other.example.com", now); err == nil {
		t.Fatal("expected hostname mismatch")
	}
}

func TestValidateRejectsMismatchedAndExpiredKeys(t *testing.T) {
	now := time.Now().UTC()
	certPEM, _ := makeCertificate(t, "api.example.com", now.Add(-time.Hour), now.Add(time.Hour), nil)
	_, otherKey := makeCertificate(t, "api.example.com", now.Add(-time.Hour), now.Add(time.Hour), nil)
	if _, err := Validate(certPEM, otherKey, "api.example.com", now); err == nil {
		t.Fatal("expected key mismatch")
	}
	expiredCert, expiredKey := makeCertificate(t, "api.example.com", now.Add(-48*time.Hour), now.Add(-time.Hour), nil)
	if _, err := Validate(expiredCert, expiredKey, "api.example.com", now); err == nil {
		t.Fatal("expected expired certificate to fail")
	}
}

func TestCoversHostnameUsesX509WildcardRules(t *testing.T) {
	t.Parallel()

	if !CoversHostname([]string{"*.example.com"}, "api.example.com") {
		t.Fatal("expected single-label wildcard to cover api.example.com")
	}
	for _, hostname := range []string{"example.com", "deep.api.example.com", "example.net"} {
		if CoversHostname([]string{"*.example.com"}, hostname) {
			t.Fatalf("wildcard unexpectedly covered %q", hostname)
		}
	}
}

func makeCertificate(t *testing.T, domain string, notBefore, notAfter time.Time, key *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
