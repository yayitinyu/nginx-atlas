package certutil

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Info struct {
	Leaf              *x509.Certificate
	FingerprintSHA256 string
	Issuer            string
	SerialNumber      string
	NotBefore         time.Time
	NotAfter          time.Time
	DNSNames          []string
}

// CoversHostname applies the same wildcard and hostname rules as Go's X.509
// verifier without trusting a caller-provided string comparison.
func CoversHostname(dnsNames []string, hostname string) bool {
	certificate := x509.Certificate{DNSNames: append([]string(nil), dnsNames...)}
	return certificate.VerifyHostname(strings.TrimSpace(strings.ToLower(hostname))) == nil
}

func Validate(fullchainPEM, privateKeyPEM []byte, domain string, now time.Time) (Info, error) {
	leaf, err := parseLeaf(fullchainPEM)
	if err != nil {
		return Info{}, err
	}
	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return Info{}, err
	}
	if err := matchPublicKey(leaf.PublicKey, key.Public()); err != nil {
		return Info{}, err
	}
	if now.Before(leaf.NotBefore.Add(-5 * time.Minute)) {
		return Info{}, fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return Info{}, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain != "" {
		if err := leaf.VerifyHostname(domain); err != nil {
			return Info{}, fmt.Errorf("certificate does not cover %q: %w", domain, err)
		}
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	return Info{
		Leaf:              leaf,
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		Issuer:            leaf.Issuer.String(),
		SerialNumber:      leaf.SerialNumber.Text(16),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
		DNSNames:          append([]string(nil), leaf.DNSNames...),
	}, nil
}

// VerifyTrustedChain verifies that a certificate returned from an ACME job is
// anchored in the controller's trust store. Local/imported certificates keep
// their explicit private-CA workflow and are validated separately by Validate.
func VerifyTrustedChain(fullchainPEM []byte, domain string, now time.Time, roots *x509.CertPool) error {
	certificates, err := parseCertificates(fullchainPEM)
	if err != nil {
		return err
	}
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("load system certificate roots: %w", err)
		}
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err = certificates[0].Verify(x509.VerifyOptions{
		DNSName:       strings.TrimSpace(strings.ToLower(domain)),
		CurrentTime:   now,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("certificate chain is not trusted: %w", err)
	}
	return nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		data = rest
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate file does not contain an X.509 certificate")
	}
	return certificates, nil
}

func parseLeaf(data []byte) (*x509.Certificate, error) {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		data = rest
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
		return cert, nil
	}
	return nil, errors.New("certificate file does not contain an X.509 certificate")
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key file does not contain a PEM key")
	}
	parsers := []func([]byte) (any, error){
		func(der []byte) (any, error) { return x509.ParsePKCS8PrivateKey(der) },
		func(der []byte) (any, error) { return x509.ParsePKCS1PrivateKey(der) },
		func(der []byte) (any, error) { return x509.ParseECPrivateKey(der) },
	}
	for _, parse := range parsers {
		parsed, err := parse(block.Bytes)
		if err != nil {
			continue
		}
		if signer, ok := parsed.(crypto.Signer); ok {
			return signer, nil
		}
	}
	return nil, errors.New("private key file contains an unsupported key")
}

func matchPublicKey(certKey, privateKey crypto.PublicKey) error {
	certDER, err := x509.MarshalPKIXPublicKey(certKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	privateDER, err := x509.MarshalPKIXPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private-key public key: %w", err)
	}
	if !bytes.Equal(certDER, privateDER) {
		return errors.New("certificate and private key do not match")
	}
	return nil
}
