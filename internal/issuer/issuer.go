package issuer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/certutil"
	"github.com/yayitinyu/nginx-atlas/internal/nginxconfig"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

var (
	providerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envNamePattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,127}$`)
)

type Runner interface {
	Run(context.Context, string, []string, map[string]string) ([]byte, error)
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args []string, extraEnv map[string]string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append([]string(nil), os.Environ()...)
	for key, value := range extraEnv {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("certificate issuer failed: %w", err)
	}
	return output, nil
}

func Issue(ctx context.Context, payload protocol.IssueCertificatePayload, dataRoot, legoBinary string, runner Runner, now time.Time) (protocol.CertificateBundle, error) {
	domains := normalizeNames(payload.Domain, payload.Domains)
	if len(domains) == 0 {
		return protocol.CertificateBundle{}, errors.New("certificate domain is missing")
	}
	for _, domain := range domains {
		if err := validateName(domain); err != nil {
			return protocol.CertificateBundle{}, err
		}
	}
	if !providerPattern.MatchString(payload.DNSProvider) || payload.DNSProvider == "manual" || payload.DNSProvider == "exec" {
		return protocol.CertificateBundle{}, errors.New("DNS provider is invalid or unsafe for unattended execution")
	}
	if _, err := mail.ParseAddress(payload.Email); err != nil {
		return protocol.CertificateBundle{}, errors.New("ACME account email is invalid")
	}
	directory, err := url.Parse(payload.DirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" {
		return protocol.CertificateBundle{}, errors.New("ACME directory must be an HTTPS URL")
	}
	env := make(map[string]string, len(payload.Credentials)+2)
	for key, value := range payload.Credentials {
		if !envNamePattern.MatchString(key) || strings.TrimSpace(value) == "" {
			return protocol.CertificateBundle{}, fmt.Errorf("invalid DNS credential variable %q", key)
		}
		env[key] = value
	}
	if payload.EABKID != "" || payload.EABHMAC != "" {
		if payload.EABKID == "" || payload.EABHMAC == "" {
			return protocol.CertificateBundle{}, errors.New("both EAB KID and HMAC are required")
		}
		env["LEGO_EAB_KID"] = payload.EABKID
		env["LEGO_EAB_HMAC"] = payload.EABHMAC
	}
	accountHash := sha256.Sum256([]byte(strings.ToLower(payload.Email) + "\x00" + payload.DirectoryURL + "\x00" + payload.DNSProvider))
	legoPath := filepath.Join(dataRoot, "lego", hex.EncodeToString(accountHash[:8]))
	if err := os.MkdirAll(legoPath, 0o700); err != nil {
		return protocol.CertificateBundle{}, fmt.Errorf("create lego data directory: %w", err)
	}
	args := []string{"run", "--path", legoPath, "--email", payload.Email, "--server", payload.DirectoryURL,
		"--dns", payload.DNSProvider, "--accept-tos", "--renew-days", "30"}
	for _, domain := range domains {
		args = append(args, "--domains", domain)
	}
	if payload.EABKID != "" {
		args = append(args, "--eab")
	}
	if legoBinary == "" {
		legoBinary = "lego"
	}
	if runner == nil {
		runner = OSRunner{}
	}
	_, err = runner.Run(ctx, legoBinary, args, env)
	if err != nil {
		return protocol.CertificateBundle{}, fmt.Errorf("ACME DNS-01 issuance failed: %w", err)
	}
	certPath, keyPath, err := findCertificate(legoPath, domains, now)
	if err != nil {
		return protocol.CertificateBundle{}, err
	}
	fullchain, err := os.ReadFile(certPath)
	if err != nil {
		return protocol.CertificateBundle{}, fmt.Errorf("read issued certificate: %w", err)
	}
	privateKey, err := os.ReadFile(keyPath)
	if err != nil {
		return protocol.CertificateBundle{}, fmt.Errorf("read issued private key: %w", err)
	}
	info, err := certutil.Validate(fullchain, privateKey, domains[0], now)
	if err != nil {
		return protocol.CertificateBundle{}, fmt.Errorf("validate issued certificate: %w", err)
	}
	if err := ensureNames(info.DNSNames, domains); err != nil {
		return protocol.CertificateBundle{}, err
	}
	return protocol.CertificateBundle{FullchainPEM: string(fullchain), PrivateKeyPEM: string(privateKey)}, nil
}

func normalizeNames(primary string, requested []string) []string {
	result := make([]string, 0, len(requested)+1)
	seen := make(map[string]bool)
	for _, value := range append([]string{primary}, requested...) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func validateName(value string) error {
	base := value
	if strings.HasPrefix(value, "*.") {
		base = strings.TrimPrefix(value, "*.")
	} else if strings.Contains(value, "*") {
		return fmt.Errorf("invalid wildcard certificate name %q", value)
	}
	if _, err := nginxconfig.ConfigFileName(base); err != nil {
		return fmt.Errorf("invalid certificate name %q", value)
	}
	return nil
}

func ensureNames(actual, requested []string) error {
	actualSet := make(map[string]bool, len(actual))
	for _, value := range actual {
		actualSet[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range requested {
		if strings.HasPrefix(value, "*.") {
			if !actualSet[value] {
				return fmt.Errorf("certificate does not contain %s", value)
			}
		} else if !certutil.CoversHostname(actual, value) {
			return fmt.Errorf("certificate does not cover %s", value)
		}
	}
	return nil
}

func findCertificate(root string, domains []string, now time.Time) (string, string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") && !strings.HasSuffix(entry.Name(), ".issuer.crt") {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return "", "", fmt.Errorf("scan lego certificates: %w", err)
	}
	for _, certPath := range matches {
		keyPath := strings.TrimSuffix(certPath, ".crt") + ".key"
		fullchain, certErr := os.ReadFile(certPath)
		privateKey, keyErr := os.ReadFile(keyPath)
		if certErr == nil && keyErr == nil {
			if info, err := certutil.Validate(fullchain, privateKey, domains[0], now); err == nil && ensureNames(info.DNSNames, domains) == nil {
				return certPath, keyPath, nil
			}
		}
	}
	return "", "", fmt.Errorf("lego did not produce a valid certificate for %s", domains[0])
}
