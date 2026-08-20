package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

type sequenceRunner struct{ nginxTests int }

func (runner *sequenceRunner) Run(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	if name == "nginx" && len(args) == 1 && args[0] == "-t" {
		runner.nginxTests++
		if runner.nginxTests == 1 {
			return []byte("nginx: configuration test failed"), errors.New("exit status 1")
		}
	}
	return []byte("ok"), nil
}

func TestApplyDomainRestoresConfigWhenNginxTestFails(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "nginx")
	sslRoot := filepath.Join(root, "ssl")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "atlas-api.example.com.conf")
	oldConfig := []byte("# previous working config\n")
	if err := os.WriteFile(configPath, oldConfig, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &sequenceRunner{}
	executor := NewExecutor(ExecutorConfig{
		NginxBinary: "nginx", Systemctl: "systemctl", NginxConfigDir: configDir,
		SSLRoot: sslRoot, DataRoot: filepath.Join(root, "data"),
	}, runner)
	payload, _ := json.Marshal(protocol.ApplyDomainPayload{Domain: "api.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 8080})
	result := executor.Execute(context.Background(), protocol.WireJob{ID: "job_test", Type: protocol.JobApplyDomain, Payload: payload})
	if result.Success {
		t.Fatal("expected nginx validation failure")
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(oldConfig) {
		t.Fatalf("config was not restored: %q", restored)
	}
	if runner.nginxTests < 2 {
		t.Fatal("expected the rolled-back configuration to be validated")
	}
}

func TestValidateTakeoverPathRejectsSiblingDirectoriesAndTraversal(t *testing.T) {
	valid := []string{
		"/etc/nginx/conf.d/legacy.conf",
		"/etc/nginx/sites-enabled/example.com",
		"/etc/nginx/conf.d/nested/../legacy.conf",
	}
	for _, value := range valid {
		if _, err := validateTakeoverPath(value); err != nil {
			t.Errorf("validateTakeoverPath(%q): %v", value, err)
		}
	}
	invalid := []string{
		"/etc/nginx/conf.d",
		"/etc/nginx/conf.d-old/legacy.conf",
		"/etc/nginx/sites-enabled-backup/example.com",
		"/etc/nginx/conf.d/../../passwd",
		"legacy.conf",
	}
	for _, value := range invalid {
		if _, err := validateTakeoverPath(value); err == nil {
			t.Errorf("validateTakeoverPath(%q) unexpectedly succeeded", value)
		}
	}
}

func TestSelfUpdateRejectsDowngradeAndForeignRepository(t *testing.T) {
	if err := requireVersionUpgrade("dev", "v0.1.15"); err == nil {
		t.Fatal("expected unversioned development build update to be rejected")
	}
	if err := requireVersionUpgrade("v0.2.0", "v0.1.14"); err == nil {
		t.Fatal("expected downgrade to be rejected")
	}
	if err := requireVersionUpgrade("v0.1.14", "v0.1.15"); err != nil {
		t.Fatalf("newer version was rejected: %v", err)
	}
	trusted, err := url.Parse("https://github.com/yayitinyu/nginx-atlas/releases/download/v0.1.15/nginx-atlas_0.1.15_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedReleaseReference(trusted, "yayitinyu/nginx-atlas", "0.1.15"); err != nil {
		t.Fatalf("trusted release URL was rejected: %v", err)
	}
	foreign, err := url.Parse("https://github.com/attacker/project/releases/download/v0.1.15/nginx-atlas_0.1.15_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedReleaseReference(foreign, "yayitinyu/nginx-atlas", "0.1.15"); err == nil {
		t.Fatal("foreign repository release URL was accepted")
	}
}

func TestRemoveServerBlocksForDomainKeepsSiblingVhosts(t *testing.T) {
	input := []byte(`
server {
    listen 80;
    server_name keep.example.com;
    location / { proxy_pass http://127.0.0.1:1; }
}
server {
    listen 443 ssl;
    server_name drop.example.com;
    ssl_certificate /etc/ssl/example.com/fullchain.pem;
    location / { proxy_pass http://127.0.0.1:2; }
}
server {
    listen 443 ssl;
    server_name also-keep.example.com;
    location / { proxy_pass http://127.0.0.1:3; }
}
`)
	modified, removed, err := removeServerBlocksForDomain(input, "drop.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed=%d want 1", removed)
	}
	text := string(modified)
	if strings.Contains(text, "drop.example.com") {
		t.Fatalf("domain still present: %s", text)
	}
	if !strings.Contains(text, "keep.example.com") || !strings.Contains(text, "also-keep.example.com") {
		t.Fatalf("sibling vhosts were damaged: %s", text)
	}
}

func TestApplyDomainUsesSharedWildcardCertificateDir(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "nginx")
	sslRoot := filepath.Join(root, "ssl")
	sharedDir := filepath.Join(sslRoot, "example.com")
	sitesEnabled := filepath.Join(root, "sites-enabled")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sitesEnabled, 0o755); err != nil {
		t.Fatal(err)
	}

	// Minimal self-signed material is overkill here: write PEM placeholders and
	// stub validation by using a real cert pair from certutil tests if available.
	// Instead, install via ensure path using the test helper below.
	fullchain, key := mustTestCertificatePEM(t, "example.com", "*.example.com")
	if err := os.WriteFile(filepath.Join(sharedDir, "fullchain.pem"), fullchain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sharedDir, "privkey.pem"), key, 0o600); err != nil {
		t.Fatal(err)
	}

	// Full apply with ReplaceConfigPath uses absolute Linux paths; exercise
	// materialize + apply without replace in this unit test.
	executor := NewExecutor(ExecutorConfig{
		NginxBinary: "nginx", Systemctl: "systemctl", NginxConfigDir: configDir,
		SSLRoot: sslRoot, DataRoot: filepath.Join(root, "data"),
	}, alwaysOKRunner{})
	payload, _ := json.Marshal(protocol.ApplyDomainPayload{
		Domain: "api.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 8080,
		TLS: true, UseLocalCertificate: true, LocalCertificateDir: sharedDir,
	})
	result := executor.Execute(context.Background(), protocol.WireJob{ID: "job_test", Type: protocol.JobApplyDomain, Payload: payload})
	if !result.Success {
		t.Fatalf("apply failed: %s", result.Error)
	}
	// Domain-local materialization should exist for Atlas-managed path.
	if _, err := os.Stat(filepath.Join(sslRoot, "api.example.com", "fullchain.pem")); err != nil {
		t.Fatalf("expected materialized fullchain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "atlas-api.example.com.conf")); err != nil {
		t.Fatalf("expected atlas config: %v", err)
	}
}

func TestCertificatePathsRejectTraversalAndSymlinkEscapes(t *testing.T) {
	root := t.TempDir()
	sslRoot := filepath.Join(root, "ssl")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(sslRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(ExecutorConfig{SSLRoot: sslRoot, DataRoot: filepath.Join(root, "data")}, alwaysOKRunner{})
	cert, key := mustTestCertificatePEM(t, "api.example.com")
	bundle := protocol.CertificateBundle{FullchainPEM: string(cert), PrivateKeyPEM: string(key)}
	if err := executor.installCertificate("../outside", bundle); err == nil {
		t.Fatal("certificate traversal was accepted")
	}
	linkedDomain := filepath.Join(sslRoot, "api.example.com")
	if err := os.Symlink(outside, linkedDomain); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if err := executor.installCertificate("api.example.com", bundle); err == nil {
		t.Fatal("symlinked certificate destination was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "privkey.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("external private key path was modified: %v", err)
	}
}

func TestDeleteDomainSucceedsWhenTakeoverNeverDisabledOriginal(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "nginx")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Simulate failed takeover: atlas conf may or may not exist; original still at path; no backup.
	executor := NewExecutor(ExecutorConfig{
		NginxBinary: "nginx", Systemctl: "systemctl", NginxConfigDir: configDir,
		SSLRoot: filepath.Join(root, "ssl"), DataRoot: filepath.Join(root, "data"),
	}, alwaysOKRunner{})
	// restore path must be under allowed prefixes. Create a fake absolute path on this OS
	// by using validateTakeoverPath-compatible string and not actually needing the file.
	// restoreTakeoverConfig with no backup and missing source is no-op success.
	payload, _ := json.Marshal(protocol.DeleteDomainPayload{
		Domain: "api.example.com", RestoreConfigPath: "/etc/nginx/sites-enabled/fandai.conf",
	})
	result := executor.Execute(context.Background(), protocol.WireJob{ID: "job_del", Type: protocol.JobDeleteDomain, Payload: payload})
	if !result.Success {
		t.Fatalf("delete failed: %s", result.Error)
	}
}

type alwaysOKRunner struct{}

func (alwaysOKRunner) Run(_ context.Context, _ string, _ []string, _ map[string]string) ([]byte, error) {
	return []byte("ok"), nil
}

func mustTestCertificatePEM(t *testing.T, names ...string) ([]byte, []byte) {
	t.Helper()
	if len(names) == 0 {
		t.Fatal("certificate names required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     append([]string(nil), names...),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
