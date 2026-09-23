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

func TestNginxSupportsModernHTTP2Directive(t *testing.T) {
	tests := []struct {
		output string
		want   bool
	}{
		{output: "nginx version: nginx/1.24.0 (Ubuntu)", want: false},
		{output: "nginx version: nginx/1.25.0", want: false},
		{output: "nginx version: nginx/1.25.1", want: true},
		{output: "nginx version: nginx/1.28.3 (Ubuntu)", want: true},
		{output: "nginx version: nginx/2.0.0", want: true},
		{output: "openresty/1.27.1.1", want: false},
		{output: "unexpected", want: false},
	}
	for _, test := range tests {
		if got := nginxSupportsModernHTTP2Directive([]byte(test.output)); got != test.want {
			t.Errorf("nginxSupportsModernHTTP2Directive(%q)=%v want %v", test.output, got, test.want)
		}
	}
}

type nginxVersionRunner struct {
	version string
}

func (runner nginxVersionRunner) Run(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	if name == "nginx" && len(args) == 1 && args[0] == "-v" {
		return []byte(runner.version), nil
	}
	return []byte("ok"), nil
}

func TestApplyDomainSelectsHTTP2SyntaxFromInstalledNginx(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wanted    string
		forbidden string
	}{
		{name: "legacy", version: "nginx version: nginx/1.24.0", wanted: "listen 443 ssl http2;", forbidden: "http2 on;"},
		{name: "modern", version: "nginx version: nginx/1.28.3 (Ubuntu)", wanted: "http2 on;", forbidden: "listen 443 ssl http2;"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, "nginx")
			sslRoot := filepath.Join(root, "ssl")
			certificateDir := filepath.Join(sslRoot, "api.example.com")
			for _, directory := range []string{configDir, certificateDir} {
				if err := os.MkdirAll(directory, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			fullchain, key := mustTestCertificatePEM(t, "api.example.com")
			if err := os.WriteFile(filepath.Join(certificateDir, "fullchain.pem"), fullchain, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(certificateDir, "privkey.pem"), key, 0o600); err != nil {
				t.Fatal(err)
			}

			executor := NewExecutor(ExecutorConfig{
				NginxBinary: "nginx", Systemctl: "systemctl", NginxConfigDir: configDir,
				SSLRoot: sslRoot, DataRoot: filepath.Join(root, "data"),
			}, nginxVersionRunner{version: test.version})
			payload, err := json.Marshal(protocol.ApplyDomainPayload{
				Domain: "api.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 8080,
				TLS: true, UseLocalCertificate: true, NginxHTTP2: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			result := executor.Execute(context.Background(), protocol.WireJob{ID: "job_test", Type: protocol.JobApplyDomain, Payload: payload})
			if !result.Success {
				t.Fatalf("apply failed: %s", result.Error)
			}
			config, err := os.ReadFile(filepath.Join(configDir, "atlas-api.example.com.conf"))
			if err != nil {
				t.Fatal(err)
			}
			text := string(config)
			if !strings.Contains(text, test.wanted) || strings.Contains(text, test.forbidden) {
				t.Fatalf("unexpected config for %s:\n%s", test.version, text)
			}
		})
	}
}

func TestApplyDomainRendersS3CompatibleProxy(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "nginx")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(ExecutorConfig{
		NginxBinary: "nginx", Systemctl: "systemctl", NginxConfigDir: configDir,
		SSLRoot: filepath.Join(root, "ssl"), DataRoot: filepath.Join(root, "data"),
	}, alwaysOKRunner{})
	payload, err := json.Marshal(protocol.ApplyDomainPayload{
		Domain: "s3.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 9000,
		NginxS3Compatible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(context.Background(), protocol.WireJob{ID: "job_s3", Type: protocol.JobApplyDomain, Payload: payload})
	if !result.Success {
		t.Fatalf("apply failed: %s", result.Error)
	}
	config, err := os.ReadFile(filepath.Join(configDir, "atlas-s3.example.com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		`client_max_body_size 0;`,
		`proxy_set_header Accept-Encoding "identity";`,
		`proxy_set_header Connection "";`,
		`proxy_request_buffering off;`,
	} {
		if !strings.Contains(string(config), wanted) {
			t.Errorf("generated config missing %q:\n%s", wanted, config)
		}
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

func TestSyncWildcardCertificateWritesApexDirectory(t *testing.T) {
	root := t.TempDir()
	sslRoot := filepath.Join(root, "ssl")
	executor := NewExecutor(ExecutorConfig{
		NginxBinary: "nginx", Systemctl: "systemctl", NginxConfigDir: filepath.Join(root, "nginx"),
		SSLRoot: sslRoot, DataRoot: filepath.Join(root, "data"),
	}, alwaysOKRunner{})
	cert, key := mustTestCertificatePEM(t, "*.example.com", "example.com")
	payload, err := json.Marshal(protocol.SyncCertificatePayload{
		Domain: "*.example.com", ReloadNginx: true,
		Certificate: protocol.CertificateBundle{FullchainPEM: string(cert), PrivateKeyPEM: string(key)},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(context.Background(), protocol.WireJob{ID: "job_sync", Type: protocol.JobSyncCertificate, Payload: payload})
	if !result.Success {
		t.Fatalf("wildcard sync failed: %s", result.Error)
	}
	if _, err := os.Stat(filepath.Join(sslRoot, "example.com", "fullchain.pem")); err != nil {
		t.Fatalf("expected apex certificate directory: %v", err)
	}
	entries, err := os.ReadDir(sslRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "*") {
			t.Fatalf("wildcard directory should not be created: %s", entry.Name())
		}
	}

	onlyCert, onlyKey := mustTestCertificatePEM(t, "*.only.example.com")
	onlyPayload, err := json.Marshal(protocol.SyncCertificatePayload{
		Domain:      "*.only.example.com",
		Certificate: protocol.CertificateBundle{FullchainPEM: string(onlyCert), PrivateKeyPEM: string(onlyKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	onlyResult := executor.Execute(context.Background(), protocol.WireJob{ID: "job_only", Type: protocol.JobSyncCertificate, Payload: onlyPayload})
	if !onlyResult.Success {
		t.Fatalf("wildcard-only sync failed: %s", onlyResult.Error)
	}
	found := false
	for _, meta := range executor.InventoryCertificates() {
		if meta.Domain == "*.only.example.com" && meta.Error == "" && meta.KeyMatches {
			found = true
		}
	}
	if !found {
		t.Fatalf("wildcard-only certificate was not inventoried: %+v", executor.InventoryCertificates())
	}
}

func TestIssueCertificateAcceptsWildcardPrimaryName(t *testing.T) {
	executor := NewExecutor(ExecutorConfig{SSLRoot: t.TempDir(), DataRoot: t.TempDir()}, alwaysOKRunner{})
	_, err := executor.issueCertificate(context.Background(), protocol.IssueCertificatePayload{
		Domain: "*.example.com", Email: "admin@example.com",
		DirectoryURL: "https://acme.example.com/directory", DNSProvider: "manual",
	})
	if err == nil || strings.Contains(err.Error(), "invalid certificate domain") {
		t.Fatalf("wildcard primary was rejected before issuance: %v", err)
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
