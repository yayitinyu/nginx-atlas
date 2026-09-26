package issuer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

type captureRunner struct {
	args   []string
	env    map[string]string
	called bool
}

func (r *captureRunner) Run(_ context.Context, _ string, args []string, env map[string]string) ([]byte, error) {
	r.called = true
	r.args = append([]string(nil), args...)
	r.env = env
	return []byte("provider log containing secret"), errors.New("exit status 1")
}

func TestIssueRunsOnlyOnControllerWithCredentialsOutsideArguments(t *testing.T) {
	runner := &captureRunner{}
	_, err := Issue(context.Background(), protocol.IssueCertificatePayload{
		Domain: "*.example.com", Domains: []string{"*.example.com", "example.com"},
		Email: "admin@example.com", DirectoryURL: "https://acme.example.com/directory",
		DNSProvider: "cloudflare", Credentials: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "private-token"},
		EABKID: "kid", EABHMAC: "private-hmac",
	}, t.TempDir(), "lego", runner, time.Now())
	if !runner.called || err == nil {
		t.Fatalf("lego was not invoked: %v", err)
	}
	arguments := strings.Join(runner.args, " ")
	if !strings.Contains(arguments, "--domains *.example.com") || !strings.Contains(arguments, "--domains example.com") {
		t.Fatalf("requested names missing from lego arguments: %q", arguments)
	}
	if strings.Contains(arguments, "private-token") || strings.Contains(arguments, "private-hmac") || strings.Contains(err.Error(), "private") {
		t.Fatal("secret or provider output leaked into command arguments or error")
	}
	if runner.env["CLOUDFLARE_DNS_API_TOKEN"] != "private-token" || runner.env["LEGO_EAB_HMAC"] != "private-hmac" {
		t.Fatal("DNS or EAB credentials were not passed through the process environment")
	}
}

func TestIssueRejectsUnsafeProviderBeforeProcessLaunch(t *testing.T) {
	runner := &captureRunner{}
	_, err := Issue(context.Background(), protocol.IssueCertificatePayload{
		Domain: "*.example.com", Email: "admin@example.com",
		DirectoryURL: "https://acme.example.com/directory", DNSProvider: "exec",
	}, t.TempDir(), "lego", runner, time.Now())
	if err == nil || runner.called {
		t.Fatalf("unsafe provider reached lego: %v", err)
	}
}
