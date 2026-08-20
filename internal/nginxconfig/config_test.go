package nginxconfig

import (
	"strings"
	"testing"
)

func TestRenderTLSSite(t *testing.T) {
	config, err := Render(Site{
		Domain: "api.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 8080,
		TLS: true, CertificateDir: "/etc/ssl/api.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(config)
	for _, wanted := range []string{
		"server_name api.example.com;",
		"proxy_pass http://127.0.0.1:8080;",
		"ssl_certificate /etc/ssl/api.example.com/fullchain.pem;",
		"return 308 https://api.example.com$request_uri;",
	} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("config missing %q:\n%s", wanted, text)
		}
	}
}

func TestRenderTrustedLocalProxyHeaderInclude(t *testing.T) {
	config, err := Render(Site{
		Domain: "atlas.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 909,
		ProxyHeaderInclude: "/etc/nginx-atlas/proxy-token.conf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "include /etc/nginx-atlas/proxy-token.conf;") {
		t.Fatalf("trusted proxy include missing:\n%s", config)
	}
	if _, err := Render(Site{Domain: "atlas.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 909, ProxyHeaderInclude: "/tmp/injected.conf"}); err == nil {
		t.Fatal("untrusted proxy include was accepted")
	}
}

func TestRenderRejectsDirectiveInjection(t *testing.T) {
	_, err := Render(Site{Domain: "example.com; include /tmp/evil", UpstreamHost: "127.0.0.1", UpstreamPort: 8080})
	if err == nil {
		t.Fatal("expected injected domain to fail")
	}
	_, err = Render(Site{Domain: "api.example.com", UpstreamHost: "127.0.0.1; return 200", UpstreamPort: 8080})
	if err == nil {
		t.Fatal("expected injected upstream host to fail")
	}
}

func TestUpstreamURLBracketsIPv6(t *testing.T) {
	if got := UpstreamURL("2001:db8::1", 8443); got != "http://[2001:db8::1]:8443" {
		t.Fatalf("unexpected IPv6 upstream URL: %s", got)
	}
}
