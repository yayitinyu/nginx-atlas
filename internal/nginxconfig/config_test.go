package nginxconfig

import (
	"regexp"
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

func TestRenderUsesVersionCompatibleHTTP2Syntax(t *testing.T) {
	tests := []struct {
		name      string
		modern    bool
		wanted    []string
		forbidden []string
	}{
		{
			name:      "legacy",
			wanted:    []string{"listen 443 ssl http2;", "listen [::]:443 ssl http2;"},
			forbidden: []string{"http2 on;"},
		},
		{
			name:      "modern",
			modern:    true,
			wanted:    []string{"listen 443 ssl;", "listen [::]:443 ssl;", "http2 on;"},
			forbidden: []string{"listen 443 ssl http2;", "listen [::]:443 ssl http2;"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := Render(Site{
				Domain: "api.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 8080,
				TLS: true, CertificateDir: "/etc/ssl/api.example.com", NginxHTTP2: true, ModernHTTP2: test.modern,
			})
			if err != nil {
				t.Fatal(err)
			}
			text := string(config)
			for _, wanted := range test.wanted {
				if !strings.Contains(text, wanted) {
					t.Errorf("config missing %q:\n%s", wanted, text)
				}
			}
			for _, forbidden := range test.forbidden {
				if strings.Contains(text, forbidden) {
					t.Errorf("config contains %q:\n%s", forbidden, text)
				}
			}
		})
	}
}

func TestRenderOnlyUpgradesWebsocketConnectionsWhenRequested(t *testing.T) {
	connectionMap := regexp.MustCompile(`map \$http_upgrade (\$atlas_connection_upgrade_[a-f0-9]{16}) \{`)
	render := func(domain string, websocket bool) string {
		t.Helper()
		config, err := Render(Site{
			Domain: domain, UpstreamHost: "127.0.0.1", UpstreamPort: 8080,
			NginxWebsocket: websocket,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(config)
	}

	first := render("api.example.com", true)
	match := connectionMap.FindStringSubmatch(first)
	if len(match) != 2 {
		t.Fatalf("websocket connection map missing:\n%s", first)
	}
	for _, wanted := range []string{
		"default upgrade;",
		"'' close;",
		"proxy_set_header Upgrade $http_upgrade;",
		"proxy_set_header Connection " + match[1] + ";",
	} {
		if !strings.Contains(first, wanted) {
			t.Errorf("config missing %q:\n%s", wanted, first)
		}
	}
	if strings.Contains(first, `proxy_set_header Connection "upgrade";`) {
		t.Fatalf("ordinary requests are still forced to upgrade:\n%s", first)
	}

	second := render("web.example.com", true)
	secondMatch := connectionMap.FindStringSubmatch(second)
	if len(secondMatch) != 2 || secondMatch[1] == match[1] {
		t.Fatalf("site-specific map variables collided: first=%v second=%v", match, secondMatch)
	}

	withoutWebsocket := render("plain.example.com", false)
	if connectionMap.MatchString(withoutWebsocket) || strings.Contains(withoutWebsocket, "proxy_set_header Upgrade") || strings.Contains(withoutWebsocket, "proxy_set_header Connection") {
		t.Fatalf("websocket directives leaked into a normal proxy:\n%s", withoutWebsocket)
	}
}

func TestRenderS3CompatibleProxy(t *testing.T) {
	for _, tlsEnabled := range []bool{false, true} {
		config, err := Render(Site{
			Domain: "s3.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 9000,
			TLS: tlsEnabled, CertificateDir: "/etc/ssl/s3.example.com", NginxS3Compatible: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		text := string(config)
		for _, wanted := range []string{
			`client_max_body_size 0;`,
			`proxy_set_header Accept-Encoding "identity";`,
			`proxy_set_header Connection "";`,
			`proxy_request_buffering off;`,
		} {
			if count := strings.Count(text, wanted); count != 1 {
				t.Errorf("TLS=%t: %q count = %d, want 1:\n%s", tlsEnabled, wanted, count, text)
			}
		}
		for _, forbidden := range []string{
			`client_max_body_size 64m;`,
			`proxy_set_header Upgrade $http_upgrade;`,
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("TLS=%t: config contains %q:\n%s", tlsEnabled, forbidden, text)
			}
		}
	}
}

func TestValidateSiteRejectsS3CompatibilityWithWebsocket(t *testing.T) {
	err := ValidateSite(Site{
		Domain: "s3.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 9000,
		NginxWebsocket: true, NginxS3Compatible: true,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("expected incompatible proxy modes to be rejected, got %v", err)
	}
}

func TestRenderAllowsLargerUpstreamResponseHeaders(t *testing.T) {
	for _, tlsEnabled := range []bool{false, true} {
		config, err := Render(Site{
			Domain: "proxy.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 8080,
			TLS: tlsEnabled, CertificateDir: "/etc/ssl/proxy.example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		if count := strings.Count(string(config), "proxy_buffer_size 8k;"); count != 1 {
			t.Fatalf("TLS=%t: proxy_buffer_size count = %d, want 1:\n%s", tlsEnabled, count, config)
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

func TestValidateCustomConfigBoundsAndEncoding(t *testing.T) {
	for _, config := range []string{"", "server { listen 80; }\x00", string([]byte{0xff}), strings.Repeat("a", (256<<10)+1)} {
		if err := ValidateCustomConfig(config); err == nil {
			t.Fatalf("unsafe custom config was accepted (length %d)", len(config))
		}
	}
	if err := ValidateCustomConfig("server { listen 80; }\n"); err != nil {
		t.Fatalf("valid custom config rejected: %v", err)
	}
}
