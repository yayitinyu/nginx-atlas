package agent

import "testing"

func TestParseNginxSitesExtractsAndMergesSafeMetadata(t *testing.T) {
	output := []byte(`nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/conf.d/atlas-api.example.com.conf:
# Managed by Nginx Atlas. Manual changes will be replaced.
server {
    listen 80;
    server_name api.example.com;
    return 308 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name api.example.com;
    ssl_certificate /etc/ssl/api.example.com/fullchain.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Authorization $http_authorization;
    }
}
# configuration file /etc/nginx/sites-enabled/legacy.conf:
server {
    listen 443 ssl;
    server_name legacy.example.com _ localhost;
    ssl_certificate /etc/ssl/legacy.example.com/fullchain.pem;
    location / { proxy_pass https://10.0.0.9:9443; }
}
`)

	sites := ParseNginxSites(output)
	if len(sites) != 2 {
		t.Fatalf("expected 2 sites, got %#v", sites)
	}
	api := sites[0]
	if api.Domain != "api.example.com" || api.UpstreamHost != "127.0.0.1" || api.UpstreamPort != 8080 || !api.TLS || !api.ManagedByAtlas {
		t.Fatalf("unexpected Atlas site: %#v", api)
	}
	if api.CertificatePath != "/etc/ssl/api.example.com/fullchain.pem" {
		t.Fatalf("unexpected certificate path: %q", api.CertificatePath)
	}
	legacy := sites[1]
	if legacy.Domain != "legacy.example.com" || legacy.UpstreamHost != "10.0.0.9" || legacy.UpstreamPort != 9443 || legacy.ManagedByAtlas {
		t.Fatalf("unexpected legacy site: %#v", legacy)
	}
}

func TestParseNginxSitesDoesNotExposeRawConfiguration(t *testing.T) {
	sites := ParseNginxSites([]byte(`# configuration file /etc/nginx/conf.d/site.conf:
server {
  listen 80;
  server_name safe.example.com;
  set $private_token super-secret;
}
`))
	if len(sites) != 1 || sites[0].Domain != "safe.example.com" {
		t.Fatalf("unexpected sites: %#v", sites)
	}
}
