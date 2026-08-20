package nginxconfig

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

var (
	domainPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

type Site struct {
	Domain             string
	UpstreamHost       string
	UpstreamPort       int
	TLS                bool
	CertificateDir     string
	NginxWebsocket     bool
	NginxHTTP2         bool
	NginxGzip          bool
	ProxyHeaderInclude string
}

func ValidateSite(site Site) error {
	if !domainPattern.MatchString(site.Domain) || len(site.Domain) > 253 {
		return errors.New("domain must be a lowercase ASCII hostname with at least one dot")
	}
	if site.UpstreamPort < 1 || site.UpstreamPort > 65535 {
		return errors.New("upstream port must be between 1 and 65535")
	}
	host := strings.ToLower(strings.TrimSpace(site.UpstreamHost))
	if net.ParseIP(host) == nil && (!hostnamePattern.MatchString(host) || len(host) > 253) {
		return errors.New("upstream host must be an IP address or a valid ASCII hostname")
	}
	if site.TLS && strings.TrimSpace(site.CertificateDir) == "" {
		return errors.New("certificate directory is required when TLS is enabled")
	}
	if site.ProxyHeaderInclude != "" && site.ProxyHeaderInclude != "/etc/nginx-atlas/proxy-token.conf" {
		return errors.New("proxy header include path is not trusted")
	}
	return nil
}

func Render(site Site) ([]byte, error) {
	site.Domain = strings.ToLower(strings.TrimSpace(site.Domain))
	site.UpstreamHost = strings.ToLower(strings.TrimSpace(site.UpstreamHost))
	if err := ValidateSite(site); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := siteTemplate.Execute(&output, site); err != nil {
		return nil, fmt.Errorf("render nginx configuration: %w", err)
	}
	return output.Bytes(), nil
}

func ConfigFileName(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return "", errors.New("invalid domain")
	}
	return "atlas-" + domain + ".conf", nil
}

func UpstreamURL(host string, port int) string {
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + strconv.Itoa(port)
}

var siteTemplate = template.Must(template.New("site").Funcs(template.FuncMap{
	"upstream": func(site Site) string { return UpstreamURL(site.UpstreamHost, site.UpstreamPort) },
}).Parse(`# Managed by Nginx Atlas. Manual changes will be replaced.
{{- if .TLS }}
server {
    listen 80;
    listen [::]:80;
    server_name {{ .Domain }};
    return 308 https://{{ .Domain }}$request_uri;
}

server {
    {{- if .NginxHTTP2 }}
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    {{- else }}
    listen 443 ssl;
    listen [::]:443 ssl;
    {{- end }}
    server_name {{ .Domain }};

    ssl_certificate {{ .CertificateDir }}/fullchain.pem;
    ssl_certificate_key {{ .CertificateDir }}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:ATLAS:10m;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=15552000" always;
    client_max_body_size 64m;

    {{- if .NginxGzip }}
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;
    {{- end }}

    location / {
        proxy_pass {{ upstream . }};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        {{- if .ProxyHeaderInclude }}
        include {{ .ProxyHeaderInclude }};
        {{- end }}
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        {{- if .NginxWebsocket }}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 10s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
        {{- end }}
    }
}
{{- else }}
server {
    listen 80;
    listen [::]:80;
    server_name {{ .Domain }};
    client_max_body_size 64m;

    {{- if .NginxGzip }}
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;
    {{- end }}

    location / {
        proxy_pass {{ upstream . }};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        {{- if .ProxyHeaderInclude }}
        include {{ .ProxyHeaderInclude }};
        {{- end }}
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        {{- if .NginxWebsocket }}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 10s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
        {{- end }}
    }
}
{{- end }}
`))
