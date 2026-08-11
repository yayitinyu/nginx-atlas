package agent

import (
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/nginxconfig"
)

var (
	configMarkerPattern = regexp.MustCompile(`^# configuration file (.+):$`)
	serverStartPattern  = regexp.MustCompile(`^\s*server\s*\{`)
	serverNamePattern   = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	proxyPassPattern    = regexp.MustCompile(`(?m)\bproxy_pass\s+(https?://[^\s;]+)`)
	certificatePattern  = regexp.MustCompile(`(?m)^\s*ssl_certificate\s+([^\s;]+)`)
	sslListenPattern    = regexp.MustCompile(`(?m)^\s*listen\s+[^;]*\bssl\b[^;]*;`)
)

// ParseNginxSites extracts only operational metadata from `nginx -T`. It does
// not retain complete server blocks, headers, secrets, or unrelated directives.
func ParseNginxSites(output []byte) []model.NginxSiteMeta {
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	currentPath := ""
	currentManaged := false
	depth := 0
	var block []string
	sites := make(map[string]model.NginxSiteMeta)

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if depth == 0 {
			if match := configMarkerPattern.FindStringSubmatch(trimmed); len(match) == 2 {
				currentPath = strings.TrimSpace(match[1])
				currentManaged = strings.HasPrefix(filepath.Base(currentPath), "atlas-")
				continue
			}
			if strings.Contains(trimmed, "Managed by Nginx Atlas") {
				currentManaged = true
				continue
			}
			cleaned := stripNginxComment(raw)
			if !serverStartPattern.MatchString(cleaned) {
				continue
			}
			block = []string{cleaned}
			depth = braceDelta(cleaned)
			if depth > 0 {
				continue
			}
		} else {
			cleaned := stripNginxComment(raw)
			block = append(block, cleaned)
			depth += braceDelta(cleaned)
			if depth > 0 {
				continue
			}
		}

		for _, site := range parseServerBlock(strings.Join(block, "\n"), currentPath, currentManaged) {
			key := site.Domain + "\x00" + site.ConfigPath
			sites[key] = mergeNginxSite(sites[key], site)
		}
		block = nil
		depth = 0
	}

	result := make([]model.NginxSiteMeta, 0, len(sites))
	for _, site := range sites {
		result = append(result, site)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Domain == result[j].Domain {
			return result[i].ConfigPath < result[j].ConfigPath
		}
		return result[i].Domain < result[j].Domain
	})
	return result
}

func parseServerBlock(block, configPath string, managed bool) []model.NginxSiteMeta {
	match := serverNamePattern.FindStringSubmatch(block)
	if len(match) != 2 {
		return nil
	}

	base := model.NginxSiteMeta{ConfigPath: configPath, TLS: sslListenPattern.MatchString(block), ManagedByAtlas: managed}
	if match := certificatePattern.FindStringSubmatch(block); len(match) == 2 {
		base.CertificatePath = strings.Trim(strings.TrimSpace(match[1]), `"'`)
		base.TLS = true
	}
	if match := proxyPassPattern.FindStringSubmatch(block); len(match) == 2 {
		if parsed, err := url.Parse(match[1]); err == nil {
			base.UpstreamHost = strings.ToLower(parsed.Hostname())
			if port, err := strconv.Atoi(parsed.Port()); err == nil {
				base.UpstreamPort = port
			}
		}
	}

	result := make([]model.NginxSiteMeta, 0)
	for _, name := range strings.Fields(match[1]) {
		name = strings.ToLower(strings.Trim(name, `"'`))
		if _, err := nginxconfig.ConfigFileName(name); err != nil {
			continue
		}
		site := base
		site.Domain = name
		result = append(result, site)
	}
	return result
}

func mergeNginxSite(existing, incoming model.NginxSiteMeta) model.NginxSiteMeta {
	if existing.Domain == "" {
		return incoming
	}
	if existing.UpstreamHost == "" && incoming.UpstreamHost != "" {
		existing.UpstreamHost = incoming.UpstreamHost
		existing.UpstreamPort = incoming.UpstreamPort
	}
	if existing.CertificatePath == "" {
		existing.CertificatePath = incoming.CertificatePath
	}
	existing.TLS = existing.TLS || incoming.TLS
	existing.ManagedByAtlas = existing.ManagedByAtlas || incoming.ManagedByAtlas
	return existing
}

func stripNginxComment(line string) string {
	if index := strings.IndexByte(line, '#'); index >= 0 {
		line = line[:index]
	}
	return strings.TrimSpace(line)
}

func braceDelta(line string) int {
	return strings.Count(line, "{") - strings.Count(line, "}")
}
