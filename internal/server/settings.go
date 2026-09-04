package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
)

const (
	minNodePollSeconds       = 10
	maxNodePollSeconds       = 300
	maxStatusSamples         = 16
	maxPanelCIDRs            = 64
	minSecurityEntranceBytes = 8
	maxSecurityEntranceBytes = 64
	defaultEntranceStatus    = http.StatusNotFound
	securityEntranceCookie   = "nginx_atlas_entrance"
	turnstileAction          = "turnstile-spin-v1"
)

var (
	errTurnstileRejected        = errors.New("turnstile rejected")
	errTurnstileUnavailable     = errors.New("turnstile unavailable")
	errTurnstileIncomplete      = errors.New("turnstile credentials required")
	errSecurityEntranceRequired = errors.New("security entrance required")
)

type settingsView struct {
	NodePollSeconds           int      `json:"node_poll_seconds"`
	TurnstileEnabled          bool     `json:"turnstile_enabled"`
	TurnstileSiteKey          string   `json:"turnstile_site_key"`
	TurnstileSecretConfigured bool     `json:"turnstile_secret_configured"`
	PanelAllowedCIDRs         []string `json:"panel_allowed_cidrs"`
	SecurityEntranceEnabled   bool     `json:"security_entrance_enabled"`
	SecurityEntranceStatus    int      `json:"security_entrance_status"`
	RequestIP                 string   `json:"request_ip,omitempty"`
}

type settingsUpdateRequest struct {
	NodePollSeconds           *int      `json:"node_poll_seconds"`
	TurnstileEnabled          *bool     `json:"turnstile_enabled"`
	TurnstileSiteKey          *string   `json:"turnstile_site_key"`
	TurnstileSecret           *string   `json:"turnstile_secret"`
	TurnstileSecretConfigured bool      `json:"turnstile_secret_configured"`
	PanelAllowedCIDRs         *[]string `json:"panel_allowed_cidrs"`
	SecurityEntranceEnabled   *bool     `json:"security_entrance_enabled"`
	SecurityEntrance          *string   `json:"security_entrance"`
	SecurityEntranceStatus    *int      `json:"security_entrance_status"`
	RequestIP                 string    `json:"request_ip"`
}

func (s *Server) effectiveSettings(state model.State) settingsView {
	return s.effectiveControllerSettings(state.Settings)
}

func (s *Server) effectiveControllerSettings(settings model.ControllerSettings) settingsView {
	seconds := settings.NodePollSeconds
	if seconds < minNodePollSeconds || seconds > maxNodePollSeconds {
		seconds = int(s.config.PollAfter.Seconds())
	}
	if seconds < minNodePollSeconds {
		seconds = minNodePollSeconds
	}
	return settingsView{
		NodePollSeconds:           seconds,
		TurnstileEnabled:          settings.TurnstileEnabled,
		TurnstileSiteKey:          settings.TurnstileSiteKey,
		TurnstileSecretConfigured: settings.TurnstileSecretCiphertext != "",
		PanelAllowedCIDRs:         append([]string{}, settings.PanelAllowedCIDRs...),
		SecurityEntranceEnabled:   validSecurityEntranceHash(settings.SecurityEntranceHash),
		SecurityEntranceStatus:    effectiveSecurityEntranceStatus(settings.SecurityEntranceStatus),
	}
}

func (s *Server) nodePollAfter(state model.State) time.Duration {
	return time.Duration(s.effectiveSettings(state).NodePollSeconds) * time.Second
}

func (s *Server) nodeOfflineAfter(state model.State) time.Duration {
	minimum := 3*s.nodePollAfter(state) + 15*time.Second
	if s.config.OfflineAfter > minimum {
		return s.config.OfflineAfter
	}
	return minimum
}

func (s *Server) handleLoginConfig(w http.ResponseWriter, _ *http.Request) {
	settings := s.store.Settings()
	enabled := settings.TurnstileEnabled && settings.TurnstileSiteKey != "" && settings.TurnstileSecretCiphertext != ""
	siteKey := ""
	if enabled {
		siteKey = settings.TurnstileSiteKey
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"turnstile_enabled":  enabled,
		"turnstile_site_key": siteKey,
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	view := s.effectiveSettings(s.store.Snapshot())
	view.RequestIP = s.clientIP(r)
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var request settingsUpdateRequest
	if !decodeJSON(w, r, &request) {
		return
	}

	if request.NodePollSeconds != nil {
		if *request.NodePollSeconds < minNodePollSeconds || *request.NodePollSeconds > maxNodePollSeconds {
			writeError(w, http.StatusBadRequest, "节点状态频率需为 10–300 秒", "invalid_node_poll_seconds", nil)
			return
		}
	}
	if request.TurnstileSiteKey != nil {
		value := strings.TrimSpace(*request.TurnstileSiteKey)
		if len(value) > 256 {
			writeError(w, http.StatusBadRequest, "Turnstile Site Key 无效", "invalid_turnstile_site_key", nil)
			return
		}
		request.TurnstileSiteKey = &value
	}
	var secretCiphertext string
	if request.TurnstileSecret != nil {
		secret := strings.TrimSpace(*request.TurnstileSecret)
		if len(secret) > 1024 {
			writeError(w, http.StatusBadRequest, "Turnstile Secret Key 无效", "invalid_turnstile_secret", nil)
			return
		}
		if secret != "" {
			ciphertext, err := s.mustSeal("controller-settings:turnstile-secret", []byte(secret))
			if err != nil {
				wrapStoreError(w, err)
				return
			}
			secretCiphertext = ciphertext
		}
	}
	var allowedCIDRs []string
	if request.PanelAllowedCIDRs != nil {
		allowed, err := normalizePanelCIDRs(*request.PanelAllowedCIDRs)
		if err != nil {
			writeError(w, http.StatusBadRequest, "IP 白名单格式无效", "invalid_panel_allowlist", map[string]string{"reason": err.Error()})
			return
		}
		requestIP := s.clientIP(r)
		if len(allowed) > 0 && !ipAllowed(requestIP, allowed) {
			writeError(w, http.StatusBadRequest, "白名单必须包含当前访问 IP", "panel_allowlist_lockout", map[string]string{"request_ip": requestIP})
			return
		}
		allowedCIDRs = allowed
	}
	var entranceHash string
	entranceProvided := request.SecurityEntrance != nil
	if entranceProvided {
		entrance, err := normalizeSecurityEntrance(*request.SecurityEntrance)
		if err != nil {
			writeError(w, http.StatusBadRequest, "安全入口需为 8-64 位字母、数字、连字符或下划线", "invalid_security_entrance", nil)
			return
		}
		entranceHash = s.hashSecurityEntrance(entrance)
		if request.SecurityEntranceEnabled != nil && !*request.SecurityEntranceEnabled {
			writeError(w, http.StatusBadRequest, "关闭安全入口时不能同时设置新路径", "invalid_security_entrance", nil)
			return
		}
	}
	if request.SecurityEntranceStatus != nil && *request.SecurityEntranceStatus != 0 && !allowedSecurityEntranceStatus(*request.SecurityEntranceStatus) {
		writeError(w, http.StatusBadRequest, "未认证响应状态无效", "invalid_security_entrance_status", nil)
		return
	}

	if err := s.store.Update(func(state *model.State) error {
		if request.NodePollSeconds != nil {
			state.Settings.NodePollSeconds = *request.NodePollSeconds
		}
		if request.TurnstileEnabled != nil {
			state.Settings.TurnstileEnabled = *request.TurnstileEnabled
		}
		if request.TurnstileSiteKey != nil {
			state.Settings.TurnstileSiteKey = *request.TurnstileSiteKey
		}
		if secretCiphertext != "" {
			state.Settings.TurnstileSecretCiphertext = secretCiphertext
		}
		if request.PanelAllowedCIDRs != nil {
			state.Settings.PanelAllowedCIDRs = append([]string{}, allowedCIDRs...)
		}
		if request.SecurityEntranceEnabled != nil {
			if !*request.SecurityEntranceEnabled {
				state.Settings.SecurityEntranceHash = ""
			} else if entranceProvided {
				state.Settings.SecurityEntranceHash = entranceHash
			} else if !validSecurityEntranceHash(state.Settings.SecurityEntranceHash) {
				return errSecurityEntranceRequired
			}
		} else if entranceProvided {
			state.Settings.SecurityEntranceHash = entranceHash
		}
		if request.SecurityEntranceStatus != nil && *request.SecurityEntranceStatus != 0 {
			state.Settings.SecurityEntranceStatus = *request.SecurityEntranceStatus
		}
		if state.Settings.TurnstileEnabled && (state.Settings.TurnstileSiteKey == "" || state.Settings.TurnstileSecretCiphertext == "") {
			return errTurnstileIncomplete
		}
		s.addAudit(state, "info", "settings.updated", "访问与节点状态设置已更新")
		return nil
	}); err != nil {
		if errors.Is(err, errTurnstileIncomplete) {
			writeError(w, http.StatusBadRequest, "启用 Turnstile 前请填写 Site Key 与 Secret Key", "turnstile_credentials_required", nil)
			return
		}
		if errors.Is(err, errSecurityEntranceRequired) {
			writeError(w, http.StatusBadRequest, "启用安全入口前请设置访问路径", "security_entrance_required", nil)
			return
		}
		wrapStoreError(w, err)
		return
	}
	state := s.store.Snapshot()
	if request.SecurityEntranceEnabled != nil || entranceProvided {
		if validSecurityEntranceHash(state.Settings.SecurityEntranceHash) {
			s.setSecurityEntranceCookie(w, r, state.Settings.SecurityEntranceHash)
		} else {
			s.clearSecurityEntranceCookie(w, r)
		}
	}
	view := s.effectiveSettings(state)
	view.RequestIP = s.clientIP(r)
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) securityEntrance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if securityEntranceExempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		settings := s.store.Settings()
		if settings.SecurityEntranceHash == "" {
			next.ServeHTTP(w, r)
			return
		}
		status := effectiveSecurityEntranceStatus(settings.SecurityEntranceStatus)
		if !validSecurityEntranceHash(settings.SecurityEntranceHash) {
			writeSecurityEntranceError(w, r, status)
			return
		}
		if s.securityEntranceCookieValid(r, settings.SecurityEntranceHash) {
			next.ServeHTTP(w, r)
			return
		}
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && s.securityEntrancePathMatches(r.URL.Path, settings.SecurityEntranceHash) {
			s.setSecurityEntranceCookie(w, r, settings.SecurityEntranceHash)
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		writeSecurityEntranceError(w, r, status)
	})
}

func securityEntranceExempt(r *http.Request) bool {
	if panelAccessExempt(r.URL.Path) {
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	return r.URL.Path != "/api/v1/login-config" && !(r.URL.Path == "/api/v1/session" && r.Method == http.MethodPost)
}

func normalizeSecurityEntrance(value string) (string, error) {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if len(value) < minSecurityEntranceBytes || len(value) > maxSecurityEntranceBytes {
		return "", errors.New("invalid length")
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return "", errors.New("invalid character")
	}
	switch strings.ToLower(value) {
	case "api", "assets", "favicon.ico", "healthz", "install.sh", "login":
		return "", errors.New("reserved path")
	}
	return value, nil
}

func (s *Server) securityEntranceDigest(value string) []byte {
	return s.box.KeyedDigest("controller-settings:security-entrance-path:v1", []byte(value))
}

func (s *Server) hashSecurityEntrance(value string) string {
	return hex.EncodeToString(s.securityEntranceDigest(value))
}

func validSecurityEntranceHash(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size
}

func (s *Server) securityEntrancePathMatches(requestPath, encodedHash string) bool {
	if !strings.HasPrefix(requestPath, "/") || strings.Count(requestPath, "/") != 1 {
		return false
	}
	candidate := strings.TrimPrefix(requestPath, "/")
	expected, err := hex.DecodeString(encodedHash)
	return err == nil && len(expected) == sha256.Size && hmac.Equal(s.securityEntranceDigest(candidate), expected)
}

func allowedSecurityEntranceStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusRequestTimeout, http.StatusRequestedRangeNotSatisfiable, 444, http.StatusInternalServerError:
		return true
	default:
		return false
	}
}

func effectiveSecurityEntranceStatus(status int) int {
	if allowedSecurityEntranceStatus(status) {
		return status
	}
	return defaultEntranceStatus
}

func (s *Server) securityEntranceCookieValue(entranceHash string) string {
	mac := hmac.New(sha256.New, s.adminTokenHash[:])
	_, _ = mac.Write([]byte("nginx-atlas:security-entrance:"))
	_, _ = mac.Write([]byte(entranceHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) securityEntranceCookieValid(r *http.Request, entranceHash string) bool {
	cookie, err := r.Cookie(securityEntranceCookie)
	if err != nil {
		return false
	}
	expected := s.securityEntranceCookieValue(entranceHash)
	return len(cookie.Value) == len(expected) && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(expected)) == 1
}

func (s *Server) setSecurityEntranceCookie(w http.ResponseWriter, r *http.Request, entranceHash string) {
	http.SetCookie(w, &http.Cookie{
		Name: securityEntranceCookie, Value: s.securityEntranceCookieValue(entranceHash), Path: "/",
		HttpOnly: true, Secure: s.secureRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSecurityEntranceCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: securityEntranceCookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
		HttpOnly: true, Secure: s.secureRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) secureRequest(r *http.Request) bool {
	return r.TLS != nil || (s.trustedProxyRequest(r) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https"))
}

func writeSecurityEntranceError(w http.ResponseWriter, r *http.Request, status int) {
	status = effectiveSecurityEntranceStatus(status)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if status == 444 {
		w.WriteHeader(status)
		return
	}
	title := http.StatusText(status)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>%d %s</title><style>html{color-scheme:light}body{margin:0;padding:40px 20px;font:16px Arial,sans-serif;text-align:center;color:#111}h1{margin:0 0 34px;font-size:clamp(32px,5vw,60px)}hr{border:0;border-top:1px solid #aaa}p{font-size:28px}</style></head><body><h1>%s</h1><hr><p>nginx</p></body></html>", status, title, title)
}

func (s *Server) panelAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if panelAccessExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if s.proxyCredentialRequired(r) {
			w.Header().Set("Cache-Control", "no-store")
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeError(w, http.StatusForbidden, "反向代理未通过主控认证", "proxy_auth_required", nil)
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		allowed := s.store.Settings().PanelAllowedCIDRs
		if len(allowed) == 0 || ipAllowed(s.clientIP(r), allowed) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusForbidden, "当前 IP 不在访问白名单中", "panel_ip_forbidden", nil)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

func panelAccessExempt(path string) bool {
	return path == "/healthz" || path == "/install.sh" || strings.HasPrefix(path, "/api/v1/agent/") || strings.HasPrefix(path, "/api/v1/local/")
}

func (s *Server) clientIP(r *http.Request) string {
	peer, ok := requestPeer(r)
	if !ok {
		return ""
	}
	if peer.IsLoopback() && s.trustedProxyRequest(r) {
		if realIP, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
			return realIP.Unmap().String()
		}
	}
	return peer.String()
}

func requestPeer(r *http.Request) (netip.Addr, bool) {
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	peer, err := netip.ParseAddr(strings.Trim(remote, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return peer.Unmap(), true
}

func (s *Server) trustedProxyRequest(r *http.Request) bool {
	proxyToken := strings.TrimSpace(r.Header.Get("X-Atlas-Proxy"))
	return len(s.proxyToken) >= 24 && len(proxyToken) == len(s.proxyToken) && subtle.ConstantTimeCompare([]byte(proxyToken), []byte(s.proxyToken)) == 1
}

func (s *Server) proxyCredentialRequired(r *http.Request) bool {
	peer, ok := requestPeer(r)
	return ok && peer.IsLoopback() && len(s.proxyToken) >= 24 && !s.trustedProxyRequest(r)
}

func normalizePanelCIDRs(values []string) ([]string, error) {
	if len(values) > maxPanelCIDRs {
		return nil, fmt.Errorf("最多允许 %d 条规则", maxPanelCIDRs)
	}
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		var prefix netip.Prefix
		if parsed, err := netip.ParsePrefix(value); err == nil {
			prefix = parsed
		} else if address, err := netip.ParseAddr(value); err == nil {
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		} else {
			return nil, fmt.Errorf("%q 不是有效 IP 或 CIDR", value)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("%q 不是有效 IPv4 映射 CIDR", value)
			}
			address := prefix.Addr().Unmap()
			prefix = netip.PrefixFrom(address, prefix.Bits()-96)
		}
		canonical := prefix.Masked().String()
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
	}
	return result, nil
}

func ipAllowed(value string, prefixes []string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) verifyTurnstile(ctx context.Context, settings model.ControllerSettings, token, remoteIP string) error {
	if !settings.TurnstileEnabled {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 4096 {
		return errTurnstileRejected
	}
	if settings.TurnstileSiteKey == "" || settings.TurnstileSecretCiphertext == "" {
		return fmt.Errorf("%w: incomplete settings", errTurnstileUnavailable)
	}
	secret, err := s.box.Open("controller-settings:turnstile-secret", settings.TurnstileSecretCiphertext)
	if err != nil {
		return fmt.Errorf("%w: decrypt secret", errTurnstileUnavailable)
	}
	form := url.Values{"secret": {string(secret)}, "response": {token}}
	if _, err := netip.ParseAddr(remoteIP); err == nil {
		form.Set("remoteip", remoteIP)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.TurnstileVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: create request", errTurnstileUnavailable)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("%w: request failed", errTurnstileUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", errTurnstileUnavailable, response.StatusCode)
	}
	var result struct {
		Success    bool     `json:"success"`
		Hostname   string   `json:"hostname"`
		Action     string   `json:"action"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result); err != nil {
		return fmt.Errorf("%w: invalid response", errTurnstileUnavailable)
	}
	if !result.Success || result.Action != turnstileAction {
		s.logger.Warn("turnstile rejected login", "codes", result.ErrorCodes)
		return errTurnstileRejected
	}
	if publicURL, err := url.Parse(s.config.PublicURL); err == nil && publicURL.Hostname() != "" && !strings.EqualFold(result.Hostname, publicURL.Hostname()) {
		s.logger.Warn("turnstile rejected login", "reason", "hostname mismatch")
		return errTurnstileRejected
	}
	return nil
}

func (s *Server) handleManagementCommands(w http.ResponseWriter, r *http.Request) {
	installerURL := strings.TrimRight(s.publicURL(r), "/") + "/install.sh"
	writeJSON(w, http.StatusOK, map[string]string{
		"uninstall_node":       fmt.Sprintf("curl -fsSL %s | sudo bash -s -- uninstall-agent", shellQuote(installerURL)),
		"uninstall_controller": fmt.Sprintf("curl -fsSL %s | sudo bash -s -- uninstall-server", shellQuote(installerURL)),
	})
}

func appendNodeStatusSample(node *model.Node, status model.NodeStatus, observedAt time.Time) {
	node.StatusHistory = append(node.StatusHistory, model.NodeStatusSample{Status: status, ObservedAt: observedAt})
	if len(node.StatusHistory) > maxStatusSamples {
		node.StatusHistory = append([]model.NodeStatusSample(nil), node.StatusHistory[len(node.StatusHistory)-maxStatusSamples:]...)
	}
}
