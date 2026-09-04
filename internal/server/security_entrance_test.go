package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestSecurityEntranceGuardsLoginAndRedirectsAcceptedBrowsers(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stateStore, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("e", 32)
	controller, err := New(Config{AdminToken: adminToken, ProxyToken: testProxyToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}

	entrance := "hyRt58za3p"
	updated := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings", map[string]any{
		"security_entrance_enabled": true,
		"security_entrance":         entrance,
		"security_entrance_status":  http.StatusInternalServerError,
	}, "Bearer "+adminToken)
	if updated.Code != http.StatusOK {
		t.Fatalf("enable security entrance returned %d: %s", updated.Code, updated.Body.String())
	}
	if strings.Contains(updated.Body.String(), entrance) {
		t.Fatal("settings response exposed the security entrance")
	}
	stored := stateStore.Snapshot().Settings
	if stored.SecurityEntranceHash == "" || stored.SecurityEntranceHash == entrance || stored.SecurityEntranceStatus != http.StatusInternalServerError {
		t.Fatalf("unexpected persisted entrance settings: %+v", stored)
	}
	rawDigest := sha256.Sum256([]byte(entrance))
	if stored.SecurityEntranceHash == hex.EncodeToString(rawDigest[:]) {
		t.Fatal("security entrance used an offline-guessable raw digest")
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte(entrance)) {
		t.Fatal("security entrance was persisted in plaintext")
	}

	blocked := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/", nil, "", nil)
	if blocked.Code != http.StatusInternalServerError || !strings.Contains(blocked.Body.String(), "Internal Server Error") {
		t.Fatalf("blocked frontend returned %d: %s", blocked.Code, blocked.Body.String())
	}
	if strings.Contains(blocked.Body.String(), entrance) || strings.Contains(blocked.Body.String(), "Nginx Atlas") {
		t.Fatal("blocked frontend exposed panel or entrance details")
	}
	blockedLogin := performEntranceRequest(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": adminToken}, "", nil)
	if blockedLogin.Code != http.StatusInternalServerError {
		t.Fatalf("direct login returned %d", blockedLogin.Code)
	}

	accepted := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/"+entrance, nil, "", nil)
	if accepted.Code != http.StatusSeeOther || accepted.Header().Get("Location") != "/login" {
		t.Fatalf("entrance returned %d with location %q", accepted.Code, accepted.Header().Get("Location"))
	}
	cookies := accepted.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != securityEntranceCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected entrance cookie: %+v", cookies)
	}
	admission := cookies[0]
	rotatedController, err := New(Config{AdminToken: strings.Repeat("r", 32), ProxyToken: testProxyToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedAdmission := performEntranceRequest(t, rotatedController.Handler(), http.MethodGet, "/"+entrance, nil, "", nil)
	if rotatedAdmission.Code != http.StatusSeeOther || rotatedAdmission.Header().Get("Location") != "/login" {
		t.Fatalf("admin token rotation invalidated the entrance path: %d", rotatedAdmission.Code)
	}
	staleAdmission := performEntranceRequest(t, rotatedController.Handler(), http.MethodGet, "/login", nil, "", admission)
	if staleAdmission.Code != http.StatusInternalServerError {
		t.Fatalf("admin token rotation did not invalidate the old admission cookie: %d", staleAdmission.Code)
	}
	spoofedHTTPS := httptest.NewRequest(http.MethodGet, "/"+entrance, nil)
	spoofedHTTPS.Header.Set("X-Forwarded-Proto", "https")
	spoofedRecorder := httptest.NewRecorder()
	controller.Handler().ServeHTTP(spoofedRecorder, spoofedHTTPS)
	spoofedCookies := spoofedRecorder.Result().Cookies()
	if len(spoofedCookies) != 1 || spoofedCookies[0].Secure || spoofedRecorder.Header().Get("Strict-Transport-Security") != "" {
		t.Fatalf("untrusted HTTPS header changed transport security: cookies=%+v hsts=%q", spoofedCookies, spoofedRecorder.Header().Get("Strict-Transport-Security"))
	}

	trustedHTTPS := httptest.NewRequest(http.MethodGet, "/"+entrance, nil)
	trustedHTTPS.Header.Set("X-Atlas-Proxy", testProxyToken)
	trustedHTTPS.Header.Set("X-Forwarded-Proto", "https")
	trustedRecorder := httptest.NewRecorder()
	controller.Handler().ServeHTTP(trustedRecorder, trustedHTTPS)
	trustedCookies := trustedRecorder.Result().Cookies()
	if len(trustedCookies) != 1 || !trustedCookies[0].Secure || trustedRecorder.Header().Get("Strict-Transport-Security") == "" {
		t.Fatalf("trusted HTTPS request missed transport security: cookies=%+v hsts=%q", trustedCookies, trustedRecorder.Header().Get("Strict-Transport-Security"))
	}

	loginPage := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/login", nil, "", admission)
	if loginPage.Code != http.StatusOK || !strings.Contains(loginPage.Body.String(), "<!doctype html>") {
		t.Fatalf("admitted login page returned %d: %s", loginPage.Code, loginPage.Body.String())
	}
	loginConfig := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/api/v1/login-config", nil, "", admission)
	if loginConfig.Code != http.StatusOK {
		t.Fatalf("admitted login config returned %d: %s", loginConfig.Code, loginConfig.Body.String())
	}
	login := performEntranceRequest(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": adminToken}, "", admission)
	if login.Code != http.StatusOK {
		t.Fatalf("admitted login returned %d: %s", login.Code, login.Body.String())
	}

	health := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/healthz", nil, "", nil)
	if health.Code != http.StatusOK {
		t.Fatalf("health endpoint was gated: %d", health.Code)
	}
	dashboard := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/api/v1/dashboard", nil, "Bearer "+adminToken, nil)
	if dashboard.Code != http.StatusOK {
		t.Fatalf("authenticated API was gated: %d: %s", dashboard.Code, dashboard.Body.String())
	}

	changed := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings", map[string]any{
		"security_entrance_enabled": true,
		"security_entrance":         "newSecurePath9",
	}, "Bearer "+adminToken)
	if changed.Code != http.StatusOK {
		t.Fatalf("change security entrance returned %d: %s", changed.Code, changed.Body.String())
	}
	staleCookie := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/login", nil, "", admission)
	if staleCookie.Code != http.StatusInternalServerError {
		t.Fatalf("old entrance cookie remained valid: %d", staleCookie.Code)
	}
}

func TestSecurityEntranceSettingsRejectUnsafeValuesAndCanBeDisabled(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x74}, 32))
	adminToken := strings.Repeat("f", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{"short", "nested/path", "login", "路径入口123456"} {
		response := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings", map[string]any{
			"security_entrance_enabled": true,
			"security_entrance":         value,
		}, "Bearer "+adminToken)
		if response.Code != http.StatusBadRequest {
			t.Errorf("unsafe entrance %q returned %d", value, response.Code)
		}
	}
	missing := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings", map[string]any{
		"security_entrance_enabled": true,
	}, "Bearer "+adminToken)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing entrance returned %d", missing.Code)
	}
	invalidStatus := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings", map[string]any{
		"security_entrance_status": http.StatusTeapot,
	}, "Bearer "+adminToken)
	if invalidStatus.Code != http.StatusBadRequest {
		t.Fatalf("invalid entrance status returned %d", invalidStatus.Code)
	}

	enabled := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings", map[string]any{
		"security_entrance_enabled": true,
		"security_entrance":         "/valid_path-99/",
		"security_entrance_status":  444,
	}, "Bearer "+adminToken)
	if enabled.Code != http.StatusOK {
		t.Fatalf("valid entrance returned %d: %s", enabled.Code, enabled.Body.String())
	}
	blocked := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/", nil, "", nil)
	if blocked.Code != 444 || blocked.Body.Len() != 0 {
		t.Fatalf("444 entrance response returned %d with %d bytes", blocked.Code, blocked.Body.Len())
	}

	disabled := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings", map[string]any{
		"security_entrance_enabled": false,
	}, "Bearer "+adminToken)
	if disabled.Code != http.StatusOK || stateStore.Snapshot().Settings.SecurityEntranceHash != "" {
		t.Fatalf("disable entrance returned %d: %s", disabled.Code, disabled.Body.String())
	}
	root := performEntranceRequest(t, controller.Handler(), http.MethodGet, "/", nil, "", nil)
	if root.Code != http.StatusOK {
		t.Fatalf("disabled entrance still blocked frontend: %d", root.Code)
	}
}

func performEntranceRequest(t *testing.T, handler http.Handler, method, path string, body any, authorization string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	payload := []byte(nil)
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("X-Atlas-Proxy", testProxyToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
