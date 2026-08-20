package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestAdminAPIsRejectPasswordAndBootstrapTokensAfterPasswordSetup(t *testing.T) {
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"hostname":"","action":"turnstile-spin-v1"}`))
	}))
	defer verifier.Close()
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x5a}, 32))
	passwordHash, err := hashAdminPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	turnstileSecret, err := box.Seal("controller-settings:turnstile-secret", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stateStore.Update(func(state *model.State) error {
		state.AdminPasswordHash = passwordHash
		state.Settings.TurnstileEnabled = true
		state.Settings.TurnstileSiteKey = "site-key"
		state.Settings.TurnstileSecretCiphertext = turnstileSecret
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("s", 32)
	controller, err := New(Config{AdminToken: adminToken, TurnstileVerifyURL: verifier.URL, ProxyToken: testProxyToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, credential := range []string{"Bearer correct horse battery staple", "Bearer " + adminToken} {
		response := performJSON(t, controller.Handler(), http.MethodGet, "/api/v1/session", nil, credential)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("direct credential %q returned %d", credential, response.Code)
		}
	}
	apiCredential := performJSONFromIP(t, controller.Handler(), http.MethodGet, "/api/v1/session", nil, "AtlasAdmin "+adminToken, "127.0.0.1")
	if apiCredential.Code != http.StatusUnauthorized {
		t.Fatalf("retired bootstrap credential returned %d: %s", apiCredential.Code, apiCredential.Body.String())
	}

	login := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{
		"password": "correct horse battery staple", "turnstile_token": "valid",
	}, "")
	if login.Code != http.StatusOK {
		t.Fatalf("challenge-protected login returned %d: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	decodeRecorder(t, login, &session)
	verified := performJSON(t, controller.Handler(), http.MethodGet, "/api/v1/session", nil, "Bearer "+session.Token)
	if verified.Code != http.StatusOK {
		t.Fatalf("issued session returned %d: %s", verified.Code, verified.Body.String())
	}
}

func TestBootstrapAPITokenRequiresDirectLoopbackBeforePasswordSetup(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x5e}, 32))
	adminToken := strings.Repeat("b", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	directRequest := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	directRequest.RemoteAddr = "127.0.0.1:12345"
	directRequest.Header.Set("Authorization", "AtlasAdmin "+adminToken)
	direct := httptest.NewRecorder()
	controller.Handler().ServeHTTP(direct, directRequest)
	if direct.Code != http.StatusOK {
		t.Fatalf("direct bootstrap API credential returned %d", direct.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Authorization", "AtlasAdmin "+adminToken)
	request.Header.Set("X-Real-IP", "203.0.113.9")
	request.Header.Set("X-Atlas-Proxy", testProxyToken)
	proxied := httptest.NewRecorder()
	controller.Handler().ServeHTTP(proxied, request)
	if proxied.Code != http.StatusUnauthorized {
		t.Fatalf("proxied bootstrap credential returned %d", proxied.Code)
	}
}

func TestLocalEnrollmentRecoveryUsesSeparateDirectCredential(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x5f}, 32))
	localToken := strings.Repeat("l", 32)
	controller, err := New(Config{AdminToken: strings.Repeat("a", 32), LocalToken: localToken, ProxyToken: testProxyToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/local/enrollments", strings.NewReader(`{"ttl_minutes":30}`))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "AtlasLocal "+localToken)
	created := httptest.NewRecorder()
	controller.Handler().ServeHTTP(created, request)
	if created.Code != http.StatusCreated {
		t.Fatalf("local recovery returned %d: %s", created.Code, created.Body.String())
	}

	proxiedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/local/enrollments", strings.NewReader(`{"ttl_minutes":30}`))
	proxiedRequest.RemoteAddr = "127.0.0.1:12345"
	proxiedRequest.Header.Set("Content-Type", "application/json")
	proxiedRequest.Header.Set("Authorization", "AtlasLocal "+localToken)
	proxiedRequest.Header.Set("X-Real-IP", "203.0.113.10")
	proxiedRequest.Header.Set("X-Atlas-Proxy", testProxyToken)
	proxied := httptest.NewRecorder()
	controller.Handler().ServeHTTP(proxied, proxiedRequest)
	if proxied.Code != http.StatusUnauthorized {
		t.Fatalf("proxied local recovery returned %d", proxied.Code)
	}
}

func TestLogoutRevokesIssuedSession(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x5d}, 32))
	adminToken := strings.Repeat("p", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	login := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": adminToken}, "")
	var session struct {
		Token string `json:"token"`
	}
	decodeRecorder(t, login, &session)
	authorization := "Bearer " + session.Token
	logout := performJSON(t, controller.Handler(), http.MethodDelete, "/api/v1/session", nil, authorization)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout returned %d: %s", logout.Code, logout.Body.String())
	}
	verified := performJSON(t, controller.Handler(), http.MethodGet, "/api/v1/session", nil, authorization)
	if verified.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session returned %d", verified.Code)
	}
}

func TestLoginRateLimitBlocksAndRecovers(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x5b}, 32))
	adminToken := strings.Repeat("r", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	controller.loginNow = func() time.Time { return now }
	for attempt := 0; attempt < maxLoginAttemptsPerClient; attempt++ {
		response := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": "wrong"}, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d: %s", attempt+1, response.Code, response.Body.String())
		}
	}
	blocked := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": adminToken}, "")
	if blocked.Code != http.StatusTooManyRequests || blocked.Header().Get("Retry-After") == "" {
		t.Fatalf("blocked login returned %d with Retry-After %q", blocked.Code, blocked.Header().Get("Retry-After"))
	}
	now = now.Add(loginRateWindow + time.Second)
	recovered := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": adminToken}, "")
	if recovered.Code != http.StatusOK {
		t.Fatalf("recovered login returned %d: %s", recovered.Code, recovered.Body.String())
	}
}

func TestLoginRejectsWhenGlobalWorkCapacityIsFull(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x5c}, 32))
	controller, err := New(Config{AdminToken: strings.Repeat("q", 32)}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < cap(controller.loginWork); index++ {
		controller.loginWork <- struct{}{}
	}
	defer func() {
		for index := 0; index < cap(controller.loginWork); index++ {
			<-controller.loginWork
		}
	}()
	response := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": "anything"}, "")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("saturated login returned %d: %s", response.Code, response.Body.String())
	}
}

func TestLoginIPv6AddressesSharePrefixBudget(t *testing.T) {
	controller := &Server{loginAttempts: make(map[string]loginAttemptWindow), loginNow: time.Now}
	for attempt := 0; attempt < maxLoginAttemptsPerClient; attempt++ {
		client := fmt.Sprintf("2001:db8:1234:5678::%x", attempt+1)
		if allowed, _ := controller.reserveLoginAttempt(client); !allowed {
			t.Fatalf("attempt %d was blocked early", attempt+1)
		}
	}
	if allowed, _ := controller.reserveLoginAttempt("2001:db8:1234:5678::ffff"); allowed {
		t.Fatal("rotating IPv6 address bypassed the shared /64 budget")
	}
	if allowed, _ := controller.reserveLoginAttempt("2001:db8:1234:5679::1"); !allowed {
		t.Fatal("independent IPv6 /64 was incorrectly blocked")
	}
}

func TestPasswordAttemptBudgetRefillsWithoutSuccessReset(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	controller := &Server{loginNow: func() time.Time { return now }}
	for attempt := 0; attempt < passwordAttemptBurst; attempt++ {
		if allowed, _ := controller.reservePasswordAttempt(); !allowed {
			t.Fatalf("password attempt %d was blocked early", attempt+1)
		}
	}
	if allowed, retryAfter := controller.reservePasswordAttempt(); allowed || retryAfter <= 0 {
		t.Fatalf("exhausted password budget allowed=%t retry=%s", allowed, retryAfter)
	}
	now = now.Add(passwordAttemptRefill)
	if allowed, _ := controller.reservePasswordAttempt(); !allowed {
		t.Fatal("password budget did not refill")
	}
}

func TestPublicControllerRequiresProxyToken(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x5a}, 32))
	_, err = New(Config{AdminToken: strings.Repeat("z", 32), PublicURL: "https://atlas.example.com"}, stateStore, box, nil)
	if err == nil || !strings.Contains(err.Error(), "proxy token") {
		t.Fatalf("public controller without proxy token returned %v", err)
	}
}
