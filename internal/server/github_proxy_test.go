package server

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestEnrollmentCommandRespectsGithubProxyChoice(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("a", 32)
	controller, err := New(Config{
		AdminToken: adminToken, PublicURL: "https://atlas.example.com", ProxyToken: strings.Repeat("p", 32),
		GithubProxy: "https://mirror.example.com",
	}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	create := func(body any) (int, string) {
		t.Helper()
		response := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/enrollments", body, "Bearer "+adminToken)
		if response.Code != http.StatusCreated {
			return response.Code, response.Body.String()
		}
		var result struct {
			Command string `json:"command"`
		}
		decodeRecorder(t, response, &result)
		return response.Code, result.Command
	}
	if status, command := create(map[string]any{}); status != http.StatusCreated || !strings.Contains(command, "--github-proxy 'https://mirror.example.com'") {
		t.Fatalf("default proxy command: %d %s", status, command)
	}
	if status, command := create(map[string]any{"github_proxy": ""}); status != http.StatusCreated || strings.Contains(command, "--github-proxy") {
		t.Fatalf("disabled proxy command: %d %s", status, command)
	}
	if status, command := create(map[string]any{"github_proxy": "https://other.example.com"}); status != http.StatusCreated || !strings.Contains(command, "--github-proxy 'https://other.example.com'") {
		t.Fatalf("custom proxy command: %d %s", status, command)
	}
	if status, _ := create(map[string]any{"github_proxy": "http://unsafe.example.com"}); status != http.StatusBadRequest {
		t.Fatalf("invalid proxy returned %d", status)
	}
}
