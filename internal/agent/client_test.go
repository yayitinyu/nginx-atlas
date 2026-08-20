package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientUnregisterUsesStoredNodeCredential(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/agent/self" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(`{"node_id":"node_1","secret":"secret_1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := OSCommandRunner{}
	client, err := NewClient(ClientConfig{ServerURL: server.URL, StatePath: statePath}, NewExecutor(ExecutorConfig{}, runner), runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Unregister(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authorization != "AtlasNode node_1.secret_1" {
		t.Fatalf("authorization = %q", authorization)
	}
}

func TestClientStopsAndRemovesCredentialAfterControllerRevocation(t *testing.T) {
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "节点不存在或已撤销", "code": "node_unauthorized"})
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(`{"node_id":"node_1","secret":"secret_1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{}
	executor := NewExecutor(ExecutorConfig{DataRoot: t.TempDir(), Systemctl: "systemctl"}, runner)
	client, err := NewClient(ClientConfig{ServerURL: server.URL, StatePath: statePath, PollInterval: 3 * time.Second}, executor, runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Run(ctx); err == nil || !strings.Contains(err.Error(), "credential removed") {
		t.Fatalf("Run error = %v", err)
	}
	if polls != 1 {
		t.Fatalf("revoked agent polled %d times", polls)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("revoked credential file still exists: %v", err)
	}
	if _, err := os.Stat(statePath + ".revoked"); err != nil {
		t.Fatalf("revocation marker missing: %v", err)
	}
	foundDisable, foundStop := false, false
	for _, call := range runner.calls {
		if call.name == "systemctl" && len(call.args) > 0 && call.args[0] == "disable" {
			foundDisable = true
		}
		if call.name == "systemctl" && len(call.args) > 0 && call.args[0] == "stop" {
			foundStop = true
		}
	}
	if !foundDisable || !foundStop {
		t.Fatalf("revoked agent was not stopped: %+v", runner.calls)
	}
}
