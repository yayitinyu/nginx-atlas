package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestDomainConfigEditCommitsOnlyAfterNodeSuccess(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x58}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("a", 32)
	secret := strings.Repeat("s", 32)
	hash := sha256.Sum256([]byte(secret))
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_1"] = model.Node{ID: "node_1", Name: "node", Status: model.NodeOnline, SecretHash: hex.EncodeToString(hash[:])}
		state.Domains["dom_1"] = model.Domain{ID: "dom_1", Name: "api.example.com", NodeID: "node_1", UpstreamHost: "127.0.0.1", UpstreamPort: 8080, CreatedAt: now, UpdatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/domains/dom_1/config"
	read := func() domainConfigView {
		t.Helper()
		response := performJSON(t, controller.Handler(), http.MethodGet, path, nil, "Bearer "+adminToken)
		if response.Code != http.StatusOK {
			t.Fatalf("read config: %d %s", response.Code, response.Body.String())
		}
		var view domainConfigView
		decodeRecorder(t, response, &view)
		return view
	}
	initial := read()
	if initial.Mode != "generated" || !strings.Contains(initial.Config, "proxy_pass http://127.0.0.1:8080;") {
		t.Fatalf("unexpected generated config: %+v", initial)
	}
	custom := "server { listen 80; server_name api.example.com; location / { proxy_pass http://127.0.0.1:8081; } }\n"
	queue := func(revision string) model.Job {
		t.Helper()
		response := performJSON(t, controller.Handler(), http.MethodPut, path, map[string]string{"config": custom, "revision": revision}, "Bearer "+adminToken)
		if response.Code != http.StatusAccepted {
			t.Fatalf("queue config: %d %s", response.Code, response.Body.String())
		}
		var job model.Job
		decodeRecorder(t, response, &job)
		return job
	}
	job := queue(initial.Revision)
	if strings.Contains(string(job.Payload), "proxy_pass") {
		t.Fatal("configuration source was returned in the queue response")
	}
	if stateStore.Snapshot().Domains["dom_1"].CustomConfig != "" {
		t.Fatal("unvalidated config became active")
	}
	snapshot := stateStore.Snapshot()
	wired, err := controller.buildWireJob(snapshot.Jobs[job.ID], snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var payload protocol.ApplyDomainPayload
	if err := json.Unmarshal(wired.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CustomConfig != custom {
		t.Fatal("custom config was not sent to node")
	}
	markRunning := func(jobID string) {
		t.Helper()
		if err := stateStore.Update(func(state *model.State) error {
			current := state.Jobs[jobID]
			current.Status = model.JobRunning
			current.Attempts = current.MaxAttempts
			state.Jobs[jobID] = current
			node := state.Nodes["node_1"]
			node.RunningJobID = jobID
			state.Nodes[node.ID] = node
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	markRunning(job.ID)
	failed := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/jobs/"+job.ID+"/result", protocol.JobResultRequest{Success: false, Error: "nginx -t failed"}, "AtlasNode node_1."+secret)
	if failed.Code != http.StatusOK {
		t.Fatalf("failed result: %d %s", failed.Code, failed.Body.String())
	}
	if stateStore.Snapshot().Domains["dom_1"].CustomConfig != "" {
		t.Fatal("failed config replaced the active version")
	}
	job = queue(read().Revision)
	markRunning(job.ID)
	succeeded := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/jobs/"+job.ID+"/result", protocol.JobResultRequest{Success: true}, "AtlasNode node_1."+secret)
	if succeeded.Code != http.StatusOK {
		t.Fatalf("success result: %d %s", succeeded.Code, succeeded.Body.String())
	}
	if current := read(); current.Mode != "custom" || current.Config != custom {
		t.Fatalf("custom config was not committed: %+v", current)
	}
	dashboard := performJSON(t, controller.Handler(), http.MethodGet, "/api/v1/dashboard", nil, "Bearer "+adminToken)
	if dashboard.Code != http.StatusOK || strings.Contains(dashboard.Body.String(), `"custom_config"`) {
		t.Fatal("full Nginx source leaked into dashboard data")
	}
	stale := performJSON(t, controller.Handler(), http.MethodPut, path, map[string]string{"config": custom, "revision": initial.Revision}, "Bearer "+adminToken)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale revision returned %d", stale.Code)
	}
	current := read()
	reset := performJSON(t, controller.Handler(), http.MethodPut, path, map[string]string{"config": "", "revision": current.Revision}, "Bearer "+adminToken)
	if reset.Code != http.StatusAccepted {
		t.Fatalf("reset returned %d: %s", reset.Code, reset.Body.String())
	}
	var resetJob model.Job
	decodeRecorder(t, reset, &resetJob)
	markRunning(resetJob.ID)
	resetDone := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/jobs/"+resetJob.ID+"/result", protocol.JobResultRequest{Success: true}, "AtlasNode node_1."+secret)
	if resetDone.Code != http.StatusOK {
		t.Fatalf("reset result: %d %s", resetDone.Code, resetDone.Body.String())
	}
	if restored := read(); restored.Mode != "generated" || restored.Config != restored.GeneratedConfig {
		t.Fatalf("generated config was not restored: %+v", restored)
	}
}
