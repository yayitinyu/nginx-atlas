package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestRemoveChildNodeHidesTombstoneAndFailsActiveJobs(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x6c}, 32))
	adminToken := strings.Repeat("n", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["child"] = model.Node{ID: "child", Name: "Child", SecretHash: "secret", Status: model.NodeOnline, RunningJobID: "job_running", CreatedAt: now}
		state.Nodes["controller"] = model.Node{ID: "controller", Name: "Controller", Status: model.NodeOnline, ControllerInstalled: true, CreatedAt: now}
		state.Jobs["job_queued"] = model.Job{ID: "job_queued", NodeID: "child", Status: model.JobQueued, CreatedAt: now}
		state.Jobs["job_running"] = model.Job{ID: "job_running", NodeID: "child", Status: model.JobRunning, CreatedAt: now, StartedAt: &now}
		state.Domains["owned"] = model.Domain{ID: "owned", Name: "owned.example.com", NodeID: "child", SyncNodeIDs: []string{"controller", "child"}, Enabled: true, AutoRenew: true}
		state.Domains["kept"] = model.Domain{ID: "kept", Name: "kept.example.com", NodeID: "controller", SyncNodeIDs: []string{"child"}}
		state.Certificates["issued"] = model.Certificate{ID: "issued", Domain: "owned.example.com", IssuerNodeID: "child", AutoRenew: true, DeployedNodeIDs: []string{"child", "controller"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	removed := performJSON(t, controller.Handler(), http.MethodDelete, "/api/v1/nodes/child", struct{}{}, "Bearer "+adminToken)
	if removed.Code != http.StatusNoContent {
		t.Fatalf("remove returned %d: %s", removed.Code, removed.Body.String())
	}
	state := stateStore.Snapshot()
	child := state.Nodes["child"]
	if child.Status != model.NodeRevoked || child.SecretHash != "" || child.RunningJobID != "" {
		t.Fatalf("child tombstone was not revoked safely: %+v", child)
	}
	for _, jobID := range []string{"job_queued", "job_running"} {
		job := state.Jobs[jobID]
		if job.Status != model.JobFailed || job.Error != nodeRemovedJobError || job.FinishedAt == nil {
			t.Fatalf("active job %s was not failed: %+v", jobID, job)
		}
	}
	owned, exists := state.Domains["owned"]
	if !exists {
		t.Fatal("domain owned by the removed node was deleted")
	}
	if owned.NodeID != "" || owned.Enabled || owned.AutoRenew || owned.Deleting || owned.LastError != nodeRemovedJobError {
		t.Fatalf("owned domain was not preserved as a disabled orphan: %+v", owned)
	}
	if got := state.Domains["kept"].SyncNodeIDs; len(got) != 0 {
		t.Fatalf("removed node remains in domain sync targets: %v", got)
	}
	certificate := state.Certificates["issued"]
	if certificate.IssuerNodeID != "" || certificate.AutoRenew || len(certificate.DeployedNodeIDs) != 1 || certificate.DeployedNodeIDs[0] != "controller" {
		t.Fatalf("certificate references were not detached: %+v", certificate)
	}
	listed := performJSON(t, controller.Handler(), http.MethodGet, "/api/v1/nodes", nil, "Bearer "+adminToken)
	var nodes []model.Node
	decodeRecorder(t, listed, &nodes)
	if len(nodes) != 1 || nodes[0].ID != "controller" {
		t.Fatalf("visible nodes = %+v, want only controller", nodes)
	}
	orphanRemoval := performJSON(t, controller.Handler(), http.MethodDelete, "/api/v1/domains/owned", struct{}{}, "Bearer "+adminToken)
	if orphanRemoval.Code != http.StatusAccepted {
		t.Fatalf("orphan removal returned %d: %s", orphanRemoval.Code, orphanRemoval.Body.String())
	}
	if _, exists := stateStore.Snapshot().Domains["owned"]; exists {
		t.Fatal("confirmed orphan removal retained the controller record")
	}

	controllerRemoval := performJSON(t, controller.Handler(), http.MethodDelete, "/api/v1/nodes/controller", struct{}{}, "Bearer "+adminToken)
	if controllerRemoval.Code != http.StatusNoContent {
		t.Fatalf("self-reported controller node removal returned %d: %s", controllerRemoval.Code, controllerRemoval.Body.String())
	}
}

func TestAgentCanUnregisterItselfBeforeLocalUninstall(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x6d}, 32))
	controller, err := New(Config{AdminToken: strings.Repeat("o", 32)}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := "agent-secret"
	hash := sha256.Sum256([]byte(secret))
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["self"] = model.Node{ID: "self", Name: "Self", SecretHash: hex.EncodeToString(hash[:]), Status: model.NodeOnline, CreatedAt: time.Now().UTC()}
		state.Domains["managed"] = model.Domain{ID: "managed", Name: "managed.example.com", NodeID: "self", Enabled: true, AutoRenew: true, CreatedAt: time.Now().UTC()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	authorization := "AtlasNode self." + secret
	unregistered := performJSON(t, controller.Handler(), http.MethodDelete, "/api/v1/agent/self", struct{}{}, authorization)
	if unregistered.Code != http.StatusNoContent {
		t.Fatalf("unregister returned %d: %s", unregistered.Code, unregistered.Body.String())
	}
	polled := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/poll", struct{}{}, authorization)
	if polled.Code != http.StatusUnauthorized {
		t.Fatalf("revoked credential poll returned %d", polled.Code)
	}
	preserved := stateStore.Snapshot().Domains["managed"]
	if preserved.ID == "" || preserved.NodeID != "" || preserved.Enabled || preserved.AutoRenew {
		t.Fatalf("self-unregister deleted or left the managed domain active: %+v", preserved)
	}
}
