package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

func TestWildcardSyncRecoversOnceAfterAgentUpgrade(t *testing.T) {
	s, st, _ := updateTestController(t)
	now := time.Now().UTC()
	payload, err := json.Marshal(syncCertificateSpec{CertificateID: "cert", Domain: "*.example.com", ReloadNginx: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(state *model.State) error {
		node := state.Nodes["node"]
		node.AgentVersion = "0.1.22"
		node.NginxHealthy = true
		node.RunningJobID = ""
		state.Nodes[node.ID] = node
		update := state.Jobs["update"]
		update.Status = model.JobSucceeded
		update.FinishedAt = &now
		state.Jobs[update.ID] = update
		state.Certificates["cert"] = model.Certificate{ID: "cert", Domain: "*.example.com", DNSNames: []string{"*.example.com"}, NotAfter: now.Add(30 * 24 * time.Hour), CreatedAt: now}
		state.Jobs["failed-sync"] = model.Job{ID: "failed-sync", NodeID: "node", Type: protocol.JobSyncCertificate, Status: model.JobFailed, Payload: payload, Attempts: 3, MaxAttempts: 3, Error: "invalid certificate domain: invalid domain", CreatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.runMaintenance()
	if st.Snapshot().Jobs["failed-sync"].RetryJobID != "" {
		t.Fatal("unsupported agent received a wildcard retry")
	}
	if err := st.Update(func(state *model.State) error {
		node := state.Nodes["node"]
		node.AgentVersion = "0.1.23"
		state.Nodes[node.ID] = node
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.runMaintenance()
	state := st.Snapshot()
	retryID := state.Jobs["failed-sync"].RetryJobID
	if retryID == "" || state.Jobs[retryID].Status != model.JobQueued || state.Jobs[retryID].RetryOfID != "failed-sync" {
		t.Fatalf("wildcard retry was not queued after upgrade: %+v", state.Jobs["failed-sync"])
	}
	s.runMaintenance()
	if st.Snapshot().Jobs["failed-sync"].RetryJobID != retryID {
		t.Fatal("wildcard sync was queued more than once")
	}
}

func TestWildcardSyncDoesNotRestoreSupersededCertificate(t *testing.T) {
	s, st, _ := updateTestController(t)
	now := time.Now().UTC()
	payload, err := json.Marshal(syncCertificateSpec{CertificateID: "old-cert", Domain: "*.example.com", ReloadNginx: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(state *model.State) error {
		node := state.Nodes["node"]
		node.AgentVersion = "0.1.23"
		node.NginxHealthy = true
		node.RunningJobID = ""
		state.Nodes[node.ID] = node
		update := state.Jobs["update"]
		update.Status = model.JobSucceeded
		state.Jobs[update.ID] = update
		state.Certificates["old-cert"] = model.Certificate{ID: "old-cert", Domain: "*.example.com", DNSNames: []string{"*.example.com"}, NotAfter: now.Add(30 * 24 * time.Hour), CreatedAt: now.Add(-time.Hour)}
		state.Certificates["new-cert"] = model.Certificate{ID: "new-cert", Domain: "*.example.com", DNSNames: []string{"*.example.com"}, NotAfter: now.Add(30 * 24 * time.Hour), CreatedAt: now}
		state.Jobs["failed-sync"] = model.Job{ID: "failed-sync", NodeID: "node", Type: protocol.JobSyncCertificate, Status: model.JobFailed, Payload: payload, Error: "invalid certificate domain: invalid domain", CreatedAt: now.Add(-time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.runMaintenance()
	if st.Snapshot().Jobs["failed-sync"].RetryJobID != "" {
		t.Fatal("superseded certificate was retried")
	}
}
