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

func updateTestController(t *testing.T) (*Server, *store.Store, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x38}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{AdminToken: strings.Repeat("x", 32)}, st, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("a", 32)
	hash := sha256.Sum256([]byte(secret))
	now := time.Now().UTC()
	payload, err := json.Marshal(protocol.UpdateAtlasPayload{ExpectedVersion: "v0.1.18"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(state *model.State) error {
		state.Nodes["node"] = model.Node{ID: "node", SecretHash: hex.EncodeToString(hash[:]), Status: model.NodeOnline, AgentVersion: "0.1.16", RunningJobID: "update", LastSeenAt: &now}
		state.Jobs["update"] = model.Job{ID: "update", NodeID: "node", Type: protocol.JobUpdateAtlas, Status: model.JobRunning, Payload: payload, Attempts: 1, MaxAttempts: 3, CreatedAt: now, StartedAt: &now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, st, "AtlasNode node." + secret
}

func TestUpdateResultWaitsForVersionAndDoesNotRedispatch(t *testing.T) {
	s, st, auth := updateTestController(t)
	result := performJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/jobs/update/result", protocol.JobResultRequest{Success: true}, auth)
	if result.Code != http.StatusOK {
		t.Fatalf("result: %d %s", result.Code, result.Body.String())
	}
	job := st.Snapshot().Jobs["update"]
	if job.Status != model.JobRunning || job.UpdateAcceptedAt == nil || job.FinishedAt != nil {
		t.Fatalf("staged update prematurely completed: %+v", job)
	}
	duplicate := performJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/jobs/update/result", protocol.JobResultRequest{Success: true}, auth)
	if duplicate.Code != http.StatusOK || !st.Snapshot().Jobs["update"].UpdateAcceptedAt.Equal(*job.UpdateAcceptedAt) {
		t.Fatal("duplicate result reset confirmation")
	}
	// Recover a persisted update even when the node's running-job pointer was lost.
	if err := st.Update(func(state *model.State) error {
		n := state.Nodes["node"]
		n.RunningJobID = ""
		state.Nodes[n.ID] = n
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	response := performJSON(t, s.Handler(), http.MethodPost, "/api/v1/agent/poll", protocol.PollRequest{}, auth)
	if response.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", response.Code, response.Body.String())
	}
	var polled protocol.PollResponse
	decodeRecorder(t, response, &polled)
	if polled.Job != nil || polled.ReportAfter != 10 || st.Snapshot().Jobs["update"].Attempts != 1 {
		t.Fatalf("waiting update redispatched or reporting not accelerated: %+v", polled)
	}
}

func TestUpdateConfirmationRequiresFreshStableReportsBeyondRollbackWindow(t *testing.T) {
	s, st, _ := updateTestController(t)
	state := st.Snapshot()
	job := state.Jobs["update"]
	start := time.Now().UTC()
	job.UpdateAcceptedAt = &start
	state.Jobs[job.ID] = job
	node := state.Nodes["node"]
	report := &protocol.NodeReport{AgentVersion: "0.1.18"}
	observe := func(elapsed time.Duration, report *protocol.NodeReport) {
		s.observeUpdate(&state, &node, state.Jobs[job.ID], report, start.Add(elapsed))
	}
	for sec := 0; sec <= 100; sec += 10 {
		observe(time.Duration(sec)*time.Second, report)
	}
	if state.Jobs[job.ID].Status != model.JobRunning {
		t.Fatal("completed before rollback window")
	}
	observe(110*time.Second, &protocol.NodeReport{AgentVersion: "0.1.16"})
	if state.Jobs[job.ID].UpdateVersionSeenAt != nil {
		t.Fatal("rollback did not reset stability")
	}
	observe(170*time.Second, report)
	observe(180*time.Second, nil)
	if state.Jobs[job.ID].Status != model.JobRunning {
		t.Fatal("heartbeat confirmed cached version")
	}
	// A reporting gap must restart the stable interval.
	observe(210*time.Second, report)
	observe(220*time.Second, report)
	observe(230*time.Second, report)
	if state.Jobs[job.ID].Status != model.JobRunning {
		t.Fatal("report gap counted as stability")
	}
	observe(240*time.Second, report)
	if state.Jobs[job.ID].Status != model.JobSucceeded || node.RunningJobID != "" || state.Jobs[job.ID].FinishedAt == nil {
		t.Fatalf("stable version not confirmed: %+v", state.Jobs[job.ID])
	}
}

func TestUpdateConfirmationTimeoutDoesNotAutomaticallyRetry(t *testing.T) {
	s, st, _ := updateTestController(t)
	old := time.Now().UTC().Add(-updateConfirmationTimeout - time.Second)
	if err := st.Update(func(state *model.State) error {
		job := state.Jobs["update"]
		job.UpdateAcceptedAt = &old
		state.Jobs[job.ID] = job
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.runMaintenance()
	state := st.Snapshot()
	job := state.Jobs["update"]
	if job.Status != model.JobFailed || job.Attempts != 1 || job.FinishedAt == nil || state.Nodes["node"].RunningJobID != "" || !strings.Contains(job.Error, "0.1.16") {
		t.Fatalf("unconfirmed update retried or falsely succeeded: %+v", job)
	}
}

func TestUpdateConfirmationDeadlineWinsOverLateMatchingReport(t *testing.T) {
	s, st, _ := updateTestController(t)
	state := st.Snapshot()
	job := state.Jobs["update"]
	start := time.Now().UTC()
	job.UpdateAcceptedAt = &start
	job.UpdateVersionSeenAt = &start
	node := state.Nodes["node"]
	s.observeUpdate(&state, &node, job, &protocol.NodeReport{AgentVersion: "0.1.18"}, start.Add(updateConfirmationTimeout))
	if state.Jobs[job.ID].Status != model.JobFailed {
		t.Fatal("late report resurrected expired update")
	}
}
