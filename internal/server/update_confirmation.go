package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const (
	// Older agents use a 90s rollback timer with systemd's default timer
	// accuracy. Observe beyond that window before trusting a version report.
	updateObservationDelay    = 3 * time.Minute
	updateStableDuration      = 30 * time.Second
	updateMaxReportGap        = 30 * time.Second
	updateConfirmationTimeout = 5 * time.Minute
)

func awaitingUpdateConfirmation(job model.Job) bool {
	return job.Type == protocol.JobUpdateAtlas && job.Status == model.JobRunning && job.UpdateAcceptedAt != nil
}

func (s *Server) observeUpdate(state *model.State, node *model.Node, job model.Job, report *protocol.NodeReport, now time.Time) {
	node.RunningJobID = job.ID
	if now.Sub(*job.UpdateAcceptedAt) >= updateConfirmationTimeout {
		s.finishUpdateConfirmation(state, node, job, false, now)
		return
	}
	// Heartbeats alone must not turn a cached version into proof of success.
	if report == nil {
		return
	}
	var payload protocol.UpdateAtlasPayload
	err := json.Unmarshal(job.Payload, &payload)
	expected := strings.TrimPrefix(strings.TrimSpace(payload.ExpectedVersion), "v")
	actual := strings.TrimPrefix(strings.TrimSpace(report.AgentVersion), "v")
	if err != nil || expected == "" || actual != expected {
		job.UpdateVersionSeenAt = nil
	} else {
		if job.UpdateVersionSeenAt == nil || job.UpdateLastReportAt == nil || now.Sub(*job.UpdateLastReportAt) > updateMaxReportGap {
			job.UpdateVersionSeenAt = &now
		}
		if now.Sub(*job.UpdateAcceptedAt) >= updateObservationDelay && now.Sub(*job.UpdateVersionSeenAt) >= updateStableDuration {
			s.finishUpdateConfirmation(state, node, job, true, now)
			return
		}
	}
	job.UpdateLastReportAt = &now
	state.Jobs[job.ID] = job
}

func (s *Server) finishUpdateConfirmation(state *model.State, node *model.Node, job model.Job, success bool, now time.Time) {
	job.FinishedAt = &now
	if node.RunningJobID == job.ID {
		node.RunningJobID = ""
	}
	if success {
		job.Status = model.JobSucceeded
		job.Error = ""
		s.addAudit(state, "success", "job.succeeded", "节点更新已通过版本稳定确认", job.NodeID, job.DomainID, job.ID)
	} else {
		job.Status = model.JobFailed
		var payload protocol.UpdateAtlasPayload
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			job.Error = "update confirmation failed: invalid persisted update payload"
		} else {
			job.Error = fmt.Sprintf("update activation was not confirmed before timeout (expected %s, last reported %s); inspect agent restart and rollback logs", payload.ExpectedVersion, node.AgentVersion)
		}
		node.LastError = job.Error
		s.addAudit(state, "error", "job.update.unconfirmed", "节点更新未能确认，可能已回滚；未自动重试", job.NodeID, job.DomainID, job.ID)
	}
	state.Jobs[job.ID] = job
}
