package server

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/issuer"
	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const certificateIssueTimeout = 15 * time.Minute

func (s *Server) runCertificateIssuer(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.issueNextCertificate(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Error("controller certificate job failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// issueNextCertificate runs on the controller's single issuer worker. Running
// jobs are picked up again after a controller restart.
func (s *Server) issueNextCertificate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot := s.store.Snapshot()
	jobs := make([]model.Job, 0)
	now := time.Now().UTC()
	for _, job := range snapshot.Jobs {
		if job.Type == protocol.JobIssueCertificate &&
			(job.Status == model.JobRunning || (job.Status == model.JobQueued && !jobQueueTime(job).After(now))) {
			jobs = append(jobs, job)
		}
	}
	if len(jobs) == 0 {
		return nil
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.Before(jobs[j].CreatedAt) })
	selected := jobs[0]
	if err := s.store.Update(func(state *model.State) error {
		current, ok := state.Jobs[selected.ID]
		if !ok || (current.Status != model.JobQueued && current.Status != model.JobRunning) {
			return errConflict
		}
		current.Status = model.JobRunning
		current.Attempts++
		current.StartedAt = &now
		state.Jobs[current.ID] = current
		if node, ok := state.Nodes[current.NodeID]; ok && node.RunningJobID == current.ID {
			node.RunningJobID = ""
			state.Nodes[node.ID] = node
		}
		selected = current
		return nil
	}); err != nil {
		return err
	}
	state := s.store.Snapshot()
	wired, err := s.buildWireJob(selected, state)
	var bundle protocol.CertificateBundle
	if err == nil {
		var payload protocol.IssueCertificatePayload
		err = json.Unmarshal(wired.Payload, &payload)
		if err == nil {
			issueCtx, cancel := context.WithTimeout(ctx, certificateIssueTimeout)
			bundle, err = issuer.Issue(issueCtx, payload, s.config.DataRoot, s.config.LegoBinary, s.certificateRunner, time.Now())
			cancel()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var prepared *model.Certificate
	if err == nil {
		prepared, err = s.prepareCertificateResult(s.store.Snapshot(), selected, &bundle)
	}
	finished := time.Now().UTC()
	updateErr := s.store.Update(func(state *model.State) error {
		current, ok := state.Jobs[selected.ID]
		if !ok || current.Status != model.JobRunning || current.Attempts != selected.Attempts {
			return errConflict
		}
		if err == nil {
			if completeErr := s.completeSuccessfulJob(state, current, protocol.JobResultRequest{Success: true}, prepared); completeErr != nil {
				return completeErr
			}
			current.Status = model.JobSucceeded
			current.Error = ""
			current.FinishedAt = &finished
			s.addAudit(state, "success", "certificate.issue.succeeded", "主控已签发证书并加入下发队列", current.NodeID, current.DomainID, current.ID)
		} else {
			current.Error = truncate(err.Error(), 2048)
			if current.Attempts < current.MaxAttempts {
				current.Status = model.JobQueued
				retryAt := finished.Add(time.Duration(current.Attempts) * time.Minute)
				current.QueuedAt = &retryAt
				current.StartedAt = nil
				s.addAudit(state, "warning", "certificate.issue.retry", "主控签发失败，稍后重试", current.NodeID, current.DomainID, current.ID)
			} else {
				current.Status = model.JobFailed
				current.FinishedAt = &finished
				s.addAudit(state, "error", "certificate.issue.failed", "主控签发失败", current.NodeID, current.DomainID, current.ID)
			}
			if domain, exists := state.Domains[current.DomainID]; exists {
				domain.LastError = current.Error
				domain.UpdatedAt = finished
				state.Domains[domain.ID] = domain
			}
		}
		state.Jobs[current.ID] = current
		return nil
	})
	if updateErr != nil {
		return updateErr
	}
	return err
}
