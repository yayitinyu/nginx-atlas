package server

import (
	"context"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const runningJobTimeout = 20 * time.Minute

func (s *Server) runScheduler(ctx context.Context) {
	s.runMaintenance()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runMaintenance()
		}
	}
}

func (s *Server) runMaintenance() {
	now := time.Now().UTC()
	err := s.store.Update(func(state *model.State) error {
		for id, node := range state.Nodes {
			if node.Status == model.NodeRevoked {
				continue
			}
			if node.LastSeenAt == nil || now.Sub(*node.LastSeenAt) > s.config.OfflineAfter {
				node.Status = model.NodeOffline
				state.Nodes[id] = node
			}
		}
		for id, job := range state.Jobs {
			if job.Status != model.JobRunning || job.StartedAt == nil || now.Sub(*job.StartedAt) <= runningJobTimeout {
				continue
			}
			if node, ok := state.Nodes[job.NodeID]; ok && node.RunningJobID == job.ID {
				node.RunningJobID = ""
				state.Nodes[node.ID] = node
			}
			if job.Attempts < job.MaxAttempts {
				job.Status = model.JobQueued
				job.StartedAt = nil
				job.Error = "agent did not report a result before the timeout"
				s.addAudit(state, "warning", "job.timeout.retry", "节点任务超时，已重新排队", job.NodeID, job.DomainID, job.ID)
			} else {
				job.Status = model.JobFailed
				job.Error = "agent did not report a result before the timeout"
				job.FinishedAt = &now
				s.addAudit(state, "error", "job.timeout", "节点任务多次超时", job.NodeID, job.DomainID, job.ID)
			}
			state.Jobs[id] = job
		}
		for id, enrollment := range state.Enrollments {
			if now.Sub(enrollment.ExpiresAt) > 24*time.Hour {
				delete(state.Enrollments, id)
			}
		}
		for id, domain := range state.Domains {
			if !domain.AutoRenew || domain.ACMEAccountID == "" || domain.DNSAccountID == "" {
				continue
			}
			certificate, ok := state.Certificates[domain.CertificateID]
			if ok && certificate.NotAfter.Sub(now) > time.Duration(domain.RenewBeforeDays)*24*time.Hour {
				continue
			}
			if hasActiveJob(state, domain.ID, protocol.JobIssueCertificate) {
				continue
			}
			job, err := enqueueJob(state, domain.NodeID, domain.ID, protocol.JobIssueCertificate, issueCertificateSpec{DomainID: domain.ID})
			if err != nil {
				return err
			}
			domain.LastJobID = job.ID
			domain.UpdatedAt = now
			state.Domains[id] = domain
			s.addAudit(state, "info", "certificate.renew.scheduled", "证书进入自动续期窗口", domain.NodeID, domain.ID, job.ID)
		}
		return nil
	})
	if err != nil {
		s.logger.Error("maintenance failed", "error", err)
	}
}

func hasActiveJob(state *model.State, domainID, jobType string) bool {
	for _, job := range state.Jobs {
		if job.DomainID == domainID && job.Type == jobType && (job.Status == model.JobQueued || job.Status == model.JobRunning) {
			return true
		}
	}
	return false
}
