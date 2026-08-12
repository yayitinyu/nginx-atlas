package server

import (
	"context"
	"encoding/json"
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
			if node.LastSeenAt == nil || now.Sub(*node.LastSeenAt) > s.nodeOfflineAfter(*state) {
				if node.Status != model.NodeOffline {
					node.Status = model.NodeOffline
					appendNodeStatusSample(&node, model.NodeOffline, now)
				}
				state.Nodes[id] = node
			}
		}
		for id, job := range state.Jobs {
			if job.Status != model.JobRunning || job.StartedAt == nil || now.Sub(*job.StartedAt) <= timeoutForJob(job.Type) {
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
				restoreFailedDomainDeletion(state, job, job.Error, now)
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
			node, nodeExists := state.Nodes[domain.NodeID]
			if !nodeExists || node.Status == model.NodeRevoked {
				continue
			}
			if _, ok := state.ACMEAccounts[domain.ACMEAccountID]; !ok {
				continue
			}
			if _, ok := state.DNSAccounts[domain.DNSAccountID]; !ok {
				continue
			}
			certificate, ok := state.Certificates[domain.CertificateID]
			renewBeforeDays := normalizeRenewBeforeDays(domain.RenewBeforeDays)
			if ok && certificate.NotAfter.Sub(now) > time.Duration(renewBeforeDays)*24*time.Hour {
				continue
			}
			if hasActiveJob(state, domain.ID, protocol.JobIssueCertificate) {
				continue
			}
			job, err := enqueueJob(state, domain.NodeID, domain.ID, protocol.JobIssueCertificate, issueCertificateSpec{DomainID: domain.ID, DNSNames: desiredNamesForDomain(*state, domain)})
			if err != nil {
				return err
			}
			domain.LastJobID = job.ID
			domain.UpdatedAt = now
			state.Domains[id] = domain
			s.addAudit(state, "info", "certificate.renew.scheduled", "证书进入自动续期窗口", domain.NodeID, domain.ID, job.ID)
		}
		linkedRenewals := make(map[string]bool)
		for _, domain := range state.Domains {
			if domain.AutoRenew && domain.CertificateID != "" {
				linkedRenewals[domain.CertificateID] = true
			}
		}
		for id, certificate := range state.Certificates {
			if !certificate.AutoRenew || linkedRenewals[id] || certificate.ACMEAccountID == "" || certificate.DNSAccountID == "" || certificate.IssuerNodeID == "" {
				continue
			}
			renewBeforeDays := normalizeRenewBeforeDays(certificate.RenewBeforeDays)
			if certificate.NotAfter.Sub(now) > time.Duration(renewBeforeDays)*24*time.Hour || hasActiveCertificateJob(state, certificate.ID) {
				continue
			}
			node, ok := state.Nodes[certificate.IssuerNodeID]
			if !ok || node.Status == model.NodeRevoked {
				continue
			}
			if _, ok := state.ACMEAccounts[certificate.ACMEAccountID]; !ok {
				continue
			}
			if _, ok := state.DNSAccounts[certificate.DNSAccountID]; !ok {
				continue
			}
			syncNodeIDs := make([]string, 0, len(certificate.DeployedNodeIDs))
			for _, nodeID := range certificate.DeployedNodeIDs {
				if nodeID != certificate.IssuerNodeID {
					syncNodeIDs = append(syncNodeIDs, nodeID)
				}
			}
			job, err := enqueueJob(state, certificate.IssuerNodeID, "", protocol.JobIssueCertificate, issueCertificateSpec{
				Domain: certificate.Domain, DNSNames: desiredCertificateNames(certificate), CertificateID: certificate.ID,
				ACMEAccountID: certificate.ACMEAccountID, DNSAccountID: certificate.DNSAccountID,
				AutoRenew: true, RenewBeforeDays: renewBeforeDays,
				Install: true, ReloadNginx: true, SyncNodeIDs: syncNodeIDs,
			})
			if err != nil {
				return err
			}
			s.addAudit(state, "info", "certificate.renew.scheduled", "独立证书进入自动续期窗口", certificate.IssuerNodeID, "", job.ID)
		}
		return nil
	})
	if err != nil {
		s.logger.Error("maintenance failed", "error", err)
	}
}

func timeoutForJob(jobType string) time.Duration {
	if jobType == protocol.JobUpdateSystem {
		return 90 * time.Minute
	}
	if jobType == protocol.JobUpdateAtlas {
		return 30 * time.Minute
	}
	return runningJobTimeout
}

func hasActiveCertificateJob(state *model.State, certificateID string) bool {
	for _, job := range state.Jobs {
		if job.Type != protocol.JobIssueCertificate || (job.Status != model.JobQueued && job.Status != model.JobRunning) {
			continue
		}
		var spec issueCertificateSpec
		if json.Unmarshal(job.Payload, &spec) == nil && spec.CertificateID == certificateID {
			return true
		}
	}
	return false
}

func hasActiveJob(state *model.State, domainID, jobType string) bool {
	for _, job := range state.Jobs {
		if job.DomainID == domainID && job.Type == jobType && (job.Status == model.JobQueued || job.Status == model.JobRunning) {
			return true
		}
	}
	return false
}
