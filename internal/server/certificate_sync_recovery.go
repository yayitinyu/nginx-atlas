package server

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const wildcardSyncMinimumVersion = "0.1.23"

func (s *Server) requeueRecoverableWildcardSyncs(state *model.State) error {
	for _, failed := range state.Jobs {
		if failed.Type != protocol.JobSyncCertificate || failed.Status != model.JobFailed || failed.RetryOfID != "" || failed.RetryJobID != "" || strings.TrimSpace(failed.Error) != "invalid certificate domain: invalid domain" {
			continue
		}
		var spec syncCertificateSpec
		if json.Unmarshal(failed.Payload, &spec) != nil || !strings.HasPrefix(spec.Domain, "*.") {
			continue
		}
		node, ok := state.Nodes[failed.NodeID]
		if !ok || node.Status != model.NodeOnline || !node.NginxHealthy || hasAnyActiveNodeJob(state, node.ID) || !supportsWildcardSync(node.AgentVersion) {
			continue
		}
		certificate, ok := state.Certificates[spec.CertificateID]
		if !ok || certificate.Domain != spec.Domain || !slices.Contains(certificate.DNSNames, spec.Domain) || !certificate.NotAfter.After(time.Now().UTC()) || slices.Contains(certificate.DeployedNodeIDs, node.ID) || !isLatestCertificateForDomain(state, certificate) || hasActiveCertificateSync(state, node.ID, certificate.ID) {
			continue
		}
		retry, err := enqueueJob(state, node.ID, failed.DomainID, protocol.JobSyncCertificate, syncCertificateSpec{
			CertificateID: certificate.ID, Domain: certificate.Domain, ReloadNginx: spec.ReloadNginx,
		})
		if err != nil {
			return err
		}
		retry.RetryOfID = failed.ID
		state.Jobs[retry.ID] = retry
		failed.RetryJobID = retry.ID
		state.Jobs[failed.ID] = failed
		s.addAudit(state, "info", "certificate.sync.requeued", "节点升级后重新安排泛域名证书同步", node.ID, failed.DomainID, retry.ID)
	}
	return nil
}

func supportsWildcardSync(version string) bool {
	_, _, valid := parseReleaseVersion(version)
	return valid && !versionUpdateAvailable(version, wildcardSyncMinimumVersion)
}

func isLatestCertificateForDomain(state *model.State, certificate model.Certificate) bool {
	for _, candidate := range state.Certificates {
		if candidate.ID != certificate.ID && candidate.Domain == certificate.Domain && candidate.CreatedAt.After(certificate.CreatedAt) {
			return false
		}
	}
	return true
}

func hasActiveCertificateSync(state *model.State, nodeID, certificateID string) bool {
	for _, job := range state.Jobs {
		if job.NodeID != nodeID || job.Type != protocol.JobSyncCertificate || (job.Status != model.JobQueued && job.Status != model.JobRunning) {
			continue
		}
		var spec syncCertificateSpec
		if json.Unmarshal(job.Payload, &spec) == nil && spec.CertificateID == certificateID {
			return true
		}
	}
	return false
}
