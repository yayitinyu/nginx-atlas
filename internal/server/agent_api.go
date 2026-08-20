package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/certutil"
	"github.com/yayitinyu/nginx-atlas/internal/id"
	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const (
	maxNodeReportBody          = 512 << 10
	maxReportedIPAddresses     = 32
	maxReportedCertificates    = 256
	maxReportedNginxSites      = 256
	maxReportedCertificateSANs = 100
	minimumNodePollInterval    = 3 * time.Second
)

func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	var request protocol.EnrollRequest
	if !decodeJSONLimit(w, r, &request, maxNodeReportBody) {
		return
	}
	if len(request.Token) < 24 {
		writeError(w, http.StatusUnauthorized, "添加令牌无效", "invalid_enrollment", nil)
		return
	}
	tokenHash := sha256.Sum256([]byte(request.Token))
	now := time.Now().UTC()
	if !s.store.HasUsableEnrollment(tokenHash[:], now) {
		writeError(w, http.StatusUnauthorized, "添加令牌不存在、已使用或已过期", "invalid_enrollment", nil)
		return
	}
	nodeID, err := id.New("node")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	secret, err := id.Token(32)
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	secretHash := sha256.Sum256([]byte(secret))
	if err := validateNodeReport(request.Report); err != nil {
		writeError(w, http.StatusBadRequest, "节点报告超出安全限制", "invalid_node_report", map[string]string{"reason": err.Error()})
		return
	}
	var node model.Node
	err = s.store.Update(func(state *model.State) error {
		var enrollment model.Enrollment
		found := false
		for _, candidate := range state.Enrollments {
			expected, decodeErr := decodeHash(candidate.TokenHash)
			if decodeErr == nil && subtle.ConstantTimeCompare(tokenHash[:], expected) == 1 {
				enrollment, found = candidate, true
				break
			}
		}
		if !found || enrollment.UsedAt != nil || !now.Before(enrollment.ExpiresAt) {
			return errInvalidEnrollment
		}
		enrollment.UsedAt = &now
		state.Enrollments[enrollment.ID] = enrollment
		node = model.Node{
			ID: nodeID, Name: enrollment.Name, SecretHash: hex.EncodeToString(secretHash[:]), Status: model.NodeOnline,
			CreatedAt: now, LastSeenAt: &now,
		}
		applyNodeReport(&node, request.Report)
		if strings.TrimSpace(node.Name) == "" {
			node.Name = strings.TrimSpace(node.Hostname)
			if node.Name == "" {
				node.Name = node.ID
			}
		}
		appendNodeStatusSample(&node, model.NodeOnline, now)
		state.Nodes[node.ID] = node
		s.addAudit(state, "success", "node.enrolled", "节点已安全加入主控", node.ID)
		return nil
	})
	if errors.Is(err, errInvalidEnrollment) {
		writeError(w, http.StatusUnauthorized, "添加令牌不存在、已使用或已过期", "invalid_enrollment", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, protocol.EnrollResponse{
		NodeID: node.ID, NodeSecret: secret, PollAfter: int(s.config.PollAfter.Seconds()),
	})
}

func (s *Server) handleAgentPoll(w http.ResponseWriter, r *http.Request) {
	nodeID := nodeIDFromContext(r.Context())
	if retryAfter, ok := s.reserveNodePoll(nodeID); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", max(1, int(retryAfter.Round(time.Second).Seconds()))))
		writeError(w, http.StatusTooManyRequests, "节点轮询过于频繁", "node_poll_rate_limited", nil)
		return
	}
	var request protocol.PollRequest
	if !decodeJSONLimit(w, r, &request, maxNodeReportBody) {
		return
	}
	if request.Report != nil {
		if err := validateNodeReport(*request.Report); err != nil {
			writeError(w, http.StatusBadRequest, "节点报告超出安全限制", "invalid_node_report", map[string]string{"reason": err.Error()})
			return
		}
	}
	var selected *model.Job
	now := time.Now().UTC()
	err := s.store.Update(func(state *model.State) error {
		node, ok := state.Nodes[nodeID]
		if !ok || node.Status == model.NodeRevoked {
			return errNotFound
		}
		wasOnline := node.Status == model.NodeOnline
		node.Status = model.NodeOnline
		node.LastSeenAt = &now
		if request.Report != nil {
			applyNodeReport(&node, *request.Report)
			appendNodeStatusSample(&node, model.NodeOnline, now)
		} else if !wasOnline {
			appendNodeStatusSample(&node, model.NodeOnline, now)
		}

		if node.RunningJobID != "" {
			if job, ok := state.Jobs[node.RunningJobID]; ok && job.Status == model.JobRunning {
				if job.Attempts < job.MaxAttempts {
					job.Attempts++
				}
				if job.StartedAt == nil {
					job.StartedAt = &now
				}
				state.Jobs[job.ID] = job
				selected = &job
				state.Nodes[nodeID] = node
				return nil
			}
			node.RunningJobID = ""
		}
		orphanedRunning := make([]model.Job, 0, 1)
		for _, job := range state.Jobs {
			if job.NodeID == nodeID && job.Status == model.JobRunning {
				orphanedRunning = append(orphanedRunning, job)
			}
		}
		sort.Slice(orphanedRunning, func(i, j int) bool { return orphanedRunning[i].CreatedAt.Before(orphanedRunning[j].CreatedAt) })
		if len(orphanedRunning) > 0 {
			job := orphanedRunning[0]
			if job.Attempts < job.MaxAttempts {
				job.Attempts++
			}
			if job.StartedAt == nil {
				job.StartedAt = &now
			}
			state.Jobs[job.ID] = job
			node.RunningJobID = job.ID
			selected = &job
			state.Nodes[nodeID] = node
			return nil
		}
		queued := make([]model.Job, 0)
		for _, job := range state.Jobs {
			if job.NodeID == nodeID && job.Status == model.JobQueued {
				queued = append(queued, job)
			}
		}
		sort.Slice(queued, func(i, j int) bool { return queued[i].CreatedAt.Before(queued[j].CreatedAt) })
		if len(queued) > 0 {
			job := queued[0]
			job.Status = model.JobRunning
			job.Attempts++
			job.StartedAt = &now
			state.Jobs[job.ID] = job
			node.RunningJobID = job.ID
			selected = &job
		}
		state.Nodes[nodeID] = node
		return nil
	})
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	snapshot := s.store.Snapshot()
	response := protocol.PollResponse{
		PollAfter: int(s.config.PollAfter.Seconds()), ReportAfter: int(s.nodePollAfter(snapshot).Seconds()), ServerNow: now,
	}
	if selected != nil {
		wireJob, err := s.buildWireJob(*selected, snapshot)
		if err != nil {
			s.failDispatch(*selected, err)
			writeError(w, http.StatusInternalServerError, "无法生成节点任务", "job_dispatch_error", nil)
			return
		}
		response.Job = &wireJob
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleAgentUnregister(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := r.Context().Value(nodeContextKey{}).(string)
	now := time.Now().UTC()
	err := s.store.Update(func(state *model.State) error {
		if _, ok := state.Nodes[nodeID]; !ok {
			return errNotFound
		}
		revokeNodeState(state, nodeID, now)
		s.addAudit(state, "warning", "node.unregistered", "节点代理已自行注销", nodeID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "节点不存在", "not_found", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgentJobResult(w http.ResponseWriter, r *http.Request) {
	nodeID := nodeIDFromContext(r.Context())
	jobID := r.PathValue("id")
	var request protocol.JobResultRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, ok := s.store.JobForNode(jobID, nodeID)
	if !ok || job.Status != model.JobRunning {
		writeError(w, http.StatusConflict, "任务不存在、节点不匹配或已完成", "job_conflict", nil)
		return
	}
	var prepared *model.Certificate
	var err error
	if request.Success {
		snapshot := s.store.Snapshot()
		current, currentOK := snapshot.Jobs[jobID]
		if !currentOK || current.NodeID != nodeID || current.Status != model.JobRunning {
			writeError(w, http.StatusConflict, "任务状态已经改变", "job_conflict", nil)
			return
		}
		job = current
		prepared, err = s.prepareCertificateResult(snapshot, job, request.Certificate)
		if err != nil {
			request.Success = false
			request.Error = err.Error()
		}
	}
	now := time.Now().UTC()
	err = s.store.Update(func(state *model.State) error {
		current, ok := state.Jobs[jobID]
		if !ok || current.NodeID != nodeID || current.Status != model.JobRunning {
			return errConflict
		}
		node := state.Nodes[nodeID]
		node.RunningJobID = ""
		node.LastSeenAt = &now
		if request.Success {
			current.Status = model.JobSucceeded
			current.Error = ""
			current.FinishedAt = &now
			if err := s.completeSuccessfulJob(state, current, request, prepared); err != nil {
				return err
			}
			s.addAudit(state, "success", "job.succeeded", safeJobMessage(request.Message), nodeID, current.DomainID, current.ID)
		} else {
			current.Error = truncate(request.Error, 2048)
			if current.Attempts < current.MaxAttempts {
				current.Status = model.JobQueued
				current.QueuedAt = &now
				current.StartedAt = nil
				s.addAudit(state, "warning", "job.retry", "任务失败，已安排自动重试", nodeID, current.DomainID, current.ID)
			} else {
				current.Status = model.JobFailed
				current.FinishedAt = &now
				restoreFailedDomainDeletion(state, current, current.Error, now)
				s.addAudit(state, "error", "job.failed", "任务重试后仍然失败", nodeID, current.DomainID, current.ID)
			}
			if domain, ok := state.Domains[current.DomainID]; ok {
				domain.LastError = current.Error
				domain.UpdatedAt = now
				state.Domains[domain.ID] = domain
			}
			node.LastError = current.Error
		}
		state.Jobs[current.ID] = current
		state.Nodes[nodeID] = node
		return nil
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "任务状态已经改变", "job_conflict", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
}

func (s *Server) buildWireJob(job model.Job, state model.State) (protocol.WireJob, error) {
	wired := protocol.WireJob{ID: job.ID, Type: job.Type}
	var payload any
	switch job.Type {
	case protocol.JobApplyDomain:
		var spec applyDomainSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return wired, err
		}
		domain, ok := state.Domains[spec.DomainID]
		if !ok {
			return wired, errors.New("domain no longer exists")
		}
		wirePayload := protocol.ApplyDomainPayload{
			Domain: domain.Name, UpstreamHost: domain.UpstreamHost, UpstreamPort: domain.UpstreamPort,
			TLS: domain.CertificateMode != "", UseLocalCertificate: spec.UseLocalCertificate,
			LocalCertificateDir: spec.LocalCertificateDir, CaptureCertificate: spec.CaptureCertificate,
			ReplaceConfigPath: spec.ReplaceConfigPath,
			NginxWebsocket:    domain.NginxWebsocket, NginxHTTP2: domain.NginxHTTP2, NginxGzip: domain.NginxGzip,
		}
		if spec.CertificateID != "" {
			bundle, err := s.decryptCertificate(state, spec.CertificateID)
			if err != nil {
				return wired, err
			}
			wirePayload.Certificate = &bundle
		}
		payload = wirePayload
	case protocol.JobDeleteDomain:
		var spec deleteDomainSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return wired, err
		}
		payload = protocol.DeleteDomainPayload{Domain: spec.Domain, RestoreConfigPath: spec.RestoreConfigPath}
	case protocol.JobSyncCertificate:
		var spec syncCertificateSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return wired, err
		}
		bundle, err := s.decryptCertificate(state, spec.CertificateID)
		if err != nil {
			return wired, err
		}
		payload = protocol.SyncCertificatePayload{Domain: spec.Domain, Certificate: bundle, ReloadNginx: spec.ReloadNginx}
	case protocol.JobIssueCertificate:
		var spec issueCertificateSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return wired, err
		}
		domainName := spec.Domain
		acmeAccountID := spec.ACMEAccountID
		dnsAccountID := spec.DNSAccountID
		if spec.DomainID != "" {
			domain, ok := state.Domains[spec.DomainID]
			if !ok {
				return wired, errors.New("domain no longer exists")
			}
			domainName = domain.Name
			acmeAccountID = domain.ACMEAccountID
			dnsAccountID = domain.DNSAccountID
		}
		if domainName == "" {
			return wired, errors.New("certificate domain is missing")
		}
		dnsAccount, ok := state.DNSAccounts[dnsAccountID]
		if !ok {
			return wired, errors.New("DNS account no longer exists")
		}
		acmeAccount, ok := state.ACMEAccounts[acmeAccountID]
		if !ok {
			return wired, errors.New("ACME account no longer exists")
		}
		credentialsJSON, err := s.box.Open("dns-account:"+dnsAccount.ID, dnsAccount.CredentialsCiphertext)
		if err != nil {
			return wired, err
		}
		var credentials map[string]string
		if err := json.Unmarshal(credentialsJSON, &credentials); err != nil {
			return wired, errors.New("DNS credentials are corrupted")
		}
		var hmac string
		if acmeAccount.EABHMACCiphertext != "" {
			plaintext, err := s.box.Open("acme-account:"+acmeAccount.ID+":eab", acmeAccount.EABHMACCiphertext)
			if err != nil {
				return wired, err
			}
			hmac = string(plaintext)
		}
		payload = protocol.IssueCertificatePayload{
			Domain: domainName, Domains: spec.DNSNames, Email: acmeAccount.Email, DirectoryURL: acmeAccount.DirectoryURL,
			DNSProvider: dnsAccount.Provider, Credentials: credentials,
			EABKID: acmeAccount.EABKID, EABHMAC: hmac,
		}
	case protocol.JobCaptureCertificate:
		var spec captureCertificateSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return wired, err
		}
		domainName := spec.Domain
		if spec.DomainID != "" {
			if domain, ok := state.Domains[spec.DomainID]; ok {
				domainName = domain.Name
			}
		}
		if domainName == "" {
			return wired, errors.New("certificate domain is missing")
		}
		payload = protocol.CaptureCertificatePayload{Domain: domainName}
	case protocol.JobReloadNginx:
		payload = struct{}{}
	case protocol.JobUpdateAtlas:
		var update protocol.UpdateAtlasPayload
		if err := json.Unmarshal(job.Payload, &update); err != nil {
			return wired, err
		}
		payload = update
	case protocol.JobUpdateSystem:
		var update protocol.UpdateSystemPayload
		if err := json.Unmarshal(job.Payload, &update); err != nil {
			return wired, err
		}
		payload = update
	default:
		return wired, fmt.Errorf("unsupported job type %q", job.Type)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return wired, err
	}
	wired.Payload = encoded
	return wired, nil
}

func (s *Server) decryptCertificate(state model.State, certificateID string) (protocol.CertificateBundle, error) {
	certificate, ok := state.Certificates[certificateID]
	if !ok {
		return protocol.CertificateBundle{}, errors.New("certificate no longer exists")
	}
	fullchain, err := s.box.Open("certificate:"+certificate.ID+":fullchain", certificate.FullchainCiphertext)
	if err != nil {
		return protocol.CertificateBundle{}, err
	}
	privateKey, err := s.box.Open("certificate:"+certificate.ID+":private-key", certificate.PrivateKeyCiphertext)
	if err != nil {
		return protocol.CertificateBundle{}, err
	}
	return protocol.CertificateBundle{FullchainPEM: string(fullchain), PrivateKeyPEM: string(privateKey)}, nil
}

func (s *Server) failDispatch(job model.Job, dispatchErr error) {
	now := time.Now().UTC()
	_ = s.store.Update(func(state *model.State) error {
		current := state.Jobs[job.ID]
		current.Status = model.JobFailed
		current.Error = truncate(dispatchErr.Error(), 2048)
		current.FinishedAt = &now
		state.Jobs[current.ID] = current
		if node, ok := state.Nodes[job.NodeID]; ok {
			node.RunningJobID = ""
			state.Nodes[node.ID] = node
		}
		s.addAudit(state, "error", "job.dispatch.failed", "任务数据无法安全下发", job.NodeID, job.DomainID, job.ID)
		return nil
	})
}

func (s *Server) prepareCertificateResult(state model.State, job model.Job, bundle *protocol.CertificateBundle) (*model.Certificate, error) {
	if bundle == nil {
		if job.Type == protocol.JobIssueCertificate || job.Type == protocol.JobCaptureCertificate {
			return nil, errors.New("certificate task returned no certificate")
		}
		return nil, nil
	}
	context, err := certificateResultContextForJob(state, job)
	if err != nil {
		return nil, err
	}
	info, err := certutil.Validate([]byte(bundle.FullchainPEM), []byte(bundle.PrivateKeyPEM), context.Domain, time.Now())
	if err != nil {
		return nil, fmt.Errorf("agent returned an invalid certificate: %w", err)
	}
	if context.Source == model.CertificateACME {
		if err := certutil.VerifyTrustedChain([]byte(bundle.FullchainPEM), context.Domain, time.Now(), s.certificateRoots); err != nil {
			return nil, fmt.Errorf("agent returned an untrusted ACME certificate: %w", err)
		}
	}
	requestedDNSNames := context.RequestedDNSNames
	if len(requestedDNSNames) == 0 {
		requestedDNSNames = append([]string(nil), info.DNSNames...)
	}
	if err := ensureCertificateNames(info.DNSNames, requestedDNSNames); err != nil {
		return nil, fmt.Errorf("agent returned a certificate with incomplete names: %w", err)
	}
	certificateID := context.CertificateID
	var existing model.Certificate
	if certificateID != "" {
		existing = state.Certificates[certificateID]
	}
	if existing.ID == "" {
		var err error
		certificateID, err = id.New("crt")
		if err != nil {
			return nil, err
		}
	}
	fullchainCiphertext, err := s.mustSeal("certificate:"+certificateID+":fullchain", []byte(bundle.FullchainPEM))
	if err != nil {
		return nil, err
	}
	privateKeyCiphertext, err := s.mustSeal("certificate:"+certificateID+":private-key", []byte(bundle.PrivateKeyPEM))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	createdAt := existing.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	deployedNodeIDs := append([]string(nil), existing.DeployedNodeIDs...)
	if context.InstalledOnIssuer {
		deployedNodeIDs = appendUnique(deployedNodeIDs, job.NodeID)
	}
	return &model.Certificate{
		ID: certificateID, Domain: context.Domain, Source: context.Source,
		FullchainCiphertext: fullchainCiphertext, PrivateKeyCiphertext: privateKeyCiphertext,
		FingerprintSHA256: info.FingerprintSHA256, Issuer: info.Issuer, SerialNumber: info.SerialNumber,
		NotBefore: info.NotBefore, NotAfter: info.NotAfter, DNSNames: info.DNSNames, RequestedDNSNames: requestedDNSNames,
		AutoRenew: context.AutoRenew, RenewBeforeDays: normalizeRenewBeforeDays(context.RenewBeforeDays),
		ACMEAccountID: context.ACMEAccountID, DNSAccountID: context.DNSAccountID,
		IssuerNodeID: job.NodeID, DeployedNodeIDs: deployedNodeIDs,
		CreatedAt: createdAt, UpdatedAt: now,
	}, nil
}

type certificateResultContext struct {
	Domain            string
	CertificateID     string
	Source            model.CertificateSource
	AutoRenew         bool
	RenewBeforeDays   int
	ACMEAccountID     string
	DNSAccountID      string
	InstalledOnIssuer bool
	RequestedDNSNames []string
}

func certificateResultContextForJob(state model.State, job model.Job) (certificateResultContext, error) {
	switch job.Type {
	case protocol.JobApplyDomain:
		var spec applyDomainSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return certificateResultContext{}, err
		}
		if !spec.CaptureCertificate {
			return certificateResultContext{}, errors.New("unexpected certificate result for apply task")
		}
		domain, ok := state.Domains[spec.DomainID]
		if !ok {
			return certificateResultContext{}, errors.New("certificate result has no matching domain")
		}
		return certificateResultContext{
			Domain: domain.Name, CertificateID: domain.CertificateID, Source: model.CertificateLocal,
			RequestedDNSNames: []string{domain.Name},
			AutoRenew:         domain.AutoRenew, RenewBeforeDays: domain.RenewBeforeDays,
			ACMEAccountID: domain.ACMEAccountID, DNSAccountID: domain.DNSAccountID,
			InstalledOnIssuer: true,
		}, nil
	case protocol.JobIssueCertificate:
		if job.DomainID != "" {
			domain, ok := state.Domains[job.DomainID]
			if !ok {
				return certificateResultContext{}, errors.New("certificate result has no matching domain")
			}
			return certificateResultContext{
				Domain: domain.Name, CertificateID: domain.CertificateID, Source: model.CertificateACME,
				RequestedDNSNames: desiredNamesForDomain(state, domain),
				AutoRenew:         domain.AutoRenew, RenewBeforeDays: domain.RenewBeforeDays,
				ACMEAccountID: domain.ACMEAccountID, DNSAccountID: domain.DNSAccountID,
			}, nil
		}
		var spec issueCertificateSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return certificateResultContext{}, err
		}
		return certificateResultContext{
			Domain: spec.Domain, CertificateID: spec.CertificateID, Source: model.CertificateACME,
			RequestedDNSNames: spec.DNSNames,
			AutoRenew:         spec.AutoRenew, RenewBeforeDays: spec.RenewBeforeDays,
			ACMEAccountID: spec.ACMEAccountID, DNSAccountID: spec.DNSAccountID,
			InstalledOnIssuer: spec.Install,
		}, nil
	case protocol.JobCaptureCertificate:
		var spec captureCertificateSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return certificateResultContext{}, err
		}
		result := certificateResultContext{
			Domain: spec.Domain, CertificateID: spec.CertificateID, Source: model.CertificateLocal,
			AutoRenew: spec.AutoRenew, RenewBeforeDays: spec.RenewBeforeDays,
			ACMEAccountID: spec.ACMEAccountID, DNSAccountID: spec.DNSAccountID,
			InstalledOnIssuer: true,
		}
		if spec.DomainID != "" {
			domain, ok := state.Domains[spec.DomainID]
			if !ok {
				return certificateResultContext{}, errors.New("certificate result has no matching domain")
			}
			result.Domain = domain.Name
			result.CertificateID = domain.CertificateID
			result.AutoRenew = domain.AutoRenew
			result.RenewBeforeDays = domain.RenewBeforeDays
			result.ACMEAccountID = domain.ACMEAccountID
			result.DNSAccountID = domain.DNSAccountID
			result.RequestedDNSNames = []string{domain.Name}
		}
		return result, nil
	default:
		return certificateResultContext{}, fmt.Errorf("job type %s cannot return a certificate", job.Type)
	}
}

func ensureCertificateNames(actual, requested []string) error {
	actualSet := make(map[string]bool, len(actual))
	for _, value := range actual {
		actualSet[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range requested {
		value = strings.ToLower(strings.TrimSpace(value))
		if strings.HasPrefix(value, "*.") {
			if !actualSet[value] {
				return fmt.Errorf("missing %s", value)
			}
			continue
		}
		if !certutil.CoversHostname(actual, value) {
			return fmt.Errorf("missing %s", value)
		}
	}
	return nil
}

func (s *Server) completeSuccessfulJob(state *model.State, job model.Job, request protocol.JobResultRequest, prepared *model.Certificate) error {
	now := time.Now().UTC()
	if prepared != nil {
		state.Certificates[prepared.ID] = *prepared
	}
	switch job.Type {
	case protocol.JobIssueCertificate:
		if prepared == nil {
			return errors.New("ACME task returned no certificate")
		}
		if job.DomainID != "" {
			domain, ok := state.Domains[job.DomainID]
			if !ok {
				return errNotFound
			}
			domain.CertificateID = prepared.ID
			domain.CertificateMode = model.CertificateACME
			domain.LastError = ""
			applyJob, err := enqueueJob(state, domain.NodeID, domain.ID, protocol.JobApplyDomain, applyDomainSpec{DomainID: domain.ID, CertificateID: prepared.ID})
			if err != nil {
				return err
			}
			domain.LastJobID = applyJob.ID
			domain.UpdatedAt = now
			state.Domains[domain.ID] = domain
		} else {
			var spec issueCertificateSpec
			if err := json.Unmarshal(job.Payload, &spec); err != nil {
				return err
			}
			targets := append([]string(nil), spec.SyncNodeIDs...)
			if spec.Install {
				targets = appendUnique(targets, job.NodeID)
			}
			if err := enqueueCertificateSyncJobs(state, prepared.ID, prepared.Domain, targets); err != nil {
				return err
			}
		}
	case protocol.JobCaptureCertificate:
		if prepared == nil {
			return errors.New("capture task returned no certificate")
		}
		var spec captureCertificateSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return err
		}
		if job.DomainID != "" {
			domain, ok := state.Domains[job.DomainID]
			if !ok {
				return errNotFound
			}
			domain.CertificateID = prepared.ID
			domain.LastError = ""
			domain.UpdatedAt = now
			state.Domains[domain.ID] = domain
		}
		if err := enqueueCertificateSyncJobs(state, prepared.ID, prepared.Domain, spec.SyncNodeIDs); err != nil {
			return err
		}
	case protocol.JobApplyDomain:
		domain, ok := state.Domains[job.DomainID]
		if !ok {
			return errNotFound
		}
		if prepared != nil {
			domain.CertificateID = prepared.ID
		}
		domain.Enabled = true
		domain.Deleting = false
		domain.LastError = ""
		domain.UpdatedAt = now
		state.Domains[domain.ID] = domain
		certificateID := domain.CertificateID
		if certificateID != "" {
			certificate := state.Certificates[certificateID]
			certificate.DeployedNodeIDs = appendUnique(certificate.DeployedNodeIDs, domain.NodeID)
			certificate.UpdatedAt = now
			state.Certificates[certificate.ID] = certificate
			for _, nodeID := range domain.SyncNodeIDs {
				_, err := enqueueJob(state, nodeID, domain.ID, protocol.JobSyncCertificate, syncCertificateSpec{
					CertificateID: certificateID, Domain: domain.Name, ReloadNginx: true,
				})
				if err != nil {
					return err
				}
			}
		}
	case protocol.JobSyncCertificate:
		var spec syncCertificateSpec
		if err := json.Unmarshal(job.Payload, &spec); err != nil {
			return err
		}
		certificate, ok := state.Certificates[spec.CertificateID]
		if ok {
			certificate.DeployedNodeIDs = appendUnique(certificate.DeployedNodeIDs, job.NodeID)
			certificate.UpdatedAt = now
			state.Certificates[certificate.ID] = certificate
		}
	case protocol.JobDeleteDomain:
		delete(state.Domains, job.DomainID)
	}
	return nil
}

func restoreFailedDomainDeletion(state *model.State, job model.Job, message string, now time.Time) {
	if job.Type != protocol.JobDeleteDomain || job.DomainID == "" {
		return
	}
	domain, ok := state.Domains[job.DomainID]
	if !ok {
		return
	}
	domain.Deleting = false
	// A removed primary node leaves the domain intentionally disabled until an
	// administrator assigns a replacement. A failed delete on a live node still
	// restores the previous enabled state.
	domain.Enabled = domain.NodeID != ""
	domain.LastError = truncate(message, 2048)
	domain.UpdatedAt = now
	state.Domains[domain.ID] = domain
}

func enqueueCertificateSyncJobs(state *model.State, certificateID, domain string, nodeIDs []string) error {
	for _, nodeID := range nodeIDs {
		if _, err := enqueueJob(state, nodeID, "", protocol.JobSyncCertificate, syncCertificateSpec{
			CertificateID: certificateID, Domain: domain, ReloadNginx: true,
		}); err != nil {
			return err
		}
	}
	return nil
}

func applyNodeReport(node *model.Node, report protocol.NodeReport) {
	node.Hostname = truncate(strings.TrimSpace(report.Hostname), 255)
	node.IPAddresses = append([]string(nil), report.IPAddresses...)
	node.OS = truncate(report.OS, 64)
	node.OSName = truncate(report.OSName, 160)
	node.OSVersion = truncate(report.OSVersion, 64)
	node.Arch = truncate(report.Arch, 64)
	node.PackageManager = truncate(report.PackageManager, 16)
	node.ControllerInstalled = report.ControllerInstalled
	node.NginxVersion = truncate(report.NginxVersion, 256)
	node.NginxHealthy = report.NginxHealthy
	node.AgentVersion = truncate(report.AgentVersion, 64)
	node.Certificates = append([]model.CertificateMeta(nil), report.Certificates...)
	node.NginxSites = append([]model.NginxSiteMeta(nil), report.NginxSites...)
	node.LastError = truncate(report.LastError, 2048)
}

func (s *Server) reserveNodePoll(nodeID string) (time.Duration, bool) {
	now := s.nodePollNow()
	s.nodePollMu.Lock()
	defer s.nodePollMu.Unlock()
	if next := s.nodeNextPoll[nodeID]; now.Before(next) {
		return next.Sub(now), false
	}
	interval := s.config.PollAfter
	if interval < minimumNodePollInterval {
		interval = minimumNodePollInterval
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	s.nodeNextPoll[nodeID] = now.Add(interval)
	return 0, true
}

func validateNodeReport(report protocol.NodeReport) error {
	if len(report.IPAddresses) > maxReportedIPAddresses {
		return fmt.Errorf("too many IP addresses")
	}
	for _, address := range report.IPAddresses {
		if len(address) > 64 {
			return fmt.Errorf("IP address is too long")
		}
		if _, err := netip.ParseAddr(strings.TrimSpace(address)); err != nil {
			return fmt.Errorf("invalid IP address")
		}
	}
	if len(report.Certificates) > maxReportedCertificates {
		return fmt.Errorf("too many certificates")
	}
	for _, certificate := range report.Certificates {
		if len(certificate.Domain) > 253 || len(certificate.Path) > 1024 || len(certificate.Issuer) > 512 || len(certificate.Error) > 2048 {
			return fmt.Errorf("certificate metadata is too large")
		}
		if len(certificate.DNSNames) > maxReportedCertificateSANs {
			return fmt.Errorf("certificate contains too many names")
		}
		for _, name := range certificate.DNSNames {
			if len(name) > 253 {
				return fmt.Errorf("certificate name is too long")
			}
		}
	}
	if len(report.NginxSites) > maxReportedNginxSites {
		return fmt.Errorf("too many nginx sites")
	}
	for _, site := range report.NginxSites {
		if len(site.Domain) > 253 || len(site.ConfigPath) > 1024 || len(site.UpstreamHost) > 253 || len(site.CertificatePath) > 1024 {
			return fmt.Errorf("nginx site metadata is too large")
		}
	}
	return nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func safeJobMessage(message string) string {
	if strings.TrimSpace(message) == "" {
		return "节点任务执行成功"
	}
	return truncate(message, 256)
}

var errInvalidEnrollment = errors.New("invalid enrollment")
