package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/certutil"
	"github.com/yayitinyu/nginx-atlas/internal/id"
	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/nginxconfig"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

var (
	dnsProviderPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	credentialNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,127}$`)
)

type domainView struct {
	model.Domain
	NodeName          string     `json:"node_name"`
	NodeStatus        string     `json:"node_status"`
	CertificateIssuer string     `json:"certificate_issuer,omitempty"`
	CertificateExpiry *time.Time `json:"certificate_expiry,omitempty"`
	CertificateStatus string     `json:"certificate_status"`
	JobStatus         string     `json:"job_status,omitempty"`
}

type certificateView struct {
	ID                string                  `json:"id"`
	Domain            string                  `json:"domain"`
	Source            model.CertificateSource `json:"source"`
	Fingerprint       string                  `json:"fingerprint_sha256"`
	Issuer            string                  `json:"issuer"`
	SerialNumber      string                  `json:"serial_number"`
	NotBefore         time.Time               `json:"not_before"`
	NotAfter          time.Time               `json:"not_after"`
	DNSNames          []string                `json:"dns_names"`
	RequestedDNSNames []string                `json:"requested_dns_names"`
	AutoRenew         bool                    `json:"auto_renew"`
	RenewBeforeDays   int                     `json:"renew_before_days"`
	ACMEAccountID     string                  `json:"acme_account_id,omitempty"`
	DNSAccountID      string                  `json:"dns_account_id,omitempty"`
	IssuerNodeID      string                  `json:"issuer_node_id,omitempty"`
	DeployedNodeIDs   []string                `json:"deployed_node_ids"`
	DaysRemaining     int                     `json:"days_remaining"`
	Status            string                  `json:"status"`
	CreatedAt         time.Time               `json:"created_at"`
	UpdatedAt         time.Time               `json:"updated_at"`
}

type dnsAccountView struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Provider       string    `json:"provider"`
	CredentialKeys []string  `json:"credential_keys"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type dnsAccountRequest struct {
	Name            string            `json:"name"`
	Provider        string            `json:"provider"`
	Credentials     map[string]string `json:"credentials"`
	KeepCredentials bool              `json:"keep_credentials"`
}

type acmeAccountView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	DirectoryURL string    `json:"directory_url"`
	HasEAB       bool      `json:"has_eab"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	state := s.store.Snapshot()
	nodes := safeNodes(state)
	domains := domainViews(state)
	certificates := certificateViews(state)
	audit := state.Audit
	if len(audit) > 12 {
		audit = audit[:12]
	}
	jobs := make([]model.Job, 0, len(state.Jobs))
	pendingJobCount := 0
	for _, job := range state.Jobs {
		if jobNeedsAttention(state, job) {
			pendingJobCount++
		}
		job.Payload = nil
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
	if len(jobs) > 100 {
		jobs = jobs[:100]
	}
	settings := s.effectiveSettings(state)
	settings.RequestIP = s.clientIP(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes, "domains": domains, "certificates": certificates, "audit": audit, "jobs": jobs,
		"settings": settings, "pending_job_count": pendingJobCount, "server_time": time.Now().UTC(),
	})
}

func (s *Server) handleNodes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, safeNodes(s.store.Snapshot()))
}

func (s *Server) handleDomains(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, domainViews(s.store.Snapshot()))
}

func (s *Server) handleCertificates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, certificateViews(s.store.Snapshot()))
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 && value <= 500 {
			limit = value
		}
	}
	audit := s.store.Snapshot().Audit
	if len(audit) > limit {
		audit = audit[:limit]
	}
	writeJSON(w, http.StatusOK, audit)
}

func (s *Server) handleClearAudit(w http.ResponseWriter, _ *http.Request) {
	cleared := 0
	err := s.store.Update(func(state *model.State) error {
		cleared = len(state.Audit)
		state.Audit = []model.AuditEvent{}
		return nil
	})
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"cleared": cleared})
}

func (s *Server) handleRetryJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	retryID, err := id.New("job")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	var retried model.Job
	err = s.store.Update(func(state *model.State) error {
		failed, ok := state.Jobs[jobID]
		if !ok {
			return errNotFound
		}
		if failed.Status != model.JobFailed || failed.RetryJobID != "" {
			return errConflict
		}
		if node, ok := state.Nodes[failed.NodeID]; !ok || node.Status == model.NodeRevoked {
			return fmt.Errorf("%w: node", errNotFound)
		}
		retried = failed
		retried.ID = retryID
		retried.Status = model.JobQueued
		retried.Payload = append(json.RawMessage(nil), failed.Payload...)
		retried.Attempts = 0
		if retried.MaxAttempts < 1 {
			retried.MaxAttempts = 3
		}
		retried.Error = ""
		retried.CreatedAt = now
		retried.QueuedAt = &now
		retried.StartedAt = nil
		retried.FinishedAt = nil
		retried.RetryOfID = failed.ID
		retried.RetryJobID = ""
		if _, err := s.buildWireJob(retried, *state); err != nil {
			return err
		}
		failed.RetryJobID = retried.ID
		state.Jobs[failed.ID] = failed
		state.Jobs[retried.ID] = retried
		if domain, ok := state.Domains[retried.DomainID]; ok {
			domain.LastJobID = retried.ID
			domain.LastError = ""
			domain.UpdatedAt = now
			if retried.Type == protocol.JobDeleteDomain {
				domain.Deleting = true
				domain.Enabled = false
			}
			state.Domains[domain.ID] = domain
		}
		s.addAudit(state, "warning", "job.manual-retry", "失败任务已手动重试", retried.NodeID, retried.DomainID, retried.ID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "任务或节点不存在", "not_found", nil)
		return
	}
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "任务无法重复重试", "job_retry_conflict", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "任务依赖已失效，无法重试", "job_retry_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	retried.Payload = nil
	writeJSON(w, http.StatusAccepted, retried)
}

func (s *Server) handleClearPendingJobs(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	cleared := 0
	err := s.store.Update(func(state *model.State) error {
		removed := make(map[string]model.Job)
		for id, job := range state.Jobs {
			if job.Status == model.JobQueued || job.Status == model.JobFailed {
				removed[id] = job
			}
		}
		for id, job := range removed {
			delete(state.Jobs, id)
			cleared++
			if node, ok := state.Nodes[job.NodeID]; ok && node.RunningJobID == id {
				node.RunningJobID = ""
				state.Nodes[node.ID] = node
			}
		}
		for id, domain := range state.Domains {
			job, ok := removed[domain.LastJobID]
			if !ok {
				continue
			}
			domain.LastJobID = ""
			domain.LastError = ""
			domain.UpdatedAt = now
			if job.Type == protocol.JobDeleteDomain {
				domain.Deleting = false
				domain.Enabled = true
			}
			state.Domains[id] = domain
		}
		if cleared > 0 {
			s.addAudit(state, "warning", "jobs.cleared", "排队与失败任务已清除")
		}
		return nil
	})
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"cleared": cleared})
}

func jobNeedsAttention(state model.State, job model.Job) bool {
	if job.Status == model.JobQueued || job.Status == model.JobRunning {
		return true
	}
	if job.Status != model.JobFailed {
		return false
	}
	if job.RetryJobID == "" {
		return true
	}
	_, retryExists := state.Jobs[job.RetryJobID]
	return !retryExists
}

func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name       string `json:"name"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if len(request.Name) > 64 {
		writeError(w, http.StatusBadRequest, "节点名称需为 2–64 个字符", "invalid_node_name", nil)
		return
	}
	if request.TTLMinutes == 0 {
		request.TTLMinutes = 30
	}
	if request.TTLMinutes < 5 || request.TTLMinutes > 1440 {
		writeError(w, http.StatusBadRequest, "令牌有效期需为 5–1440 分钟", "invalid_ttl", nil)
		return
	}
	enrollmentID, err := id.New("enr")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	token, err := id.Token(32)
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(request.TTLMinutes) * time.Minute)
	hash := sha256.Sum256([]byte(token))
	err = s.store.Update(func(state *model.State) error {
		state.Enrollments[enrollmentID] = model.Enrollment{
			ID: enrollmentID, Name: request.Name, TokenHash: hex.EncodeToString(hash[:]),
			ExpiresAt: expiresAt, CreatedAt: now,
		}
		s.addAudit(state, "info", "node.enrollment.created", "已生成节点添加命令")
		return nil
	})
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	baseURL := s.publicURL(r)
	command := fmt.Sprintf("( tmp=$(mktemp) && trap 'rm -f -- \"$tmp\"' EXIT && chmod 600 \"$tmp\" && curl -fsSL %s -o \"$tmp\" && printf '%%s' %s | sudo bash \"$tmp\" agent --server %s --token-stdin )",
		shellQuote(strings.TrimRight(baseURL, "/")+"/install.sh"), shellQuote(token), shellQuote(baseURL))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": enrollmentID, "name": request.Name, "token": token, "expires_at": expiresAt, "command": command,
	})
}

func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	now := time.Now().UTC()
	err := s.store.Update(func(state *model.State) error {
		node, ok := state.Nodes[nodeID]
		if !ok || node.Status == model.NodeRevoked {
			return errNotFound
		}
		revokeNodeState(state, nodeID, now)
		s.addAudit(state, "warning", "node.revoked", "节点访问凭据已撤销", nodeID)
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

func (s *Server) handleRevokeNodes(w http.ResponseWriter, r *http.Request) {
	ids, ok := decodeBatchIDs(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	err := s.store.Update(func(state *model.State) error {
		for _, nodeID := range ids {
			node, exists := state.Nodes[nodeID]
			if !exists || node.Status == model.NodeRevoked {
				return errNotFound
			}
		}
		for _, nodeID := range ids {
			revokeNodeState(state, nodeID, now)
			s.addAudit(state, "warning", "node.revoked", "节点访问凭据已撤销", nodeID)
		}
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "所选节点不存在或已撤销", "not_found", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": len(ids)})
}

func (s *Server) handleDeleteCertificates(w http.ResponseWriter, r *http.Request) {
	ids, ok := decodeBatchIDs(w, r)
	if !ok {
		return
	}
	err := s.store.Update(func(state *model.State) error {
		selected := make(map[string]struct{}, len(ids))
		for _, certificateID := range ids {
			if _, exists := state.Certificates[certificateID]; !exists {
				return errNotFound
			}
			selected[certificateID] = struct{}{}
		}
		for _, domain := range state.Domains {
			if _, exists := selected[domain.CertificateID]; exists {
				return errConflict
			}
		}
		for certificateID := range selected {
			if hasActiveCertificateReference(state, certificateID) {
				return errConflict
			}
		}
		for _, certificateID := range ids {
			delete(state.Certificates, certificateID)
		}
		s.addAudit(state, "warning", "certificate.deleted", fmt.Sprintf("已移除 %d 张证书", len(ids)))
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "所选证书不存在", "not_found", nil)
		return
	}
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "所选证书仍被域名或执行中的任务使用", "certificate_in_use", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": len(ids)})
}

func decodeBatchIDs(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	var request struct {
		IDs []string `json:"ids"`
	}
	if !decodeJSON(w, r, &request) {
		return nil, false
	}
	if len(request.IDs) == 0 || len(request.IDs) > 100 {
		writeError(w, http.StatusBadRequest, "请选择 1–100 项", "invalid_selection", nil)
		return nil, false
	}
	seen := make(map[string]struct{}, len(request.IDs))
	ids := make([]string, 0, len(request.IDs))
	for _, raw := range request.IDs {
		value := strings.TrimSpace(raw)
		if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
			writeError(w, http.StatusBadRequest, "选择项无效", "invalid_selection", nil)
			return nil, false
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		ids = append(ids, value)
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "请选择至少一项", "invalid_selection", nil)
		return nil, false
	}
	return ids, true
}

func hasActiveCertificateReference(state *model.State, certificateID string) bool {
	for _, job := range state.Jobs {
		if job.Status != model.JobQueued && job.Status != model.JobRunning {
			continue
		}
		var reference struct {
			CertificateID string `json:"certificate_id"`
		}
		if json.Unmarshal(job.Payload, &reference) == nil && reference.CertificateID == certificateID {
			return true
		}
	}
	return false
}

type createDomainRequest struct {
	Domain                  string   `json:"domain"`
	NodeID                  string   `json:"node_id"`
	UpstreamHost            string   `json:"upstream_host"`
	UpstreamPort            int      `json:"upstream_port"`
	CertificateMode         string   `json:"certificate_mode"`
	CertificateID           string   `json:"certificate_id"`
	ACMEAccountID           string   `json:"acme_account_id"`
	DNSAccountID            string   `json:"dns_account_id"`
	AutoRenew               bool     `json:"auto_renew"`
	RenewBeforeDays         int      `json:"renew_before_days"`
	SyncNodeIDs             []string `json:"sync_node_ids"`
	CloudflareEnabled       bool     `json:"cloudflare_enabled"`
	CloudflareDNSAccountID  string   `json:"cloudflare_dns_account_id"`
	CloudflareProxied       bool     `json:"cloudflare_proxied"`
	CloudflareRecordType    string   `json:"cloudflare_record_type"`
	CloudflareRecordContent string   `json:"cloudflare_record_content"`
	NginxWebsocket          bool     `json:"nginx_websocket"`
	NginxHTTP2              bool     `json:"nginx_http2"`
	NginxGzip               bool     `json:"nginx_gzip"`
}

type updateDomainRequest struct {
	Domain                  string    `json:"domain"`
	NodeID                  string    `json:"node_id"`
	UpstreamHost            string    `json:"upstream_host"`
	UpstreamPort            int       `json:"upstream_port"`
	CertificateMode         string    `json:"certificate_mode"`
	CertificateID           *string   `json:"certificate_id"`
	ACMEAccountID           *string   `json:"acme_account_id"`
	DNSAccountID            *string   `json:"dns_account_id"`
	AutoRenew               *bool     `json:"auto_renew"`
	RenewBeforeDays         int       `json:"renew_before_days"`
	SyncNodeIDs             *[]string `json:"sync_node_ids"`
	CloudflareEnabled       *bool     `json:"cloudflare_enabled"`
	CloudflareDNSAccountID  *string   `json:"cloudflare_dns_account_id"`
	CloudflareProxied       *bool     `json:"cloudflare_proxied"`
	CloudflareRecordType    *string   `json:"cloudflare_record_type"`
	CloudflareRecordContent *string   `json:"cloudflare_record_content"`
	NginxWebsocket          *bool     `json:"nginx_websocket"`
	NginxHTTP2              *bool     `json:"nginx_http2"`
	NginxGzip               *bool     `json:"nginx_gzip"`
}

type applyDomainSpec struct {
	DomainID            string `json:"domain_id"`
	CertificateID       string `json:"certificate_id,omitempty"`
	UseLocalCertificate bool   `json:"use_local_certificate"`
	CaptureCertificate  bool   `json:"capture_certificate"`
	LocalCertificateDir string `json:"local_certificate_dir,omitempty"`
	ReplaceConfigPath   string `json:"replace_config_path,omitempty"`
}

type issueCertificateSpec struct {
	DomainID        string   `json:"domain_id,omitempty"`
	Domain          string   `json:"domain,omitempty"`
	DNSNames        []string `json:"dns_names,omitempty"`
	CertificateID   string   `json:"certificate_id,omitempty"`
	ACMEAccountID   string   `json:"acme_account_id,omitempty"`
	DNSAccountID    string   `json:"dns_account_id,omitempty"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewBeforeDays int      `json:"renew_before_days"`
	Install         bool     `json:"install"`
	ReloadNginx     bool     `json:"reload_nginx"`
	SyncNodeIDs     []string `json:"sync_node_ids,omitempty"`
}

type captureCertificateSpec struct {
	DomainID        string   `json:"domain_id,omitempty"`
	Domain          string   `json:"domain"`
	CertificateID   string   `json:"certificate_id,omitempty"`
	ACMEAccountID   string   `json:"acme_account_id,omitempty"`
	DNSAccountID    string   `json:"dns_account_id,omitempty"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewBeforeDays int      `json:"renew_before_days"`
	SyncNodeIDs     []string `json:"sync_node_ids,omitempty"`
}

type syncCertificateSpec struct {
	CertificateID string `json:"certificate_id"`
	Domain        string `json:"domain"`
	ReloadNginx   bool   `json:"reload_nginx"`
}

type deleteDomainSpec struct {
	DomainID          string `json:"domain_id"`
	Domain            string `json:"domain"`
	RestoreConfigPath string `json:"restore_config_path,omitempty"`
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var request createDomainRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Domain = strings.ToLower(strings.TrimSpace(request.Domain))
	request.UpstreamHost = strings.ToLower(strings.TrimSpace(request.UpstreamHost))
	if err := nginxconfig.ValidateSite(nginxconfig.Site{
		Domain: request.Domain, UpstreamHost: request.UpstreamHost, UpstreamPort: request.UpstreamPort,
		TLS: request.CertificateMode != "none", CertificateDir: "/etc/ssl/" + request.Domain,
	}); err != nil {
		writeError(w, http.StatusBadRequest, "域名或上游配置无效", "invalid_domain", map[string]string{"reason": err.Error()})
		return
	}
	if request.RenewBeforeDays == 0 {
		request.RenewBeforeDays = 30
	}
	if request.RenewBeforeDays < 7 || request.RenewBeforeDays > 60 {
		writeError(w, http.StatusBadRequest, "自动续期阈值需为 7–60 天", "invalid_renewal_window", nil)
		return
	}
	dependencies := s.store.Snapshot()
	if request.CertificateMode == "acme" && request.ACMEAccountID == "" {
		request.ACMEAccountID = firstACMEAccountID(dependencies)
	}
	if request.CertificateMode == "acme" && request.DNSAccountID == "" {
		request.DNSAccountID = firstDNSAccountID(dependencies)
	}
	var source model.CertificateSource
	switch request.CertificateMode {
	case "local":
		source = model.CertificateLocal
	case "upload":
		source = model.CertificateUpload
		if request.CertificateID == "" {
			writeError(w, http.StatusBadRequest, "请选择已上传的证书", "certificate_required", nil)
			return
		}
	case "acme":
		source = model.CertificateACME
		if request.ACMEAccountID == "" || request.DNSAccountID == "" {
			writeError(w, http.StatusBadRequest, "请选择 DNS 与 ACME 账户", "acme_accounts_required", nil)
			return
		}
	case "none":
		source = ""
		request.AutoRenew = false
		request.ACMEAccountID = ""
		request.DNSAccountID = ""
	default:
		writeError(w, http.StatusBadRequest, "证书来源无效", "invalid_certificate_mode", nil)
		return
	}
	if request.AutoRenew && source != "" && (request.ACMEAccountID == "" || request.DNSAccountID == "") {
		writeError(w, http.StatusBadRequest, "自动续期需要 DNS 与 ACME 账户", "renewal_accounts_required", nil)
		return
	}
	if request.CloudflareEnabled {
		cloudflare, err := s.upsertCloudflareRecord(r.Context(), dependencies, request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "无法创建或更新 Cloudflare DNS 记录", "cloudflare_record_unavailable", map[string]string{"reason": err.Error()})
			return
		}
		request.CloudflareDNSAccountID = cloudflare.DNSAccountID
		request.CloudflareRecordType = cloudflare.RecordType
		request.CloudflareRecordContent = cloudflare.Content
		request.CloudflareProxied = cloudflare.Proxied
	}
	domainID, err := id.New("dom")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	var created model.Domain
	err = s.store.Update(func(state *model.State) error {
		if node, ok := state.Nodes[request.NodeID]; !ok || node.Status == model.NodeRevoked {
			return fmt.Errorf("%w: node", errNotFound)
		}
		for _, domain := range state.Domains {
			if domain.Name == request.Domain {
				return errConflict
			}
		}
		if request.CertificateID != "" {
			cert, ok := state.Certificates[request.CertificateID]
			if !ok {
				return fmt.Errorf("%w: certificate", errNotFound)
			}
			if cert.Domain != request.Domain && !certutil.CoversHostname(cert.DNSNames, request.Domain) {
				return errors.New("selected certificate does not cover the domain")
			}
		}
		if source == model.CertificateACME || request.AutoRenew {
			if _, ok := state.ACMEAccounts[request.ACMEAccountID]; !ok {
				return fmt.Errorf("%w: acme", errNotFound)
			}
			if _, ok := state.DNSAccounts[request.DNSAccountID]; !ok {
				return fmt.Errorf("%w: dns", errNotFound)
			}
		}
		if request.CertificateID != "" && request.AutoRenew {
			certificate := state.Certificates[request.CertificateID]
			certificate.AutoRenew = true
			certificate.RenewBeforeDays = request.RenewBeforeDays
			certificate.ACMEAccountID = request.ACMEAccountID
			certificate.DNSAccountID = request.DNSAccountID
			certificate.UpdatedAt = now
			state.Certificates[certificate.ID] = certificate
		}
		syncNodeIDs, err := validateNodeIDs(state, request.SyncNodeIDs, request.NodeID)
		if err != nil {
			return err
		}
		created = model.Domain{
			ID: domainID, Name: request.Domain, NodeID: request.NodeID,
			UpstreamHost: request.UpstreamHost, UpstreamPort: request.UpstreamPort,
			CertificateID: request.CertificateID, CertificateMode: source,
			ACMEAccountID: request.ACMEAccountID, DNSAccountID: request.DNSAccountID,
			AutoRenew: request.AutoRenew, RenewBeforeDays: request.RenewBeforeDays,
			SyncNodeIDs: syncNodeIDs, CreatedAt: now, UpdatedAt: now,
			CloudflareEnabled: request.CloudflareEnabled, CloudflareDNSAccountID: request.CloudflareDNSAccountID,
			CloudflareProxied: request.CloudflareProxied, CloudflareRecordType: request.CloudflareRecordType,
			CloudflareRecordContent: request.CloudflareRecordContent,
			NginxWebsocket:          request.NginxWebsocket, NginxHTTP2: request.NginxHTTP2, NginxGzip: request.NginxGzip,
		}
		state.Domains[domainID] = created
		var job model.Job
		if source == model.CertificateACME {
			job, err = enqueueJob(state, request.NodeID, domainID, protocol.JobIssueCertificate, issueCertificateSpec{DomainID: domainID, DNSNames: []string{request.Domain}})
		} else {
			job, err = enqueueJob(state, request.NodeID, domainID, protocol.JobApplyDomain, applyDomainSpec{
				DomainID: domainID, CertificateID: request.CertificateID,
				UseLocalCertificate: source == model.CertificateLocal, CaptureCertificate: source == model.CertificateLocal,
			})
		}
		if err != nil {
			return err
		}
		created.LastJobID = job.ID
		state.Domains[domainID] = created
		s.addAudit(state, "info", "domain.created", "域名已加入部署队列", request.NodeID, domainID, job.ID)
		return nil
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "域名已存在", "domain_exists", nil)
		return
	}
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusBadRequest, "节点、证书或账户不存在", "dependency_not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法创建域名", "invalid_domain_request", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, created)
}

func firstACMEAccountID(state model.State) string {
	ids := make([]string, 0, len(state.ACMEAccounts))
	for id := range state.ACMEAccounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func firstDNSAccountID(state model.State) string {
	ids := make([]string, 0, len(state.DNSAccounts))
	for id := range state.DNSAccounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func (s *Server) handleAdoptDomain(w http.ResponseWriter, r *http.Request) {
	var request struct {
		NodeID     string `json:"node_id"`
		Domain     string `json:"domain"`
		ConfigPath string `json:"config_path"`
		Takeover   bool   `json:"takeover"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Domain = strings.ToLower(strings.TrimSpace(request.Domain))
	request.ConfigPath = strings.TrimSpace(request.ConfigPath)
	if _, err := nginxconfig.ConfigFileName(request.Domain); err != nil || len(request.ConfigPath) > 1024 || (request.Takeover && !validReportedTakeoverPath(request.ConfigPath)) {
		writeError(w, http.StatusBadRequest, "节点域名或配置路径无效", "invalid_discovered_domain", nil)
		return
	}
	domainID, err := id.New("dom")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	var adopted model.Domain
	err = s.store.Update(func(state *model.State) error {
		node, ok := state.Nodes[request.NodeID]
		if !ok || node.Status == model.NodeRevoked {
			return fmt.Errorf("%w: node", errNotFound)
		}
		var discovered model.NginxSiteMeta
		found := false
		for _, site := range node.NginxSites {
			if site.Domain == request.Domain && (request.ConfigPath == "" || site.ConfigPath == request.ConfigPath) {
				discovered = site
				found = true
				break
			}
		}
		if !found {
			return errors.New("node has not reported this Nginx server block")
		}
		localCertDir := localCertificateDirFromSite(discovered)
		if request.Takeover {
			if discovered.ManagedByAtlas {
				return errors.New("the discovered rule is already managed by Atlas")
			}
			if err := nginxconfig.ValidateSite(nginxconfig.Site{
				Domain: request.Domain, UpstreamHost: discovered.UpstreamHost, UpstreamPort: discovered.UpstreamPort,
				TLS: discovered.TLS, CertificateDir: localCertDir,
			}); err != nil {
				return fmt.Errorf("the discovered rule cannot be safely rendered: %w", err)
			}
			if discovered.TLS && !nodeHasValidCertificate(node, request.Domain) {
				return errors.New("a valid certificate covering this domain is required before takeover (shared wildcard directories are supported)")
			}
		}
		for _, domain := range state.Domains {
			if domain.Name == request.Domain {
				return errConflict
			}
		}
		var source model.CertificateSource
		if discovered.TLS {
			source = model.CertificateLocal
		}
		adopted = model.Domain{
			ID: domainID, Name: request.Domain, NodeID: request.NodeID,
			UpstreamHost: discovered.UpstreamHost, UpstreamPort: discovered.UpstreamPort,
			CertificateMode: source, RenewBeforeDays: 30, Enabled: true,
			ObservedOnly: !request.Takeover, TakenOver: request.Takeover,
			ConfigPath: discovered.ConfigPath, CreatedAt: now, UpdatedAt: now,
		}
		state.Domains[adopted.ID] = adopted
		if request.Takeover {
			job, err := enqueueJob(state, node.ID, adopted.ID, protocol.JobApplyDomain, applyDomainSpec{
				DomainID: adopted.ID, UseLocalCertificate: discovered.TLS, CaptureCertificate: discovered.TLS,
				LocalCertificateDir: localCertDir, ReplaceConfigPath: discovered.ConfigPath,
			})
			if err != nil {
				return err
			}
			adopted.LastJobID = job.ID
			state.Domains[adopted.ID] = adopted
		} else if discovered.TLS && nodeHasValidCertificate(node, request.Domain) {
			job, err := enqueueJob(state, node.ID, adopted.ID, protocol.JobCaptureCertificate, captureCertificateSpec{
				DomainID: adopted.ID, Domain: adopted.Name, RenewBeforeDays: 30,
			})
			if err != nil {
				return err
			}
			adopted.LastJobID = job.ID
			state.Domains[adopted.ID] = adopted
		}
		if request.Takeover {
			s.addAudit(state, "warning", "domain.takeover.queued", "现有 Nginx 规则接管任务已加入队列；原配置将先备份", node.ID, adopted.ID, adopted.LastJobID)
		} else {
			s.addAudit(state, "info", "domain.observation.adopted", "已开始监控节点现有 Nginx 域名；原配置未修改", node.ID, adopted.ID, adopted.LastJobID)
		}
		return nil
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "域名已在管理列表中", "domain_exists", nil)
		return
	}
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusBadRequest, "节点不存在", "dependency_not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法接管节点域名", "adopt_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	for _, view := range domainViews(s.store.Snapshot()) {
		if view.ID == adopted.ID {
			writeJSON(w, http.StatusCreated, view)
			return
		}
	}
	writeJSON(w, http.StatusCreated, adopted)
}

func validReportedTakeoverPath(value string) bool {
	cleaned := path.Clean(strings.TrimSpace(value))
	return strings.HasPrefix(cleaned, "/etc/nginx/conf.d/") ||
		strings.HasPrefix(cleaned, "/etc/nginx/sites-enabled/")
}

func nodeHasValidCertificate(node model.Node, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, certificate := range node.Certificates {
		if certificate.Error != "" {
			continue
		}
		if certificate.Domain == domain || certutil.CoversHostname(certificate.DNSNames, domain) {
			return true
		}
	}
	// Fall back to a site-reported certificate path. Inventory may list the
	// wildcard leaf under a different directory name than the vhost domain.
	for _, site := range node.NginxSites {
		if site.Domain != domain || !site.TLS {
			continue
		}
		if strings.TrimSpace(site.CertificatePath) != "" {
			return true
		}
	}
	return false
}

// localCertificateDirFromSite returns the directory that should hold
// fullchain.pem / privkey.pem for a discovered site. Shared wildcard certs
// (e.g. /etc/ssl/suimori.com/fullchain.pem for haru.suimori.com) keep their
// real directory instead of assuming /etc/ssl/<vhost>.
func localCertificateDirFromSite(site model.NginxSiteMeta) string {
	if certPath := strings.TrimSpace(site.CertificatePath); certPath != "" {
		dir := path.Dir(path.Clean(certPath))
		if path.IsAbs(dir) && dir != "/" && dir != "." {
			return dir
		}
	}
	if site.TLS && site.Domain != "" {
		return "/etc/ssl/" + strings.ToLower(strings.TrimSpace(site.Domain))
	}
	return ""
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	domainID := r.PathValue("id")
	queued := true
	err := s.store.Update(func(state *model.State) error {
		domain, ok := state.Domains[domainID]
		if !ok {
			return errNotFound
		}
		if domain.ObservedOnly {
			queued = false
			delete(state.Domains, domain.ID)
			s.addAudit(state, "info", "domain.observation.removed", "已停止管理节点现有域名；原 Nginx 配置未修改", domain.NodeID, domain.ID)
			return nil
		}
		node, nodeExists := state.Nodes[domain.NodeID]
		if domain.NodeID == "" || !nodeExists || node.Status == model.NodeRevoked {
			queued = false
			delete(state.Domains, domain.ID)
			s.addAudit(state, "warning", "domain.orphan.removed", "已移除失联节点的域名记录；未修改节点上的 Nginx 配置", domain.NodeID, domain.ID)
			return nil
		}
		if domainIsDeleting(*state, domain) {
			return errConflict
		}
		restorePath := ""
		if domain.TakenOver {
			restorePath = domain.ConfigPath
		}
		job, err := enqueueJob(state, domain.NodeID, domain.ID, protocol.JobDeleteDomain, deleteDomainSpec{DomainID: domain.ID, Domain: domain.Name, RestoreConfigPath: restorePath})
		if err != nil {
			return err
		}
		domain.Enabled = false
		domain.Deleting = true
		domain.LastJobID = job.ID
		domain.UpdatedAt = time.Now().UTC()
		state.Domains[domain.ID] = domain
		s.addAudit(state, "warning", "domain.delete.queued", "域名移除任务已加入队列", domain.NodeID, domain.ID, job.ID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "域名不存在", "not_found", nil)
		return
	}
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "域名正在删除", "delete_in_progress", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": queued})
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	domainID := r.PathValue("id")
	var update updateDomainRequest
	if !decodeJSON(w, r, &update) {
		return
	}
	snapshot := s.store.Snapshot()
	existing, ok := snapshot.Domains[domainID]
	if !ok {
		writeError(w, http.StatusNotFound, "域名不存在", "not_found", nil)
		return
	}
	request := createDomainRequest{
		Domain:                  update.Domain,
		NodeID:                  update.NodeID,
		UpstreamHost:            update.UpstreamHost,
		UpstreamPort:            update.UpstreamPort,
		CertificateMode:         update.CertificateMode,
		RenewBeforeDays:         update.RenewBeforeDays,
		SyncNodeIDs:             append([]string{}, existing.SyncNodeIDs...),
		CloudflareEnabled:       existing.CloudflareEnabled,
		CloudflareDNSAccountID:  existing.CloudflareDNSAccountID,
		CloudflareProxied:       existing.CloudflareProxied,
		CloudflareRecordType:    existing.CloudflareRecordType,
		CloudflareRecordContent: existing.CloudflareRecordContent,
		NginxWebsocket:          existing.NginxWebsocket,
		NginxHTTP2:              existing.NginxHTTP2,
		NginxGzip:               existing.NginxGzip,
	}
	if update.CertificateID != nil {
		request.CertificateID = strings.TrimSpace(*update.CertificateID)
	} else if update.CertificateMode == "" || update.CertificateMode == string(existing.CertificateMode) {
		request.CertificateID = existing.CertificateID
	}
	if update.ACMEAccountID != nil {
		request.ACMEAccountID = strings.TrimSpace(*update.ACMEAccountID)
	} else {
		request.ACMEAccountID = existing.ACMEAccountID
	}
	if update.DNSAccountID != nil {
		request.DNSAccountID = strings.TrimSpace(*update.DNSAccountID)
	} else {
		request.DNSAccountID = existing.DNSAccountID
	}
	request.AutoRenew = existing.AutoRenew
	if update.AutoRenew != nil {
		request.AutoRenew = *update.AutoRenew
	}
	if update.SyncNodeIDs != nil {
		request.SyncNodeIDs = append([]string{}, (*update.SyncNodeIDs)...)
	}
	if update.CloudflareEnabled != nil {
		request.CloudflareEnabled = *update.CloudflareEnabled
	}
	if update.CloudflareDNSAccountID != nil {
		request.CloudflareDNSAccountID = strings.TrimSpace(*update.CloudflareDNSAccountID)
	}
	if update.CloudflareProxied != nil {
		request.CloudflareProxied = *update.CloudflareProxied
	}
	if update.CloudflareRecordType != nil {
		request.CloudflareRecordType = strings.TrimSpace(*update.CloudflareRecordType)
	}
	if update.CloudflareRecordContent != nil {
		request.CloudflareRecordContent = strings.TrimSpace(*update.CloudflareRecordContent)
	}
	if update.NginxWebsocket != nil {
		request.NginxWebsocket = *update.NginxWebsocket
	}
	if update.NginxHTTP2 != nil {
		request.NginxHTTP2 = *update.NginxHTTP2
	}
	if update.NginxGzip != nil {
		request.NginxGzip = *update.NginxGzip
	}

	request.Domain = strings.ToLower(strings.TrimSpace(request.Domain))
	if request.Domain == "" {
		request.Domain = existing.Name
	}
	if request.Domain != existing.Name {
		writeError(w, http.StatusBadRequest, "域名不可在编辑时更改", "domain_immutable", nil)
		return
	}
	if request.NodeID == "" {
		request.NodeID = existing.NodeID
	}
	request.UpstreamHost = strings.ToLower(strings.TrimSpace(request.UpstreamHost))
	if request.UpstreamHost == "" {
		request.UpstreamHost = existing.UpstreamHost
	}
	if request.UpstreamPort == 0 {
		request.UpstreamPort = existing.UpstreamPort
	}
	if request.CertificateMode == "" {
		request.CertificateMode = string(existing.CertificateMode)
		if request.CertificateMode == "" {
			request.CertificateMode = "none"
		}
	}
	if request.RenewBeforeDays == 0 {
		request.RenewBeforeDays = normalizeRenewBeforeDays(existing.RenewBeforeDays)
	}
	if request.RenewBeforeDays < 7 || request.RenewBeforeDays > 60 {
		writeError(w, http.StatusBadRequest, "自动续期阈值需为 7–60 天", "invalid_renewal_window", nil)
		return
	}

	var source model.CertificateSource
	switch request.CertificateMode {
	case "local":
		source = model.CertificateLocal
	case "upload":
		source = model.CertificateUpload
		if request.CertificateID == "" && existing.CertificateMode == model.CertificateUpload {
			request.CertificateID = existing.CertificateID
		}
		if request.CertificateID == "" {
			writeError(w, http.StatusBadRequest, "请选择已上传的证书", "certificate_required", nil)
			return
		}
	case "acme":
		source = model.CertificateACME
	case "none":
		request.AutoRenew = false
		request.ACMEAccountID = ""
		request.DNSAccountID = ""
	default:
		writeError(w, http.StatusBadRequest, "证书来源无效", "invalid_certificate_mode", nil)
		return
	}
	if source == model.CertificateACME || request.AutoRenew {
		if request.ACMEAccountID == "" {
			request.ACMEAccountID = firstACMEAccountID(snapshot)
		}
		if request.DNSAccountID == "" {
			request.DNSAccountID = firstDNSAccountID(snapshot)
		}
		if request.ACMEAccountID == "" || request.DNSAccountID == "" {
			writeError(w, http.StatusBadRequest, "自动签发需要 DNS 与 ACME 账户", "acme_accounts_required", nil)
			return
		}
	} else {
		request.ACMEAccountID = ""
		request.DNSAccountID = ""
	}
	if err := nginxconfig.ValidateSite(nginxconfig.Site{
		Domain: request.Domain, UpstreamHost: request.UpstreamHost, UpstreamPort: request.UpstreamPort,
		TLS: source != "", CertificateDir: "/etc/ssl/" + request.Domain,
	}); err != nil {
		writeError(w, http.StatusBadRequest, "域名或上游配置无效", "invalid_domain", map[string]string{"reason": err.Error()})
		return
	}
	if request.CloudflareEnabled {
		cloudflare, err := s.upsertCloudflareRecord(r.Context(), snapshot, request)
		if err != nil {
			writeError(w, http.StatusBadRequest, "无法创建或更新 Cloudflare DNS 记录", "cloudflare_record_unavailable", map[string]string{"reason": err.Error()})
			return
		}
		request.CloudflareDNSAccountID = cloudflare.DNSAccountID
		request.CloudflareRecordType = cloudflare.RecordType
		request.CloudflareRecordContent = cloudflare.Content
		request.CloudflareProxied = cloudflare.Proxied
	}

	var updated model.Domain
	err := s.store.Update(func(state *model.State) error {
		domain, ok := state.Domains[domainID]
		if !ok {
			return errNotFound
		}
		if node, ok := state.Nodes[request.NodeID]; !ok || node.Status == model.NodeRevoked {
			return fmt.Errorf("%w: node", errNotFound)
		}
		certificateID := ""
		if source == model.CertificateUpload {
			certificateID = request.CertificateID
		} else if source == model.CertificateACME && domain.CertificateMode == model.CertificateACME {
			if cert, ok := state.Certificates[domain.CertificateID]; ok && (cert.Domain == domain.Name || certutil.CoversHostname(cert.DNSNames, domain.Name)) {
				certificateID = cert.ID
			}
		} else if source == model.CertificateLocal {
			if _, ok := state.Certificates[domain.CertificateID]; ok {
				certificateID = domain.CertificateID
			}
		}
		if certificateID != "" {
			cert, ok := state.Certificates[certificateID]
			if !ok {
				return fmt.Errorf("%w: certificate", errNotFound)
			}
			if cert.Domain != domain.Name && !certutil.CoversHostname(cert.DNSNames, domain.Name) {
				return errors.New("selected certificate does not cover the domain")
			}
		}
		if source == model.CertificateACME || request.AutoRenew {
			if _, ok := state.ACMEAccounts[request.ACMEAccountID]; !ok {
				return fmt.Errorf("%w: acme", errNotFound)
			}
			if _, ok := state.DNSAccounts[request.DNSAccountID]; !ok {
				return fmt.Errorf("%w: dns", errNotFound)
			}
		}
		syncNodeIDs, err := validateNodeIDs(state, request.SyncNodeIDs, request.NodeID)
		if err != nil {
			return err
		}
		domain.NodeID = request.NodeID
		domain.UpstreamHost = request.UpstreamHost
		domain.UpstreamPort = request.UpstreamPort
		domain.CertificateID = certificateID
		domain.CertificateMode = source
		domain.ACMEAccountID = request.ACMEAccountID
		domain.DNSAccountID = request.DNSAccountID
		domain.AutoRenew = request.AutoRenew
		domain.RenewBeforeDays = request.RenewBeforeDays
		domain.SyncNodeIDs = syncNodeIDs
		domain.CloudflareEnabled = request.CloudflareEnabled
		if request.CloudflareEnabled {
			domain.CloudflareDNSAccountID = request.CloudflareDNSAccountID
			domain.CloudflareProxied = request.CloudflareProxied
			domain.CloudflareRecordType = request.CloudflareRecordType
			domain.CloudflareRecordContent = request.CloudflareRecordContent
		} else {
			domain.CloudflareDNSAccountID = ""
			domain.CloudflareProxied = false
			domain.CloudflareRecordType = ""
			domain.CloudflareRecordContent = ""
		}
		domain.NginxWebsocket = request.NginxWebsocket
		domain.NginxHTTP2 = request.NginxHTTP2
		domain.NginxGzip = request.NginxGzip
		domain.Enabled = true
		domain.Deleting = false
		domain.UpdatedAt = time.Now().UTC()
		if certificateID != "" && request.AutoRenew {
			certificate := state.Certificates[certificateID]
			certificate.AutoRenew = true
			certificate.RenewBeforeDays = request.RenewBeforeDays
			certificate.ACMEAccountID = request.ACMEAccountID
			certificate.DNSAccountID = request.DNSAccountID
			certificate.UpdatedAt = domain.UpdatedAt
			state.Certificates[certificate.ID] = certificate
		}

		if !domain.ObservedOnly {
			var job model.Job
			if source == model.CertificateACME && certificateID == "" {
				job, err = enqueueJob(state, domain.NodeID, domain.ID, protocol.JobIssueCertificate, issueCertificateSpec{DomainID: domain.ID, DNSNames: []string{domain.Name}})
			} else {
				jobCertificateID := ""
				if source == model.CertificateUpload || source == model.CertificateACME {
					jobCertificateID = certificateID
				}
				job, err = enqueueJob(state, domain.NodeID, domain.ID, protocol.JobApplyDomain, applyDomainSpec{
					DomainID: domain.ID, CertificateID: jobCertificateID,
					UseLocalCertificate: source == model.CertificateLocal, CaptureCertificate: source == model.CertificateLocal,
				})
			}
			if err != nil {
				return err
			}
			domain.LastJobID = job.ID
		}
		state.Domains[domain.ID] = domain
		updated = domain
		s.addAudit(state, "info", "domain.updated", "域名配置已更新并加入部署队列", domain.NodeID, domain.ID, domain.LastJobID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "域名不存在", "not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法更新域名", "invalid_domain_update", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

type certificateAutomationRequest struct {
	Domain          string   `json:"domain"`
	DNSNames        []string `json:"dns_names"`
	NodeID          string   `json:"node_id"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewBeforeDays int      `json:"renew_before_days"`
	ACMEAccountID   string   `json:"acme_account_id"`
	DNSAccountID    string   `json:"dns_account_id"`
	SyncNodeIDs     []string `json:"sync_node_ids"`
}

func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	var request certificateAutomationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Domain = strings.ToLower(strings.TrimSpace(request.Domain))
	if _, err := nginxconfig.ConfigFileName(request.Domain); err != nil {
		writeError(w, http.StatusBadRequest, "域名无效", "invalid_domain", nil)
		return
	}
	dnsNames, err := normalizeCertificateNames(request.Domain, request.DNSNames)
	if err != nil {
		writeError(w, http.StatusBadRequest, "证书域名列表无效", "invalid_dns_names", map[string]string{"reason": err.Error()})
		return
	}
	request.DNSNames = dnsNames
	request.RenewBeforeDays = normalizeRenewBeforeDays(request.RenewBeforeDays)
	if request.RenewBeforeDays < 7 || request.RenewBeforeDays > 60 {
		writeError(w, http.StatusBadRequest, "自动签发需要有效续期窗口", "invalid_automation", nil)
		return
	}
	var job model.Job
	err = s.store.Update(func(state *model.State) error {
		if request.ACMEAccountID == "" {
			request.ACMEAccountID = firstACMEAccountID(*state)
		}
		if request.DNSAccountID == "" {
			request.DNSAccountID = firstDNSAccountID(*state)
		}
		if node, ok := state.Nodes[request.NodeID]; !ok || node.Status == model.NodeRevoked {
			return fmt.Errorf("%w: node", errNotFound)
		}
		if _, ok := state.ACMEAccounts[request.ACMEAccountID]; !ok {
			return fmt.Errorf("%w: acme", errNotFound)
		}
		if _, ok := state.DNSAccounts[request.DNSAccountID]; !ok {
			return fmt.Errorf("%w: dns", errNotFound)
		}
		syncNodeIDs, err := validateNodeIDs(state, request.SyncNodeIDs, request.NodeID)
		if err != nil {
			return err
		}
		certificateID := certificateIDForDomain(*state, request.Domain)
		job, err = enqueueJob(state, request.NodeID, "", protocol.JobIssueCertificate, issueCertificateSpec{
			Domain: request.Domain, DNSNames: request.DNSNames, CertificateID: certificateID,
			ACMEAccountID: request.ACMEAccountID, DNSAccountID: request.DNSAccountID,
			AutoRenew: request.AutoRenew, RenewBeforeDays: request.RenewBeforeDays,
			Install: true, ReloadNginx: true, SyncNodeIDs: syncNodeIDs,
		})
		if err != nil {
			return err
		}
		s.addAudit(state, "info", "certificate.issue.queued", "独立证书签发任务已加入队列", request.NodeID, "", job.ID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusBadRequest, "节点、DNS 或 ACME 账户不存在", "dependency_not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法创建签发任务", "issuance_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleImportCertificate(w http.ResponseWriter, r *http.Request) {
	var request certificateAutomationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Domain = strings.ToLower(strings.TrimSpace(request.Domain))
	if _, err := nginxconfig.ConfigFileName(request.Domain); err != nil {
		writeError(w, http.StatusBadRequest, "域名无效", "invalid_domain", nil)
		return
	}
	request.RenewBeforeDays = normalizeRenewBeforeDays(request.RenewBeforeDays)
	if request.RenewBeforeDays < 7 || request.RenewBeforeDays > 60 {
		writeError(w, http.StatusBadRequest, "自动续期阈值需为 7–60 天", "invalid_renewal_window", nil)
		return
	}
	var job model.Job
	err := s.store.Update(func(state *model.State) error {
		node, ok := state.Nodes[request.NodeID]
		if !ok || node.Status == model.NodeRevoked {
			return fmt.Errorf("%w: node", errNotFound)
		}
		found := false
		for _, meta := range node.Certificates {
			if meta.Domain == request.Domain && meta.KeyMatches && meta.Error == "" {
				found = true
				break
			}
		}
		if !found {
			return errors.New("node has not reported a valid certificate for this domain")
		}
		if request.AutoRenew {
			if request.ACMEAccountID == "" {
				request.ACMEAccountID = firstACMEAccountID(*state)
			}
			if request.DNSAccountID == "" {
				request.DNSAccountID = firstDNSAccountID(*state)
			}
			if _, ok := state.ACMEAccounts[request.ACMEAccountID]; !ok {
				return fmt.Errorf("%w: acme", errNotFound)
			}
			if _, ok := state.DNSAccounts[request.DNSAccountID]; !ok {
				return fmt.Errorf("%w: dns", errNotFound)
			}
		} else {
			request.ACMEAccountID = ""
			request.DNSAccountID = ""
		}
		syncNodeIDs, err := validateNodeIDs(state, request.SyncNodeIDs, request.NodeID)
		if err != nil {
			return err
		}
		job, err = enqueueJob(state, request.NodeID, "", protocol.JobCaptureCertificate, captureCertificateSpec{
			Domain: request.Domain, CertificateID: certificateIDForDomain(*state, request.Domain),
			ACMEAccountID: request.ACMEAccountID, DNSAccountID: request.DNSAccountID,
			AutoRenew: request.AutoRenew, RenewBeforeDays: request.RenewBeforeDays, SyncNodeIDs: syncNodeIDs,
		})
		if err != nil {
			return err
		}
		s.addAudit(state, "info", "certificate.capture.queued", "节点现有证书接管任务已加入队列", request.NodeID, "", job.ID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusBadRequest, "节点、DNS 或 ACME 账户不存在", "dependency_not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法接管节点证书", "capture_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func normalizeRenewBeforeDays(value int) int {
	if value == 0 {
		return 30
	}
	return value
}

func normalizeCertificateNames(primary string, values []string) ([]string, error) {
	primary = strings.ToLower(strings.TrimSpace(primary))
	all := append([]string{primary}, values...)
	result := make([]string, 0, len(all))
	seen := make(map[string]bool)
	for _, value := range all {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		base := value
		if strings.HasPrefix(value, "*.") {
			base = strings.TrimPrefix(value, "*.")
		} else if strings.Contains(value, "*") {
			return nil, fmt.Errorf("通配符只能位于最左侧标签：%s", value)
		}
		if _, err := nginxconfig.ConfigFileName(base); err != nil {
			return nil, fmt.Errorf("无效域名：%s", value)
		}
		seen[value] = true
		result = append(result, value)
		if len(result) > 20 {
			return nil, errors.New("单张证书最多支持 20 个域名")
		}
	}
	if len(result) == 0 || result[0] != primary {
		return nil, errors.New("主域名不能为空")
	}
	return result, nil
}

func certificateIDForDomain(state model.State, domain string) string {
	for _, certificate := range state.Certificates {
		if certificate.Domain == domain {
			return certificate.ID
		}
	}
	return ""
}

func desiredCertificateNames(certificate model.Certificate) []string {
	if len(certificate.RequestedDNSNames) > 0 {
		return append([]string(nil), certificate.RequestedDNSNames...)
	}
	if len(certificate.DNSNames) > 0 {
		return append([]string(nil), certificate.DNSNames...)
	}
	return []string{certificate.Domain}
}

func desiredNamesForDomain(state model.State, domain model.Domain) []string {
	if certificate, ok := state.Certificates[domain.CertificateID]; ok {
		return desiredCertificateNames(certificate)
	}
	return []string{domain.Name}
}

func (s *Server) handleUploadCertificate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "证书上传内容无效或超过 8 MiB", "invalid_upload", nil)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if domain != "" {
		if _, err := nginxconfig.ConfigFileName(domain); err != nil {
			writeError(w, http.StatusBadRequest, "域名无效", "invalid_domain", nil)
			return
		}
	}
	fullchain, err := readFirstFormFile(r, []string{"certificate", "fullchain"}, 4<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法读取证书文件", "invalid_certificate_file", map[string]string{"reason": err.Error()})
		return
	}
	privateKey, err := readFirstFormFile(r, []string{"private_key", "privkey"}, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法读取私钥文件", "invalid_private_key", map[string]string{"reason": err.Error()})
		return
	}
	info, err := certutil.Validate(fullchain, privateKey, domain, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "证书校验失败", "certificate_invalid", map[string]string{"reason": err.Error()})
		return
	}
	if domain == "" {
		domain, err = inferCertificateDomain(info)
		if err != nil {
			writeError(w, http.StatusBadRequest, "无法从证书识别域名", "certificate_domain_missing", nil)
			return
		}
	}
	autoRenew, err := strconv.ParseBool(defaultString(r.FormValue("auto_renew"), "false"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "自动续期选项无效", "invalid_automation", nil)
		return
	}
	renewBeforeDays, err := strconv.Atoi(defaultString(r.FormValue("renew_before_days"), "30"))
	if err != nil || renewBeforeDays < 7 || renewBeforeDays > 60 {
		writeError(w, http.StatusBadRequest, "自动续期阈值需为 7–60 天", "invalid_renewal_window", nil)
		return
	}
	issuerNodeID := strings.TrimSpace(r.FormValue("node_id"))
	acmeAccountID := strings.TrimSpace(r.FormValue("acme_account_id"))
	dnsAccountID := strings.TrimSpace(r.FormValue("dns_account_id"))
	var requestedSyncNodeIDs []string
	if value := strings.TrimSpace(r.FormValue("sync_node_ids")); value != "" {
		if err := json.Unmarshal([]byte(value), &requestedSyncNodeIDs); err != nil {
			writeError(w, http.StatusBadRequest, "同步节点列表无效", "invalid_sync_nodes", nil)
			return
		}
	}
	if autoRenew && issuerNodeID == "" {
		writeError(w, http.StatusBadRequest, "自动续期需要签发节点", "renewal_node_required", nil)
		return
	}
	if !autoRenew {
		acmeAccountID = ""
		dnsAccountID = ""
	}
	certificateID, err := id.New("crt")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	fullchainCiphertext, err := s.mustSeal("certificate:"+certificateID+":fullchain", fullchain)
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	privateKeyCiphertext, err := s.mustSeal("certificate:"+certificateID+":private-key", privateKey)
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	certificate := model.Certificate{
		ID: certificateID, Domain: domain, Source: model.CertificateUpload,
		FullchainCiphertext: fullchainCiphertext, PrivateKeyCiphertext: privateKeyCiphertext,
		FingerprintSHA256: info.FingerprintSHA256, Issuer: info.Issuer, SerialNumber: info.SerialNumber,
		NotBefore: info.NotBefore, NotAfter: info.NotAfter, DNSNames: info.DNSNames, RequestedDNSNames: info.DNSNames,
		AutoRenew: autoRenew, RenewBeforeDays: renewBeforeDays,
		ACMEAccountID: acmeAccountID, DNSAccountID: dnsAccountID, IssuerNodeID: issuerNodeID,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.Update(func(state *model.State) error {
		if issuerNodeID != "" {
			if node, ok := state.Nodes[issuerNodeID]; !ok || node.Status == model.NodeRevoked {
				return fmt.Errorf("%w: node", errNotFound)
			}
		}
		if autoRenew {
			if certificate.ACMEAccountID == "" {
				certificate.ACMEAccountID = firstACMEAccountID(*state)
			}
			if certificate.DNSAccountID == "" {
				certificate.DNSAccountID = firstDNSAccountID(*state)
			}
			acmeAccountID = certificate.ACMEAccountID
			dnsAccountID = certificate.DNSAccountID
			if _, ok := state.ACMEAccounts[acmeAccountID]; !ok {
				return fmt.Errorf("%w: acme", errNotFound)
			}
			if _, ok := state.DNSAccounts[dnsAccountID]; !ok {
				return fmt.Errorf("%w: dns", errNotFound)
			}
		}
		syncNodeIDs, err := validateNodeIDs(state, requestedSyncNodeIDs, "")
		if err != nil {
			return err
		}
		state.Certificates[certificate.ID] = certificate
		for _, nodeID := range syncNodeIDs {
			if _, err := enqueueJob(state, nodeID, "", protocol.JobSyncCertificate, syncCertificateSpec{
				CertificateID: certificate.ID, Domain: certificate.Domain, ReloadNginx: true,
			}); err != nil {
				return err
			}
		}
		s.addAudit(state, "info", "certificate.uploaded", "证书已上传并完成私钥匹配校验")
		return nil
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusBadRequest, "节点、DNS 或 ACME 账户不存在", "dependency_not_found", nil)
		} else {
			writeError(w, http.StatusBadRequest, "无法保存上传证书", "upload_unavailable", map[string]string{"reason": err.Error()})
		}
		return
	}
	writeJSON(w, http.StatusCreated, makeCertificateView(certificate, time.Now()))
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func (s *Server) handleSetCertificateAutoRenew(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Enabled == nil {
		writeError(w, http.StatusBadRequest, "缺少自动续期开关状态", "invalid_auto_renew", nil)
		return
	}

	certificateID := r.PathValue("id")
	now := time.Now().UTC()
	var updated model.Certificate
	err := s.store.Update(func(state *model.State) error {
		certificate, ok := state.Certificates[certificateID]
		if !ok {
			return errNotFound
		}

		if *request.Enabled {
			issuerNodeID, acmeAccountID, dnsAccountID := certificateAutomationDependencies(state, certificate)
			if issuerNodeID == "" || acmeAccountID == "" || dnsAccountID == "" {
				return errors.New("certificate is not linked to a signing node, DNS account, and ACME account")
			}
			node, ok := state.Nodes[issuerNodeID]
			if !ok || node.Status == model.NodeRevoked {
				return errors.New("signing node is unavailable or revoked")
			}
			if _, ok := state.ACMEAccounts[acmeAccountID]; !ok {
				return errors.New("ACME account no longer exists")
			}
			if _, ok := state.DNSAccounts[dnsAccountID]; !ok {
				return errors.New("DNS account no longer exists")
			}
			certificate.IssuerNodeID = issuerNodeID
			certificate.ACMEAccountID = acmeAccountID
			certificate.DNSAccountID = dnsAccountID
			certificate.RenewBeforeDays = normalizeRenewBeforeDays(certificate.RenewBeforeDays)
		}

		certificate.AutoRenew = *request.Enabled
		certificate.UpdatedAt = now
		state.Certificates[certificate.ID] = certificate

		// A certificate is renewed once. Only its exact managed domain may own
		// the domain-level schedule; SAN aliases rely on the certificate schedule.
		for id, domain := range state.Domains {
			if domain.CertificateID != certificate.ID {
				continue
			}
			domain.AutoRenew = *request.Enabled && domain.Name == certificate.Domain &&
				domain.NodeID == certificate.IssuerNodeID && domain.ACMEAccountID == certificate.ACMEAccountID &&
				domain.DNSAccountID == certificate.DNSAccountID
			domain.UpdatedAt = now
			state.Domains[id] = domain
		}

		updated = certificate
		action := "certificate.auto-renew.disabled"
		message := "证书自动续期已关闭"
		if certificate.AutoRenew {
			action = "certificate.auto-renew.enabled"
			message = "证书自动续期已启用"
		}
		s.addAudit(state, "info", action, message, certificate.IssuerNodeID, "", "")
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "证书不存在", "not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法更改自动续期", "auto_renew_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, makeCertificateView(updated, time.Now()))
}

func (s *Server) handleUpdateCertificateAutomation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		NodeID          string   `json:"node_id"`
		AutoRenew       bool     `json:"auto_renew"`
		RenewBeforeDays int      `json:"renew_before_days"`
		ACMEAccountID   string   `json:"acme_account_id"`
		DNSAccountID    string   `json:"dns_account_id"`
		DNSNames        []string `json:"dns_names"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.NodeID = strings.TrimSpace(request.NodeID)
	request.ACMEAccountID = strings.TrimSpace(request.ACMEAccountID)
	request.DNSAccountID = strings.TrimSpace(request.DNSAccountID)
	request.RenewBeforeDays = normalizeRenewBeforeDays(request.RenewBeforeDays)
	if request.RenewBeforeDays < 7 || request.RenewBeforeDays > 60 {
		writeError(w, http.StatusBadRequest, "自动续期阈值需为 7–60 天", "invalid_renewal_window", nil)
		return
	}
	certificateID := r.PathValue("id")
	var updated model.Certificate
	err := s.store.Update(func(state *model.State) error {
		certificate, ok := state.Certificates[certificateID]
		if !ok {
			return errNotFound
		}
		dnsNames, err := normalizeCertificateNames(certificate.Domain, request.DNSNames)
		if err != nil {
			return err
		}
		if request.NodeID == "" {
			request.NodeID = certificate.IssuerNodeID
		}
		if request.ACMEAccountID == "" {
			request.ACMEAccountID = defaultString(certificate.ACMEAccountID, firstACMEAccountID(*state))
		}
		if request.DNSAccountID == "" {
			request.DNSAccountID = defaultString(certificate.DNSAccountID, firstDNSAccountID(*state))
		}
		if request.AutoRenew && (request.NodeID == "" || request.ACMEAccountID == "" || request.DNSAccountID == "") {
			return errors.New("自动续期需要签发节点、DNS 与 ACME 账户")
		}
		if request.NodeID != "" {
			node, ok := state.Nodes[request.NodeID]
			if !ok || node.Status == model.NodeRevoked {
				return fmt.Errorf("%w: node", errNotFound)
			}
		}
		if request.ACMEAccountID != "" {
			if _, ok := state.ACMEAccounts[request.ACMEAccountID]; !ok {
				return fmt.Errorf("%w: acme", errNotFound)
			}
		}
		if request.DNSAccountID != "" {
			if _, ok := state.DNSAccounts[request.DNSAccountID]; !ok {
				return fmt.Errorf("%w: dns", errNotFound)
			}
		}
		now := time.Now().UTC()
		certificate.IssuerNodeID = request.NodeID
		certificate.ACMEAccountID = request.ACMEAccountID
		certificate.DNSAccountID = request.DNSAccountID
		certificate.AutoRenew = request.AutoRenew
		certificate.RenewBeforeDays = request.RenewBeforeDays
		certificate.RequestedDNSNames = dnsNames
		certificate.UpdatedAt = now
		state.Certificates[certificate.ID] = certificate
		for id, domain := range state.Domains {
			if domain.CertificateID != certificate.ID || domain.Name != certificate.Domain {
				continue
			}
			domain.ACMEAccountID = certificate.ACMEAccountID
			domain.DNSAccountID = certificate.DNSAccountID
			domain.RenewBeforeDays = certificate.RenewBeforeDays
			domain.AutoRenew = certificate.AutoRenew && domain.NodeID == certificate.IssuerNodeID
			domain.UpdatedAt = now
			state.Domains[id] = domain
		}
		updated = certificate
		s.addAudit(state, "info", "certificate.automation.updated", "证书签发账户、域名与续期设置已更新", certificate.IssuerNodeID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "证书、节点或账户不存在", "not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法更新证书自动化设置", "automation_update_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, makeCertificateView(updated, time.Now()))
}

func certificateAutomationDependencies(state *model.State, certificate model.Certificate) (string, string, string) {
	if certificate.IssuerNodeID != "" && certificate.ACMEAccountID != "" && certificate.DNSAccountID != "" {
		return certificate.IssuerNodeID, certificate.ACMEAccountID, certificate.DNSAccountID
	}
	for _, domain := range state.Domains {
		if domainIsDeleting(*state, domain) {
			continue
		}
		if domain.CertificateID == certificate.ID && domain.Name == certificate.Domain &&
			domain.NodeID != "" && domain.ACMEAccountID != "" && domain.DNSAccountID != "" {
			return domain.NodeID, domain.ACMEAccountID, domain.DNSAccountID
		}
	}
	return certificate.IssuerNodeID, defaultString(certificate.ACMEAccountID, firstACMEAccountID(*state)), defaultString(certificate.DNSAccountID, firstDNSAccountID(*state))
}

func (s *Server) handleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	certificateID := r.PathValue("id")
	var job model.Job
	err := s.store.Update(func(state *model.State) error {
		certificate, ok := state.Certificates[certificateID]
		if !ok {
			return errNotFound
		}
		var domain model.Domain
		found := false
		for _, candidate := range state.Domains {
			if candidate.CertificateID == certificate.ID && candidate.Name == certificate.Domain {
				domain, found = candidate, true
				break
			}
		}
		var err error
		if found && domain.ACMEAccountID != "" && domain.DNSAccountID != "" {
			node, nodeExists := state.Nodes[domain.NodeID]
			if !nodeExists {
				return errors.New("domain node no longer exists")
			}
			if node.Status == model.NodeRevoked {
				return errors.New("domain node has been revoked")
			}
			if _, ok := state.ACMEAccounts[domain.ACMEAccountID]; !ok {
				return errors.New("ACME account no longer exists")
			}
			if _, ok := state.DNSAccounts[domain.DNSAccountID]; !ok {
				return errors.New("DNS account no longer exists")
			}
			if hasActiveJob(state, domain.ID, protocol.JobIssueCertificate) {
				return errors.New("certificate renewal is already queued")
			}
			job, err = enqueueJob(state, domain.NodeID, domain.ID, protocol.JobIssueCertificate, issueCertificateSpec{DomainID: domain.ID, DNSNames: desiredNamesForDomain(*state, domain)})
			if err == nil {
				domain.LastJobID = job.ID
				domain.UpdatedAt = time.Now().UTC()
				state.Domains[domain.ID] = domain
			}
		} else {
			if certificate.ACMEAccountID == "" || certificate.DNSAccountID == "" || certificate.IssuerNodeID == "" {
				return errors.New("certificate is not linked to a signing node, DNS account, and ACME account")
			}
			node, ok := state.Nodes[certificate.IssuerNodeID]
			if !ok {
				return errors.New("issuer node no longer exists")
			}
			if node.Status == model.NodeRevoked {
				return errors.New("issuer node has been revoked")
			}
			if _, ok := state.ACMEAccounts[certificate.ACMEAccountID]; !ok {
				return errors.New("ACME account no longer exists")
			}
			if _, ok := state.DNSAccounts[certificate.DNSAccountID]; !ok {
				return errors.New("DNS account no longer exists")
			}
			if hasActiveCertificateJob(state, certificate.ID) {
				return errors.New("certificate renewal is already queued")
			}
			syncNodeIDs := make([]string, 0, len(certificate.DeployedNodeIDs))
			for _, nodeID := range certificate.DeployedNodeIDs {
				if nodeID != certificate.IssuerNodeID {
					syncNodeIDs = append(syncNodeIDs, nodeID)
				}
			}
			job, err = enqueueJob(state, certificate.IssuerNodeID, "", protocol.JobIssueCertificate, issueCertificateSpec{
				Domain: certificate.Domain, DNSNames: desiredCertificateNames(certificate), CertificateID: certificate.ID,
				ACMEAccountID: certificate.ACMEAccountID, DNSAccountID: certificate.DNSAccountID,
				AutoRenew: certificate.AutoRenew, RenewBeforeDays: normalizeRenewBeforeDays(certificate.RenewBeforeDays),
				Install: true, ReloadNginx: true, SyncNodeIDs: syncNodeIDs,
			})
		}
		if err != nil {
			return err
		}
		s.addAudit(state, "info", "certificate.renew.queued", "证书续期任务已加入队列", job.NodeID, job.DomainID, job.ID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "证书不存在", "not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法续期证书", "renewal_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleSyncCertificate(w http.ResponseWriter, r *http.Request) {
	certificateID := r.PathValue("id")
	var request struct {
		NodeIDs []string `json:"node_ids"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	var jobs []model.Job
	err := s.store.Update(func(state *model.State) error {
		certificate, ok := state.Certificates[certificateID]
		if !ok {
			return errNotFound
		}
		nodeIDs, err := validateNodeIDs(state, request.NodeIDs, "")
		if err != nil {
			return err
		}
		for _, nodeID := range nodeIDs {
			job, err := enqueueJob(state, nodeID, "", protocol.JobSyncCertificate, syncCertificateSpec{
				CertificateID: certificate.ID, Domain: certificate.Domain, ReloadNginx: true,
			})
			if err != nil {
				return err
			}
			jobs = append(jobs, job)
		}
		s.addAudit(state, "info", "certificate.sync.queued", "证书同步任务已加入队列")
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "证书或节点不存在", "not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法同步证书", "sync_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, jobs)
}

func (s *Server) handleDNSAccounts(w http.ResponseWriter, _ *http.Request) {
	state := s.store.Snapshot()
	views := make([]dnsAccountView, 0, len(state.DNSAccounts))
	for _, account := range state.DNSAccounts {
		keys := []string{}
		if plaintext, err := s.box.Open("dns-account:"+account.ID, account.CredentialsCiphertext); err == nil {
			var credentials map[string]string
			if json.Unmarshal(plaintext, &credentials) == nil {
				for key := range credentials {
					keys = append(keys, key)
				}
				sort.Strings(keys)
			}
		}
		views = append(views, dnsAccountView{ID: account.ID, Name: account.Name, Provider: account.Provider, CredentialKeys: keys, CreatedAt: account.CreatedAt, UpdatedAt: account.UpdatedAt})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleCreateDNSAccount(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeDNSAccountRequest(w, r)
	if !ok {
		return
	}
	if request.KeepCredentials {
		writeError(w, http.StatusBadRequest, "新 DNS 账户必须提交凭据", "invalid_credentials", nil)
		return
	}
	accountID, err := id.New("dns")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	plaintext, _ := json.Marshal(request.Credentials)
	ciphertext, err := s.mustSeal("dns-account:"+accountID, plaintext)
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	account := model.DNSAccount{ID: accountID, Name: request.Name, Provider: request.Provider, CredentialsCiphertext: ciphertext, CreatedAt: now, UpdatedAt: now}
	if err := s.store.Update(func(state *model.State) error {
		if len(state.DNSAccounts) > 0 {
			return errConflict
		}
		state.DNSAccounts[account.ID] = account
		s.addAudit(state, "info", "dns-account.created", "DNS 账户已加密保存")
		return nil
	}); err != nil {
		if errors.Is(err, errConflict) {
			writeError(w, http.StatusConflict, "DNS 账户已存在", "dns_account_exists", nil)
			return
		}
		wrapStoreError(w, err)
		return
	}
	keys := credentialKeys(request.Credentials)
	writeJSON(w, http.StatusCreated, dnsAccountView{ID: account.ID, Name: account.Name, Provider: account.Provider, CredentialKeys: keys, CreatedAt: now, UpdatedAt: now})
}

func (s *Server) handleUpdateDNSAccount(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("id")
	request, ok := decodeDNSAccountRequest(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	var account model.DNSAccount
	err := s.store.Update(func(state *model.State) error {
		existing, exists := state.DNSAccounts[accountID]
		if !exists {
			return errNotFound
		}
		existing.Name = request.Name
		existing.Provider = request.Provider
		if !request.KeepCredentials {
			plaintext, _ := json.Marshal(request.Credentials)
			ciphertext, err := s.mustSeal("dns-account:"+accountID, plaintext)
			if err != nil {
				return err
			}
			existing.CredentialsCiphertext = ciphertext
		}
		existing.UpdatedAt = now
		state.DNSAccounts[accountID] = existing
		account = existing
		s.addAudit(state, "info", "dns-account.updated", "DNS 账户已更新")
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "DNS 账户不存在", "not_found", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dnsAccountView{ID: account.ID, Name: account.Name, Provider: account.Provider, CredentialKeys: dnsAccountCredentialKeys(s, account), CreatedAt: account.CreatedAt, UpdatedAt: account.UpdatedAt})
}

func decodeDNSAccountRequest(w http.ResponseWriter, r *http.Request) (dnsAccountRequest, bool) {
	var request dnsAccountRequest
	if !decodeJSON(w, r, &request) {
		return request, false
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Provider = strings.ToLower(strings.TrimSpace(request.Provider))
	if len(request.Name) < 2 || len(request.Name) > 64 || !dnsProviderPattern.MatchString(request.Provider) || request.Provider == "manual" || request.Provider == "exec" {
		writeError(w, http.StatusBadRequest, "DNS 账户名称或提供商无效", "invalid_dns_account", nil)
		return request, false
	}
	if request.KeepCredentials && len(request.Credentials) > 0 {
		writeError(w, http.StatusBadRequest, "保留凭据时不能同时提交新凭据", "invalid_credentials", nil)
		return request, false
	}
	if !request.KeepCredentials && (len(request.Credentials) == 0 || len(request.Credentials) > 32) {
		writeError(w, http.StatusBadRequest, "DNS 凭据不能为空且最多包含 32 项", "invalid_credentials", nil)
		return request, false
	}
	for key, value := range request.Credentials {
		value = strings.TrimSpace(value)
		if !credentialNamePattern.MatchString(key) || value == "" || len(value) > 4096 {
			writeError(w, http.StatusBadRequest, "DNS 凭据变量无效", "invalid_credentials", map[string]string{"key": key})
			return request, false
		}
		request.Credentials[key] = value
	}
	return request, true
}

func dnsAccountCredentialKeys(s *Server, account model.DNSAccount) []string {
	plaintext, err := s.box.Open("dns-account:"+account.ID, account.CredentialsCiphertext)
	if err != nil {
		return nil
	}
	var credentials map[string]string
	if json.Unmarshal(plaintext, &credentials) != nil {
		return nil
	}
	return credentialKeys(credentials)
}

func credentialKeys(credentials map[string]string) []string {
	keys := make([]string, 0, len(credentials))
	for key := range credentials {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) handleACMEAccounts(w http.ResponseWriter, _ *http.Request) {
	state := s.store.Snapshot()
	views := make([]acmeAccountView, 0, len(state.ACMEAccounts))
	for _, account := range state.ACMEAccounts {
		views = append(views, acmeAccountView{ID: account.ID, Name: account.Name, Email: account.Email, DirectoryURL: account.DirectoryURL, HasEAB: account.EABKID != "", CreatedAt: account.CreatedAt, UpdatedAt: account.UpdatedAt})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	writeJSON(w, http.StatusOK, views)
}

type acmeAccountRequest struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	DirectoryURL string `json:"directory_url"`
	EABKID       string `json:"eab_kid"`
	EABHMAC      string `json:"eab_hmac"`
	KeepEAB      bool   `json:"keep_eab"`
}

func (s *Server) handleCreateACMEAccount(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeACMEAccountRequest(w, r)
	if !ok {
		return
	}
	accountID, err := id.New("acme")
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	var hmacCiphertext string
	if request.EABHMAC != "" {
		hmacCiphertext, err = s.mustSeal("acme-account:"+accountID+":eab", []byte(request.EABHMAC))
		if err != nil {
			wrapStoreError(w, err)
			return
		}
	}
	now := time.Now().UTC()
	account := model.ACMEAccount{
		ID: accountID, Name: request.Name, Email: request.Email, DirectoryURL: request.DirectoryURL,
		EABKID: request.EABKID, EABHMACCiphertext: hmacCiphertext, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.Update(func(state *model.State) error {
		if len(state.ACMEAccounts) > 0 {
			return errConflict
		}
		state.ACMEAccounts[account.ID] = account
		s.addAudit(state, "info", "acme-account.created", "ACME 账户已保存")
		return nil
	}); err != nil {
		if errors.Is(err, errConflict) {
			writeError(w, http.StatusConflict, "ACME 账户已存在", "acme_account_exists", nil)
			return
		}
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, acmeAccountView{ID: account.ID, Name: account.Name, Email: account.Email, DirectoryURL: account.DirectoryURL, HasEAB: account.EABKID != "", CreatedAt: now, UpdatedAt: now})
}

func (s *Server) handleUpdateACMEAccount(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("id")
	request, ok := decodeACMEAccountRequest(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	var updated model.ACMEAccount
	err := s.store.Update(func(state *model.State) error {
		account, exists := state.ACMEAccounts[accountID]
		if !exists {
			return errNotFound
		}
		account.Name = request.Name
		account.Email = request.Email
		account.DirectoryURL = request.DirectoryURL
		switch {
		case request.KeepEAB:
			// Keep the encrypted HMAC and KID exactly as stored.
		case request.EABKID == "":
			account.EABKID = ""
			account.EABHMACCiphertext = ""
		default:
			ciphertext, err := s.mustSeal("acme-account:"+account.ID+":eab", []byte(request.EABHMAC))
			if err != nil {
				return err
			}
			account.EABKID = request.EABKID
			account.EABHMACCiphertext = ciphertext
		}
		account.UpdatedAt = now
		state.ACMEAccounts[account.ID] = account
		updated = account
		s.addAudit(state, "info", "acme-account.updated", "ACME 账户已更新")
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "ACME 账户不存在", "not_found", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, acmeAccountView{ID: updated.ID, Name: updated.Name, Email: updated.Email, DirectoryURL: updated.DirectoryURL, HasEAB: updated.EABKID != "", CreatedAt: updated.CreatedAt, UpdatedAt: updated.UpdatedAt})
}

func decodeACMEAccountRequest(w http.ResponseWriter, r *http.Request) (acmeAccountRequest, bool) {
	var request acmeAccountRequest
	if !decodeJSON(w, r, &request) {
		return request, false
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Email = strings.TrimSpace(request.Email)
	request.DirectoryURL = strings.TrimSpace(request.DirectoryURL)
	request.EABKID = strings.TrimSpace(request.EABKID)
	if request.DirectoryURL == "" {
		request.DirectoryURL = letsEncryptDirectory
	}
	if len(request.Name) < 2 || len(request.Name) > 64 {
		writeError(w, http.StatusBadRequest, "ACME 账户名称无效", "invalid_acme_account", nil)
		return request, false
	}
	if _, err := mail.ParseAddress(request.Email); err != nil {
		writeError(w, http.StatusBadRequest, "ACME 邮箱无效", "invalid_email", nil)
		return request, false
	}
	directory, err := url.Parse(request.DirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" {
		writeError(w, http.StatusBadRequest, "ACME 目录必须是 HTTPS URL", "invalid_directory", nil)
		return request, false
	}
	if request.KeepEAB && (request.EABKID != "" || request.EABHMAC != "") {
		writeError(w, http.StatusBadRequest, "保留 EAB 时不能同时提交新凭据", "invalid_eab", nil)
		return request, false
	}
	if !request.KeepEAB && (request.EABKID == "") != (request.EABHMAC == "") {
		writeError(w, http.StatusBadRequest, "EAB KID 与 HMAC 必须同时填写", "invalid_eab", nil)
		return request, false
	}
	return request, true
}

func (s *Server) handleChangeAdminPassword(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if !s.verifyAdminCredential(request.CurrentPassword) {
		writeError(w, http.StatusUnauthorized, "当前管理员密码不正确", "current_password_invalid", nil)
		return
	}
	if len(request.NewPassword) < 12 || len(request.NewPassword) > 256 {
		writeError(w, http.StatusBadRequest, "新密码需为 12–256 个字符", "invalid_new_password", nil)
		return
	}
	if request.NewPassword == request.CurrentPassword {
		writeError(w, http.StatusBadRequest, "新密码不能与当前密码相同", "password_unchanged", nil)
		return
	}
	encoded, err := hashAdminPassword(request.NewPassword)
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	err = s.store.Update(func(state *model.State) error {
		state.AdminPasswordHash = encoded
		s.addAudit(state, "warning", "admin.password.changed", "管理员面板密码已更改")
		return nil
	})
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	s.clearAdminSessions()
	token, expiresAt, err := s.createAdminSession()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "密码已更改，但无法创建新会话", "session_error", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "token": token, "expires_at": expiresAt})
}

func safeNodes(state model.State) []model.Node {
	result := make([]model.Node, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		if node.Status == model.NodeRevoked {
			continue
		}
		node.SecretHash = ""
		result = append(result, node)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result
}

func domainViews(state model.State) []domainView {
	result := make([]domainView, 0, len(state.Domains))
	now := time.Now()
	for _, domain := range state.Domains {
		if domainIsDeleting(state, domain) {
			continue
		}
		view := domainView{Domain: domain, CertificateStatus: "none"}
		if node, ok := state.Nodes[domain.NodeID]; ok {
			view.NodeName = node.Name
			view.NodeStatus = string(node.Status)
		}
		var cert *model.Certificate
		if certificate, ok := state.Certificates[domain.CertificateID]; ok {
			cert = &certificate
		} else {
			for _, certificate := range state.Certificates {
				if certificate.Domain == domain.Name || certutil.CoversHostname(certificate.DNSNames, domain.Name) {
					c := certificate
					cert = &c
					break
				}
			}
		}
		if cert != nil {
			expiry := cert.NotAfter
			view.CertificateIssuer = cert.Issuer
			view.CertificateExpiry = &expiry
			view.CertificateStatus = certificateState(cert.NotAfter, now)
		} else {
			if node, ok := state.Nodes[domain.NodeID]; ok {
				for _, certificate := range node.Certificates {
					if certificate.Domain == domain.Name || certutil.CoversHostname(certificate.DNSNames, domain.Name) {
						expiry := certificate.NotAfter
						view.CertificateIssuer = certificate.Issuer
						view.CertificateExpiry = &expiry
						view.CertificateStatus = certificateState(certificate.NotAfter, now)
						break
					}
				}
			}
		}
		if job, ok := state.Jobs[domain.LastJobID]; ok {
			view.JobStatus = string(job.Status)
		}
		result = append(result, view)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result
}

func domainIsDeleting(state model.State, domain model.Domain) bool {
	if domain.Deleting {
		return true
	}
	job, ok := state.Jobs[domain.LastJobID]
	return ok && job.Type == protocol.JobDeleteDomain && job.Status != model.JobFailed
}

func certificateViews(state model.State) []certificateView {
	result := make([]certificateView, 0, len(state.Certificates))
	now := time.Now()
	for _, certificate := range state.Certificates {
		result = append(result, makeCertificateView(certificate, now))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].NotAfter.Before(result[j].NotAfter) })
	return result
}

func makeCertificateView(certificate model.Certificate, now time.Time) certificateView {
	if now.IsZero() {
		now = time.Now()
	}
	days := int(certificate.NotAfter.Sub(now).Hours() / 24)
	return certificateView{
		ID: certificate.ID, Domain: certificate.Domain, Source: certificate.Source,
		Fingerprint: certificate.FingerprintSHA256, Issuer: certificate.Issuer, SerialNumber: certificate.SerialNumber,
		NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter, DNSNames: certificate.DNSNames,
		RequestedDNSNames: certificate.RequestedDNSNames,
		AutoRenew:         certificate.AutoRenew, RenewBeforeDays: normalizeRenewBeforeDays(certificate.RenewBeforeDays),
		ACMEAccountID: certificate.ACMEAccountID, DNSAccountID: certificate.DNSAccountID,
		IssuerNodeID: certificate.IssuerNodeID, DeployedNodeIDs: certificate.DeployedNodeIDs,
		DaysRemaining: days, Status: certificateState(certificate.NotAfter, now), CreatedAt: certificate.CreatedAt, UpdatedAt: certificate.UpdatedAt,
	}
}

func certificateState(expiry, now time.Time) string {
	remaining := expiry.Sub(now)
	if remaining <= 0 {
		return "expired"
	}
	if remaining <= 30*24*time.Hour {
		return "expiring"
	}
	return "valid"
}

func validateNodeIDs(state *model.State, values []string, exclude string) ([]string, error) {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, nodeID := range values {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" || nodeID == exclude || seen[nodeID] {
			continue
		}
		node, ok := state.Nodes[nodeID]
		if !ok || node.Status == model.NodeRevoked {
			return nil, fmt.Errorf("%w: node %s", errNotFound, nodeID)
		}
		seen[nodeID] = true
		result = append(result, nodeID)
	}
	return result, nil
}

func enqueueJob(state *model.State, nodeID, domainID, jobType string, spec any) (model.Job, error) {
	jobID, err := id.New("job")
	if err != nil {
		return model.Job{}, err
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return model.Job{}, err
	}
	now := time.Now().UTC()
	job := model.Job{
		ID: jobID, NodeID: nodeID, DomainID: domainID, Type: jobType, Status: model.JobQueued,
		Payload: payload, MaxAttempts: 3, CreatedAt: now, QueuedAt: &now,
	}
	state.Jobs[job.ID] = job
	return job, nil
}

func readFormFile(r *http.Request, name string, limit int64) ([]byte, error) {
	file, _, err := r.FormFile(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func readFirstFormFile(r *http.Request, names []string, limit int64) ([]byte, error) {
	var lastErr error
	for _, name := range names {
		data, err := readFormFile(r, name, limit)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func inferCertificateDomain(info certutil.Info) (string, error) {
	candidates := append([]string(nil), info.DNSNames...)
	if info.Leaf != nil {
		candidates = append(candidates, info.Leaf.Subject.CommonName)
	}
	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		validationName := strings.TrimPrefix(candidate, "*.")
		if candidate == "" || validationName == candidate && strings.Contains(candidate, "*") {
			continue
		}
		if _, err := nginxconfig.ConfigFileName(validationName); err == nil {
			return candidate, nil
		}
	}
	return "", errors.New("certificate has no usable DNS name")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

var (
	errNotFound = errors.New("not found")
	errConflict = errors.New("conflict")
)

func decodeHash(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid hash")
	}
	return decoded, nil
}
