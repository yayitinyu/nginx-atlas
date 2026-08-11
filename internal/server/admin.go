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
	ID              string                  `json:"id"`
	Domain          string                  `json:"domain"`
	Source          model.CertificateSource `json:"source"`
	Fingerprint     string                  `json:"fingerprint_sha256"`
	Issuer          string                  `json:"issuer"`
	SerialNumber    string                  `json:"serial_number"`
	NotBefore       time.Time               `json:"not_before"`
	NotAfter        time.Time               `json:"not_after"`
	DNSNames        []string                `json:"dns_names"`
	AutoRenew       bool                    `json:"auto_renew"`
	ACMEAccountID   string                  `json:"acme_account_id,omitempty"`
	DNSAccountID    string                  `json:"dns_account_id,omitempty"`
	IssuerNodeID    string                  `json:"issuer_node_id,omitempty"`
	DeployedNodeIDs []string                `json:"deployed_node_ids"`
	DaysRemaining   int                     `json:"days_remaining"`
	Status          string                  `json:"status"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
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
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
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

func (s *Server) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	state := s.store.Snapshot()
	nodes := safeNodes(state)
	domains := domainViews(state)
	certificates := certificateViews(state)
	audit := state.Audit
	if len(audit) > 12 {
		audit = audit[:12]
	}
	jobs := make([]model.Job, 0, len(state.Jobs))
	for _, job := range state.Jobs {
		job.Payload = nil
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
	if len(jobs) > 12 {
		jobs = jobs[:12]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes, "domains": domains, "certificates": certificates, "audit": audit, "jobs": jobs,
		"server_time": time.Now().UTC(),
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

func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name       string `json:"name"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if len(request.Name) < 2 || len(request.Name) > 64 {
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
	command := fmt.Sprintf("curl -fsSL %s/install.sh | sudo bash -s -- agent --server %s --token %s --name %s",
		shellQuote(baseURL), shellQuote(baseURL), shellQuote(token), shellQuote(request.Name))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": enrollmentID, "name": request.Name, "token": token, "expires_at": expiresAt, "command": command,
	})
}

func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	now := time.Now().UTC()
	err := s.store.Update(func(state *model.State) error {
		node, ok := state.Nodes[nodeID]
		if !ok {
			return errNotFound
		}
		node.Status = model.NodeRevoked
		node.RevokedAt = &now
		node.SecretHash = ""
		state.Nodes[nodeID] = node
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

type createDomainRequest struct {
	Domain          string   `json:"domain"`
	NodeID          string   `json:"node_id"`
	UpstreamHost    string   `json:"upstream_host"`
	UpstreamPort    int      `json:"upstream_port"`
	CertificateMode string   `json:"certificate_mode"`
	CertificateID   string   `json:"certificate_id"`
	ACMEAccountID   string   `json:"acme_account_id"`
	DNSAccountID    string   `json:"dns_account_id"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewBeforeDays int      `json:"renew_before_days"`
	SyncNodeIDs     []string `json:"sync_node_ids"`
}

type applyDomainSpec struct {
	DomainID            string `json:"domain_id"`
	CertificateID       string `json:"certificate_id,omitempty"`
	UseLocalCertificate bool   `json:"use_local_certificate"`
	CaptureCertificate  bool   `json:"capture_certificate"`
}

type issueCertificateSpec struct {
	DomainID string `json:"domain_id"`
}

type syncCertificateSpec struct {
	CertificateID string `json:"certificate_id"`
	Domain        string `json:"domain"`
	ReloadNginx   bool   `json:"reload_nginx"`
}

type deleteDomainSpec struct {
	DomainID string `json:"domain_id"`
	Domain   string `json:"domain"`
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
		}
		state.Domains[domainID] = created
		var job model.Job
		if source == model.CertificateACME {
			job, err = enqueueJob(state, request.NodeID, domainID, protocol.JobIssueCertificate, issueCertificateSpec{DomainID: domainID})
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

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	domainID := r.PathValue("id")
	err := s.store.Update(func(state *model.State) error {
		domain, ok := state.Domains[domainID]
		if !ok {
			return errNotFound
		}
		job, err := enqueueJob(state, domain.NodeID, domain.ID, protocol.JobDeleteDomain, deleteDomainSpec{DomainID: domain.ID, Domain: domain.Name})
		if err != nil {
			return err
		}
		domain.Enabled = false
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
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": true})
}

func (s *Server) handleUploadCertificate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "证书上传内容无效或超过 8 MiB", "invalid_upload", nil)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if _, err := nginxconfig.ConfigFileName(domain); err != nil {
		writeError(w, http.StatusBadRequest, "域名无效", "invalid_domain", nil)
		return
	}
	fullchain, err := readFormFile(r, "fullchain", 4<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法读取 fullchain.pem", "invalid_fullchain", map[string]string{"reason": err.Error()})
		return
	}
	privateKey, err := readFormFile(r, "privkey", 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法读取 privkey.pem", "invalid_private_key", map[string]string{"reason": err.Error()})
		return
	}
	info, err := certutil.Validate(fullchain, privateKey, domain, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "证书校验失败", "certificate_invalid", map[string]string{"reason": err.Error()})
		return
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
		NotBefore: info.NotBefore, NotAfter: info.NotAfter, DNSNames: info.DNSNames,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.Update(func(state *model.State) error {
		state.Certificates[certificate.ID] = certificate
		s.addAudit(state, "info", "certificate.uploaded", "证书已上传并完成私钥匹配校验")
		return nil
	}); err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, makeCertificateView(certificate, time.Now()))
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
			if candidate.CertificateID == certificate.ID {
				domain, found = candidate, true
				break
			}
		}
		if !found || domain.ACMEAccountID == "" || domain.DNSAccountID == "" {
			return errors.New("certificate is not linked to DNS and ACME accounts")
		}
		var err error
		job, err = enqueueJob(state, domain.NodeID, domain.ID, protocol.JobIssueCertificate, issueCertificateSpec{DomainID: domain.ID})
		if err != nil {
			return err
		}
		domain.LastJobID = job.ID
		domain.UpdatedAt = time.Now().UTC()
		state.Domains[domain.ID] = domain
		s.addAudit(state, "info", "certificate.renew.queued", "证书续期任务已加入队列", domain.NodeID, domain.ID, job.ID)
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
		state.DNSAccounts[account.ID] = account
		s.addAudit(state, "info", "dns-account.created", "DNS 账户已加密保存")
		return nil
	}); err != nil {
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
	plaintext, _ := json.Marshal(request.Credentials)
	ciphertext, err := s.mustSeal("dns-account:"+accountID, plaintext)
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	now := time.Now().UTC()
	var account model.DNSAccount
	err = s.store.Update(func(state *model.State) error {
		existing, exists := state.DNSAccounts[accountID]
		if !exists {
			return errNotFound
		}
		existing.Name = request.Name
		existing.Provider = request.Provider
		existing.CredentialsCiphertext = ciphertext
		existing.UpdatedAt = now
		state.DNSAccounts[accountID] = existing
		account = existing
		s.addAudit(state, "info", "dns-account.updated", "DNS 账户凭据已重新加密保存")
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
	writeJSON(w, http.StatusOK, dnsAccountView{ID: account.ID, Name: account.Name, Provider: account.Provider, CredentialKeys: credentialKeys(request.Credentials), CreatedAt: account.CreatedAt, UpdatedAt: account.UpdatedAt})
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
	if len(request.Credentials) == 0 || len(request.Credentials) > 32 {
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

func (s *Server) handleCreateACMEAccount(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name         string `json:"name"`
		Email        string `json:"email"`
		DirectoryURL string `json:"directory_url"`
		EABKID       string `json:"eab_kid"`
		EABHMAC      string `json:"eab_hmac"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Email = strings.TrimSpace(request.Email)
	request.DirectoryURL = strings.TrimSpace(request.DirectoryURL)
	if request.DirectoryURL == "" {
		request.DirectoryURL = letsEncryptDirectory
	}
	if len(request.Name) < 2 || len(request.Name) > 64 {
		writeError(w, http.StatusBadRequest, "ACME 账户名称无效", "invalid_acme_account", nil)
		return
	}
	if _, err := mail.ParseAddress(request.Email); err != nil {
		writeError(w, http.StatusBadRequest, "ACME 邮箱无效", "invalid_email", nil)
		return
	}
	directory, err := url.Parse(request.DirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" {
		writeError(w, http.StatusBadRequest, "ACME 目录必须是 HTTPS URL", "invalid_directory", nil)
		return
	}
	if (request.EABKID == "") != (request.EABHMAC == "") {
		writeError(w, http.StatusBadRequest, "EAB KID 与 HMAC 必须同时填写", "invalid_eab", nil)
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
		state.ACMEAccounts[account.ID] = account
		s.addAudit(state, "info", "acme-account.created", "ACME 账户已保存")
		return nil
	}); err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, acmeAccountView{ID: account.ID, Name: account.Name, Email: account.Email, DirectoryURL: account.DirectoryURL, HasEAB: account.EABKID != "", CreatedAt: now, UpdatedAt: now})
}

func safeNodes(state model.State) []model.Node {
	result := make([]model.Node, 0, len(state.Nodes))
	for _, node := range state.Nodes {
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
		view := domainView{Domain: domain, CertificateStatus: "none"}
		if node, ok := state.Nodes[domain.NodeID]; ok {
			view.NodeName = node.Name
			view.NodeStatus = string(node.Status)
		}
		if certificate, ok := state.Certificates[domain.CertificateID]; ok {
			expiry := certificate.NotAfter
			view.CertificateIssuer = certificate.Issuer
			view.CertificateExpiry = &expiry
			view.CertificateStatus = certificateState(certificate.NotAfter, now)
		} else if domain.CertificateMode == model.CertificateLocal {
			if node, ok := state.Nodes[domain.NodeID]; ok {
				for _, certificate := range node.Certificates {
					if certificate.Domain == domain.Name {
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
		AutoRenew: certificate.AutoRenew, ACMEAccountID: certificate.ACMEAccountID, DNSAccountID: certificate.DNSAccountID,
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
	job := model.Job{
		ID: jobID, NodeID: nodeID, DomainID: domainID, Type: jobType, Status: model.JobQueued,
		Payload: payload, MaxAttempts: 3, CreatedAt: time.Now().UTC(),
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
