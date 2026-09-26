package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/nginxconfig"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

var nginxVersionForConfig = regexp.MustCompile(`nginx/(\d+)\.(\d+)\.(\d+)`)

type domainConfigView struct {
	Config          string `json:"config"`
	GeneratedConfig string `json:"generated_config"`
	Mode            string `json:"mode"`
	Revision        string `json:"revision"`
	Path            string `json:"path"`
}

func domainConfig(state model.State, domain model.Domain) (domainConfigView, error) {
	filename, err := nginxconfig.ConfigFileName(domain.Name)
	if err != nil {
		return domainConfigView{}, err
	}
	view := domainConfigView{Mode: "generated", Path: "/etc/nginx/conf.d/" + filename}
	node := state.Nodes[domain.NodeID]
	include := ""
	if node.ControllerInstalled && domain.UpstreamPort == 909 && loopbackHost(domain.UpstreamHost) {
		include = "/etc/nginx-atlas/proxy-token.conf"
	}
	config, err := nginxconfig.Render(nginxconfig.Site{
		Domain: domain.Name, UpstreamHost: domain.UpstreamHost, UpstreamPort: domain.UpstreamPort,
		TLS: domain.CertificateMode != "", CertificateDir: "/etc/ssl/" + domain.Name,
		NginxWebsocket: domain.NginxWebsocket, NginxS3Compatible: domain.NginxS3Compatible,
		NginxHTTP2: domain.NginxHTTP2, ModernHTTP2: modernHTTP2FromVersion(node.NginxVersion),
		NginxGzip: domain.NginxGzip, ProxyHeaderInclude: include,
	})
	if err != nil {
		return domainConfigView{}, err
	}
	view.GeneratedConfig = string(config)
	view.Config = view.GeneratedConfig
	if domain.CustomConfig != "" {
		view.Mode = "custom"
		view.Config = domain.CustomConfig
	}
	hash := sha256.Sum256([]byte(domain.NodeID + "\x00" + string(domain.CertificateMode) + "\x00" + domain.CertificateID + "\x00" + view.Config))
	view.Revision = hex.EncodeToString(hash[:])
	return view, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func modernHTTP2FromVersion(version string) bool {
	match := nginxVersionForConfig.FindStringSubmatch(version)
	if len(match) != 4 {
		return false
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])
	return major > 1 || major == 1 && (minor > 25 || minor == 25 && patch >= 1)
}

func hasActiveCustomConfigJob(state model.State, domainID string) bool {
	for _, job := range state.Jobs {
		if job.DomainID != domainID || job.Type != protocol.JobApplyDomain ||
			(job.Status != model.JobQueued && job.Status != model.JobRunning) {
			continue
		}
		var spec applyDomainSpec
		if json.Unmarshal(job.Payload, &spec) == nil && spec.CustomConfig != nil {
			return true
		}
	}
	return false
}

func (s *Server) handleDomainConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	state := s.store.Snapshot()
	domain, ok := state.Domains[r.PathValue("id")]
	if !ok || domain.ObservedOnly || domain.Deleting {
		writeError(w, http.StatusNotFound, "该域名没有可编辑的 Atlas 配置", "domain_config_unavailable", nil)
		return
	}
	view, err := domainConfig(state, domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法生成当前配置", "domain_config_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleUpdateDomainConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request struct {
		Config   *string `json:"config"`
		Revision string  `json:"revision"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Config == nil || request.Revision == "" {
		writeError(w, http.StatusBadRequest, "配置与版本不能为空", "invalid_domain_config", nil)
		return
	}
	if *request.Config != "" {
		if err := nginxconfig.ValidateCustomConfig(*request.Config); err != nil {
			writeError(w, http.StatusBadRequest, "配置内容无效", "invalid_domain_config", map[string]string{"reason": err.Error()})
			return
		}
	}
	var queued model.Job
	err := s.store.Update(func(state *model.State) error {
		domain, ok := state.Domains[r.PathValue("id")]
		if !ok || domain.ObservedOnly || domain.Deleting {
			return errNotFound
		}
		if node, ok := state.Nodes[domain.NodeID]; !ok || node.Status == model.NodeRevoked {
			return errNotFound
		}
		if hasActiveJob(state, domain.ID, protocol.JobApplyDomain) ||
			hasActiveJob(state, domain.ID, protocol.JobIssueCertificate) ||
			hasActiveJob(state, domain.ID, protocol.JobDeleteDomain) {
			return errConflict
		}
		view, err := domainConfig(*state, domain)
		if err != nil {
			return err
		}
		if view.Revision != request.Revision {
			return errConflict
		}
		certificateID := ""
		if domain.CertificateMode == model.CertificateACME || domain.CertificateMode == model.CertificateUpload {
			certificateID = domain.CertificateID
		}
		if domain.CertificateMode == model.CertificateACME && certificateID == "" {
			return errors.New("certificate has not been issued yet")
		}
		queued, err = enqueueJob(state, domain.NodeID, domain.ID, protocol.JobApplyDomain, applyDomainSpec{
			DomainID: domain.ID, CertificateID: certificateID,
			UseLocalCertificate: domain.CertificateMode == model.CertificateLocal,
			CustomConfig:        request.Config,
		})
		if err != nil {
			return err
		}
		domain.LastJobID = queued.ID
		domain.LastError = ""
		state.Domains[domain.ID] = domain
		s.addAudit(state, "info", "domain.config.queued", fmt.Sprintf("已提交 %s 的完整 Nginx 配置", domain.Name), domain.NodeID, domain.ID, queued.ID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "域名或节点不存在", "not_found", nil)
		return
	}
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "配置已变化或已有任务执行中，请重新打开", "domain_config_conflict", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法下发配置", "invalid_domain_config", map[string]string{"reason": err.Error()})
		return
	}
	queued.Payload = nil
	writeJSON(w, http.StatusAccepted, queued)
}
