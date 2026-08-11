package protocol

import (
	"encoding/json"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
)

const (
	JobApplyDomain        = "apply_domain"
	JobDeleteDomain       = "delete_domain"
	JobSyncCertificate    = "sync_certificate"
	JobIssueCertificate   = "issue_certificate"
	JobCaptureCertificate = "capture_certificate"
	JobReloadNginx        = "reload_nginx"
)

type EnrollRequest struct {
	Token  string     `json:"token"`
	Name   string     `json:"name"`
	Report NodeReport `json:"report"`
}

type EnrollResponse struct {
	NodeID     string `json:"node_id"`
	NodeSecret string `json:"node_secret"`
	PollAfter  int    `json:"poll_after_seconds"`
}

type NodeReport struct {
	Hostname     string                  `json:"hostname"`
	IPAddresses  []string                `json:"ip_addresses,omitempty"`
	OS           string                  `json:"os"`
	Arch         string                  `json:"arch"`
	NginxVersion string                  `json:"nginx_version,omitempty"`
	NginxHealthy bool                    `json:"nginx_healthy"`
	AgentVersion string                  `json:"agent_version"`
	Certificates []model.CertificateMeta `json:"certificates,omitempty"`
	NginxSites   []model.NginxSiteMeta   `json:"nginx_sites,omitempty"`
	LastError    string                  `json:"last_error,omitempty"`
}

type PollRequest struct {
	Report NodeReport `json:"report"`
}

type PollResponse struct {
	Job       *WireJob  `json:"job,omitempty"`
	PollAfter int       `json:"poll_after_seconds"`
	ServerNow time.Time `json:"server_now"`
}

type WireJob struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type CertificateBundle struct {
	FullchainPEM  string `json:"fullchain_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

type ApplyDomainPayload struct {
	Domain              string             `json:"domain"`
	UpstreamHost        string             `json:"upstream_host"`
	UpstreamPort        int                `json:"upstream_port"`
	TLS                 bool               `json:"tls"`
	UseLocalCertificate bool               `json:"use_local_certificate"`
	Certificate         *CertificateBundle `json:"certificate,omitempty"`
	CaptureCertificate  bool               `json:"capture_certificate"`
}

type DeleteDomainPayload struct {
	Domain string `json:"domain"`
}

type SyncCertificatePayload struct {
	Domain      string            `json:"domain"`
	Certificate CertificateBundle `json:"certificate"`
	ReloadNginx bool              `json:"reload_nginx"`
}

type IssueCertificatePayload struct {
	Domain       string            `json:"domain"`
	Email        string            `json:"email"`
	DirectoryURL string            `json:"directory_url"`
	DNSProvider  string            `json:"dns_provider"`
	Credentials  map[string]string `json:"credentials"`
	EABKID       string            `json:"eab_kid,omitempty"`
	EABHMAC      string            `json:"eab_hmac,omitempty"`
	Install      bool              `json:"install"`
	ReloadNginx  bool              `json:"reload_nginx"`
}

type CaptureCertificatePayload struct {
	Domain string `json:"domain"`
}

type JobResultRequest struct {
	Success     bool               `json:"success"`
	Message     string             `json:"message"`
	Error       string             `json:"error,omitempty"`
	Certificate *CertificateBundle `json:"certificate,omitempty"`
	NginxOutput string             `json:"nginx_output,omitempty"`
}

type APIError struct {
	Error   string            `json:"error"`
	Code    string            `json:"code,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}
