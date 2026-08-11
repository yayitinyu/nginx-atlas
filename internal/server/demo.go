package server

import (
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func seedDemoState(stateStore *store.Store) error {
	return stateStore.Update(func(state *model.State) error {
		if len(state.Nodes) > 0 || len(state.Domains) > 0 {
			return nil
		}
		now := time.Now().UTC()
		nodes := []model.Node{
			{ID: "node_demo_shanghai", Name: "Shanghai-01", Status: model.NodeOnline, Hostname: "edge-sh-01", IPAddresses: []string{"203.0.113.10"}, OS: "linux", Arch: "amd64", NginxVersion: "nginx/1.26.3", NginxHealthy: true, AgentVersion: "dev", LastSeenAt: &now, CreatedAt: now.Add(-48 * time.Hour)},
			{ID: "node_demo_tokyo", Name: "Tokyo-02", Status: model.NodeOnline, Hostname: "edge-tyo-02", IPAddresses: []string{"203.0.113.20"}, OS: "linux", Arch: "amd64", NginxVersion: "nginx/1.26.3", NginxHealthy: true, AgentVersion: "dev", LastSeenAt: &now, CreatedAt: now.Add(-36 * time.Hour)},
			{ID: "node_demo_frankfurt", Name: "Frankfurt-01", Status: model.NodeOnline, Hostname: "edge-fra-01", IPAddresses: []string{"203.0.113.30"}, OS: "linux", Arch: "arm64", NginxVersion: "nginx/1.26.3", NginxHealthy: true, AgentVersion: "dev", LastSeenAt: &now, CreatedAt: now.Add(-24 * time.Hour)},
		}
		for _, node := range nodes {
			state.Nodes[node.ID] = node
		}
		certificates := []model.Certificate{
			{ID: "crt_demo_api", Domain: "api.example.com", Source: model.CertificateACME, Issuer: "Let's Encrypt E6", SerialNumber: "0a11ce", NotBefore: now.Add(-11 * 24 * time.Hour), NotAfter: now.Add(79 * 24 * time.Hour), DNSNames: []string{"api.example.com"}, AutoRenew: true, RenewBeforeDays: 30, ACMEAccountID: "acme_demo", DNSAccountID: "dns_demo", IssuerNodeID: "node_demo_shanghai", DeployedNodeIDs: []string{"node_demo_shanghai"}, CreatedAt: now.Add(-11 * 24 * time.Hour), UpdatedAt: now.Add(-11 * 24 * time.Hour)},
			{ID: "crt_demo_studio", Domain: "studio.example.com", Source: model.CertificateUpload, Issuer: "Let's Encrypt R11", SerialNumber: "0b22df", NotBefore: now.Add(-69 * 24 * time.Hour), NotAfter: now.Add(21 * 24 * time.Hour), DNSNames: []string{"studio.example.com"}, AutoRenew: true, RenewBeforeDays: 30, ACMEAccountID: "acme_demo", DNSAccountID: "dns_demo", IssuerNodeID: "node_demo_tokyo", DeployedNodeIDs: []string{"node_demo_tokyo"}, CreatedAt: now.Add(-69 * 24 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour)},
		}
		for _, certificate := range certificates {
			state.Certificates[certificate.ID] = certificate
		}
		domains := []model.Domain{
			{ID: "dom_demo_api", Name: "api.example.com", NodeID: "node_demo_shanghai", UpstreamHost: "127.0.0.1", UpstreamPort: 8080, CertificateID: "crt_demo_api", CertificateMode: model.CertificateACME, ACMEAccountID: "acme_demo", DNSAccountID: "dns_demo", AutoRenew: true, RenewBeforeDays: 30, SyncNodeIDs: []string{"node_demo_frankfurt"}, Enabled: true, CreatedAt: now.Add(-11 * 24 * time.Hour), UpdatedAt: now.Add(-8 * time.Minute)},
			{ID: "dom_demo_studio", Name: "studio.example.com", NodeID: "node_demo_tokyo", UpstreamHost: "127.0.0.1", UpstreamPort: 3000, CertificateID: "crt_demo_studio", CertificateMode: model.CertificateUpload, ACMEAccountID: "acme_demo", DNSAccountID: "dns_demo", AutoRenew: true, RenewBeforeDays: 30, SyncNodeIDs: []string{"node_demo_frankfurt"}, Enabled: true, CreatedAt: now.Add(-69 * 24 * time.Hour), UpdatedAt: now.Add(-12 * time.Minute)},
		}
		for _, domain := range domains {
			state.Domains[domain.ID] = domain
		}
		state.DNSAccounts["dns_demo"] = model.DNSAccount{ID: "dns_demo", Name: "Cloudflare demo", Provider: "cloudflare", CreatedAt: now, UpdatedAt: now}
		state.ACMEAccounts["acme_demo"] = model.ACMEAccount{ID: "acme_demo", Name: "Let's Encrypt demo", Email: "demo@example.com", DirectoryURL: letsEncryptDirectory, CreatedAt: now, UpdatedAt: now}
		state.Audit = []model.AuditEvent{
			{ID: "evt_demo_1", Level: "success", Action: "nginx.reloaded", Message: "Nginx 配置已验证并重载", NodeID: "node_demo_shanghai", DomainID: "dom_demo_api", CreatedAt: now.Add(-1 * time.Minute)},
			{ID: "evt_demo_2", Level: "warning", Action: "certificate.expiring", Message: "证书将在 21 天后到期", NodeID: "node_demo_tokyo", DomainID: "dom_demo_studio", CreatedAt: now.Add(-12 * time.Minute)},
			{ID: "evt_demo_3", Level: "success", Action: "node.recovered", Message: "节点 Tokyo-02 状态恢复正常", NodeID: "node_demo_tokyo", CreatedAt: now.Add(-28 * time.Minute)},
		}
		return nil
	})
}
