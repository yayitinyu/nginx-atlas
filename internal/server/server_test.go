package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestEnrollmentExchangesOneTimeTokenWithoutPersistingSecrets(t *testing.T) {
	temp := t.TempDir()
	statePath := filepath.Join(temp, "state.json")
	stateStore, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("a", 32)
	controller, err := New(Config{AdminToken: adminToken, PublicURL: "https://atlas.example.com"}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}

	enrollmentRecorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/enrollments", map[string]any{"name": "Tokyo-02", "ttl_minutes": 30}, "Bearer "+adminToken)
	if enrollmentRecorder.Code != http.StatusCreated {
		t.Fatalf("create enrollment returned %d: %s", enrollmentRecorder.Code, enrollmentRecorder.Body.String())
	}
	var enrollment struct {
		Token string `json:"token"`
	}
	decodeRecorder(t, enrollmentRecorder, &enrollment)

	enrollRecorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/enroll", protocol.EnrollRequest{
		Token: enrollment.Token, Name: "ignored", Report: protocol.NodeReport{Hostname: "tokyo", OS: "linux", Arch: "amd64", NginxHealthy: true},
	}, "")
	if enrollRecorder.Code != http.StatusCreated {
		t.Fatalf("enroll returned %d: %s", enrollRecorder.Code, enrollRecorder.Body.String())
	}
	var credentials protocol.EnrollResponse
	decodeRecorder(t, enrollRecorder, &credentials)
	if credentials.NodeID == "" || credentials.NodeSecret == "" {
		t.Fatal("missing node credentials")
	}

	reuseRecorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/enroll", protocol.EnrollRequest{Token: enrollment.Token}, "")
	if reuseRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("one-time token reuse returned %d", reuseRecorder.Code)
	}

	pollRecorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/poll", protocol.PollRequest{Report: protocol.NodeReport{Hostname: "tokyo", OS: "linux", Arch: "amd64", NginxHealthy: true}}, "AtlasNode "+credentials.NodeID+"."+credentials.NodeSecret)
	if pollRecorder.Code != http.StatusOK {
		t.Fatalf("poll returned %d: %s", pollRecorder.Code, pollRecorder.Body.String())
	}

	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte(enrollment.Token)) || bytes.Contains(stateBytes, []byte(credentials.NodeSecret)) {
		t.Fatal("plaintext enrollment or node secret was persisted")
	}
}

func TestDNSAccountCredentialUpdateTrimsTransportWhitespace(t *testing.T) {
	temp := t.TempDir()
	statePath := filepath.Join(temp, "state.json")
	stateStore, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x37}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("c", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}

	created := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/dns-accounts", dnsAccountRequest{
		Name: "Cloudflare", Provider: "cloudflare", Credentials: map[string]string{"CF_DNS_API_TOKEN": " first-token\r\n"},
	}, "Bearer "+adminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("create DNS account returned %d: %s", created.Code, created.Body.String())
	}
	var view dnsAccountView
	decodeRecorder(t, created, &view)

	updated := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/dns-accounts/"+view.ID, dnsAccountRequest{
		Name: "Cloudflare", Provider: "cloudflare", Credentials: map[string]string{"CF_DNS_API_TOKEN": " second-token\r\n"},
	}, "Bearer "+adminToken)
	if updated.Code != http.StatusOK {
		t.Fatalf("update DNS account returned %d: %s", updated.Code, updated.Body.String())
	}

	account := stateStore.Snapshot().DNSAccounts[view.ID]
	plaintext, err := box.Open("dns-account:"+view.ID, account.CredentialsCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	var credentials map[string]string
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		t.Fatal(err)
	}
	if got := credentials["CF_DNS_API_TOKEN"]; got != "second-token" {
		t.Fatalf("credential whitespace was not trimmed: %q", got)
	}
	preserved := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/dns-accounts/"+view.ID, dnsAccountRequest{
		Name: "Cloudflare renamed", Provider: "cloudflare", KeepCredentials: true,
	}, "Bearer "+adminToken)
	if preserved.Code != http.StatusOK {
		t.Fatalf("preserve DNS credentials returned %d: %s", preserved.Code, preserved.Body.String())
	}
	account = stateStore.Snapshot().DNSAccounts[view.ID]
	plaintext, err = box.Open("dns-account:"+view.ID, account.CredentialsCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(plaintext, &credentials); err != nil || credentials["CF_DNS_API_TOKEN"] != "second-token" {
		t.Fatalf("preserved credential changed: %q, %v", credentials["CF_DNS_API_TOKEN"], err)
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte("first-token")) || bytes.Contains(stateBytes, []byte("second-token")) {
		t.Fatal("plaintext DNS credential was persisted")
	}
}

func TestAdminPasswordChangeRotatesBrowserSessions(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	stateStore, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("initial-", 4)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}

	login := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": adminToken}, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	decodeRecorder(t, login, &session)
	changed := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/settings/admin-password", map[string]string{
		"current_password": adminToken, "new_password": "new secure panel password",
	}, "Bearer "+session.Token)
	if changed.Code != http.StatusOK {
		t.Fatalf("change password returned %d: %s", changed.Code, changed.Body.String())
	}
	var rotated struct {
		Token string `json:"token"`
	}
	decodeRecorder(t, changed, &rotated)
	if rotated.Token == "" || rotated.Token == session.Token {
		t.Fatal("password change did not return a rotated session")
	}
	oldSession := performJSON(t, controller.Handler(), http.MethodGet, "/api/v1/session", nil, "Bearer "+session.Token)
	if oldSession.Code != http.StatusUnauthorized {
		t.Fatalf("old session returned %d", oldSession.Code)
	}
	newSession := performJSON(t, controller.Handler(), http.MethodGet, "/api/v1/session", nil, "Bearer "+rotated.Token)
	if newSession.Code != http.StatusOK {
		t.Fatalf("rotated session returned %d: %s", newSession.Code, newSession.Body.String())
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateBytes, []byte("new secure panel password")) || bytes.Contains(stateBytes, []byte(adminToken)) {
		t.Fatal("plaintext administrator credential was persisted")
	}
}

func TestACMEAccountUpdateCanPreserveEncryptedEAB(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x64}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("e", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	created := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/acme-accounts", acmeAccountRequest{
		Name: "External ACME", Email: "ops@example.com", DirectoryURL: "https://acme.example.com/directory",
		EABKID: "kid-1", EABHMAC: "eab-secret",
	}, "Bearer "+adminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("create ACME returned %d: %s", created.Code, created.Body.String())
	}
	var view acmeAccountView
	decodeRecorder(t, created, &view)
	before := stateStore.Snapshot().ACMEAccounts[view.ID].EABHMACCiphertext
	updated := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/acme-accounts/"+view.ID, acmeAccountRequest{
		Name: "External ACME renamed", Email: "ops@example.com", DirectoryURL: "https://acme.example.com/directory", KeepEAB: true,
	}, "Bearer "+adminToken)
	if updated.Code != http.StatusOK {
		t.Fatalf("update ACME returned %d: %s", updated.Code, updated.Body.String())
	}
	after := stateStore.Snapshot().ACMEAccounts[view.ID]
	if after.EABHMACCiphertext != before || after.EABKID != "kid-1" || after.Name != "External ACME renamed" {
		t.Fatalf("EAB was not preserved: %+v", after)
	}
}

func TestAdoptExistingNginxDomainDoesNotRewriteNodeConfiguration(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("n", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_existing"] = model.Node{
			ID: "node_existing", Name: "Existing", Status: model.NodeOnline, CreatedAt: now,
			NginxSites: []model.NginxSiteMeta{{
				Domain: "legacy.example.com", ConfigPath: "/etc/nginx/sites-enabled/legacy.conf",
				UpstreamHost: "127.0.0.1", UpstreamPort: 9000,
			}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	adopted := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/domains/adopt", map[string]string{
		"node_id": "node_existing", "domain": "legacy.example.com", "config_path": "/etc/nginx/sites-enabled/legacy.conf",
	}, "Bearer "+adminToken)
	if adopted.Code != http.StatusCreated {
		t.Fatalf("adopt returned %d: %s", adopted.Code, adopted.Body.String())
	}
	snapshot := stateStore.Snapshot()
	var domain model.Domain
	for _, candidate := range snapshot.Domains {
		domain = candidate
	}
	if !domain.ObservedOnly || !domain.Enabled || domain.LastJobID != "" {
		t.Fatalf("unexpected adopted domain: %+v", domain)
	}
	removed := performJSON(t, controller.Handler(), http.MethodDelete, "/api/v1/domains/"+domain.ID, nil, "Bearer "+adminToken)
	if removed.Code != http.StatusAccepted {
		t.Fatalf("remove observation returned %d: %s", removed.Code, removed.Body.String())
	}
	var response map[string]bool
	decodeRecorder(t, removed, &response)
	if response["queued"] || len(stateStore.Snapshot().Jobs) != 0 {
		t.Fatal("removing an observed domain queued a destructive node job")
	}
}

func TestImportNodeCertificateQueuesReadOnlyCapture(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x63}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("i", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_cert"] = model.Node{ID: "node_cert", Name: "Cert node", Status: model.NodeOnline, CreatedAt: now,
			Certificates: []model.CertificateMeta{{Domain: "cert.example.com", KeyMatches: true, NotAfter: now.Add(60 * 24 * time.Hour)}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	recorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/certificates/import", certificateAutomationRequest{
		Domain: "cert.example.com", NodeID: "node_cert", RenewBeforeDays: 30,
	}, "Bearer "+adminToken)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("import returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var job model.Job
	decodeRecorder(t, recorder, &job)
	if job.Type != protocol.JobCaptureCertificate || job.NodeID != "node_cert" {
		t.Fatalf("unexpected capture job: %+v", job)
	}
}

func TestCertificateRenewalRejectsRevokedIssuerNode(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x65}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("r", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_revoked"] = model.Node{
			ID: "node_revoked", Name: "Revoked", Status: model.NodeRevoked, CreatedAt: now,
		}
		state.DNSAccounts["dns_test"] = model.DNSAccount{ID: "dns_test", Name: "DNS", Provider: "cloudflare"}
		state.ACMEAccounts["acme_test"] = model.ACMEAccount{
			ID: "acme_test", Name: "ACME", Email: "ops@example.com", DirectoryURL: letsEncryptDirectory,
		}
		state.Certificates["crt_revoked"] = model.Certificate{
			ID: "crt_revoked", Domain: "revoked.example.com", NotAfter: now.Add(24 * time.Hour),
			AutoRenew: true, RenewBeforeDays: 30, IssuerNodeID: "node_revoked",
			DNSAccountID: "dns_test", ACMEAccountID: "acme_test", CreatedAt: now, UpdatedAt: now,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	renewed := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/certificates/crt_revoked/renew", nil, "Bearer "+adminToken)
	if renewed.Code != http.StatusBadRequest {
		t.Fatalf("renew on revoked node returned %d: %s", renewed.Code, renewed.Body.String())
	}
	controller.runMaintenance()
	if jobs := stateStore.Snapshot().Jobs; len(jobs) != 0 {
		t.Fatalf("revoked issuer node received renewal jobs: %+v", jobs)
	}
}

func TestCertificateAutoRenewSwitchPersistsAndUpdatesExactDomain(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x66}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("s", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_signer"] = model.Node{ID: "node_signer", Name: "Signer", Status: model.NodeOnline, CreatedAt: now}
		state.DNSAccounts["dns_test"] = model.DNSAccount{ID: "dns_test", Name: "DNS", Provider: "cloudflare"}
		state.ACMEAccounts["acme_test"] = model.ACMEAccount{ID: "acme_test", Name: "ACME", Email: "ops@example.com", DirectoryURL: letsEncryptDirectory}
		state.Certificates["crt_switch"] = model.Certificate{
			ID: "crt_switch", Domain: "switch.example.com", NotAfter: now.Add(60 * 24 * time.Hour), RenewBeforeDays: 30,
			IssuerNodeID: "node_signer", DNSAccountID: "dns_test", ACMEAccountID: "acme_test", CreatedAt: now, UpdatedAt: now,
		}
		state.Domains["dom_exact"] = model.Domain{
			ID: "dom_exact", Name: "switch.example.com", NodeID: "node_signer", CertificateID: "crt_switch",
			DNSAccountID: "dns_test", ACMEAccountID: "acme_test", CreatedAt: now, UpdatedAt: now,
		}
		state.Domains["dom_san"] = model.Domain{
			ID: "dom_san", Name: "alias.example.com", NodeID: "node_signer", CertificateID: "crt_switch",
			DNSAccountID: "dns_test", ACMEAccountID: "acme_test", AutoRenew: true, CreatedAt: now, UpdatedAt: now,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	enabled := true
	response := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/certificates/crt_switch/auto-renew", map[string]*bool{"enabled": &enabled}, "Bearer "+adminToken)
	if response.Code != http.StatusOK {
		t.Fatalf("enable auto-renew returned %d: %s", response.Code, response.Body.String())
	}
	snapshot := stateStore.Snapshot()
	if !snapshot.Certificates["crt_switch"].AutoRenew || !snapshot.Domains["dom_exact"].AutoRenew {
		t.Fatal("enabling certificate auto-renew did not update the exact domain")
	}
	if snapshot.Domains["dom_san"].AutoRenew {
		t.Fatal("SAN alias retained a duplicate domain-level renewal schedule")
	}
	renewed := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/certificates/crt_switch/renew", nil, "Bearer "+adminToken)
	if renewed.Code != http.StatusAccepted {
		t.Fatalf("renew exact domain returned %d: %s", renewed.Code, renewed.Body.String())
	}
	var renewalJob model.Job
	decodeRecorder(t, renewed, &renewalJob)
	if renewalJob.DomainID != "dom_exact" {
		t.Fatalf("certificate renewal targeted %q instead of the exact domain", renewalJob.DomainID)
	}

	disabled := false
	response = performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/certificates/crt_switch/auto-renew", map[string]*bool{"enabled": &disabled}, "Bearer "+adminToken)
	if response.Code != http.StatusOK {
		t.Fatalf("disable auto-renew returned %d: %s", response.Code, response.Body.String())
	}
	snapshot = stateStore.Snapshot()
	if snapshot.Certificates["crt_switch"].AutoRenew || snapshot.Domains["dom_exact"].AutoRenew || snapshot.Domains["dom_san"].AutoRenew {
		t.Fatal("disabling certificate auto-renew left an active schedule")
	}
}

func TestCertificateAutoRenewSwitchRejectsMissingAutomation(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x67}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("t", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Certificates["crt_manual"] = model.Certificate{ID: "crt_manual", Domain: "manual.example.com", NotAfter: now.Add(60 * 24 * time.Hour), CreatedAt: now, UpdatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	enabled := true
	response := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/certificates/crt_manual/auto-renew", map[string]*bool{"enabled": &enabled}, "Bearer "+adminToken)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing automation returned %d: %s", response.Code, response.Body.String())
	}
	if stateStore.Snapshot().Certificates["crt_manual"].AutoRenew {
		t.Fatal("invalid automation configuration was enabled")
	}
}

func TestFailedIssuancePreservesAgentError(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x38}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("d", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}

	enrollmentRecorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/enrollments", map[string]any{"name": "Primary", "ttl_minutes": 30}, "Bearer "+adminToken)
	var enrollment struct {
		Token string `json:"token"`
	}
	decodeRecorder(t, enrollmentRecorder, &enrollment)
	enrollRecorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/enroll", protocol.EnrollRequest{Token: enrollment.Token, Report: protocol.NodeReport{Hostname: "primary"}}, "")
	var credentials protocol.EnrollResponse
	decodeRecorder(t, enrollRecorder, &credentials)

	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Domains["dom_atlas"] = model.Domain{ID: "dom_atlas", Name: "atlas.example.com", NodeID: credentials.NodeID, CreatedAt: now, UpdatedAt: now}
		state.Jobs["job_issue"] = model.Job{
			ID: "job_issue", NodeID: credentials.NodeID, DomainID: "dom_atlas", Type: protocol.JobIssueCertificate,
			Status: model.JobRunning, Attempts: 3, MaxAttempts: 3, CreatedAt: now, StartedAt: &now,
		}
		node := state.Nodes[credentials.NodeID]
		node.RunningJobID = "job_issue"
		state.Nodes[node.ID] = node
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	wantError := "ACME DNS-01 issuance failed: exit status 1"
	resultRecorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/agent/jobs/job_issue/result", protocol.JobResultRequest{
		Success: false, Error: wantError,
	}, "AtlasNode "+credentials.NodeID+"."+credentials.NodeSecret)
	if resultRecorder.Code != http.StatusOK {
		t.Fatalf("submit failed result returned %d: %s", resultRecorder.Code, resultRecorder.Body.String())
	}
	snapshot := stateStore.Snapshot()
	if got := snapshot.Jobs["job_issue"].Error; got != wantError {
		t.Fatalf("job error was overwritten: got %q want %q", got, wantError)
	}
	if got := snapshot.Domains["dom_atlas"].LastError; got != wantError {
		t.Fatalf("domain error was overwritten: got %q want %q", got, wantError)
	}
}

func TestCreateDomainLinksUploadedCertificateToRenewalAccounts(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("b", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_primary"] = model.Node{ID: "node_primary", Name: "Primary", Status: model.NodeOnline, CreatedAt: now}
		state.Certificates["crt_wildcard"] = model.Certificate{
			ID: "crt_wildcard", Domain: "*.example.com", Source: model.CertificateUpload,
			DNSNames: []string{"*.example.com"}, NotAfter: now.Add(60 * 24 * time.Hour), CreatedAt: now, UpdatedAt: now,
		}
		state.DNSAccounts["dns_cloudflare"] = model.DNSAccount{ID: "dns_cloudflare", Name: "Cloudflare", Provider: "cloudflare", CreatedAt: now, UpdatedAt: now}
		state.ACMEAccounts["acme_letsencrypt"] = model.ACMEAccount{ID: "acme_letsencrypt", Name: "Let's Encrypt", Email: "ops@example.com", CreatedAt: now, UpdatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	request := createDomainRequest{
		Domain: "api.example.com", NodeID: "node_primary", UpstreamHost: "127.0.0.1", UpstreamPort: 8080,
		CertificateMode: "upload", CertificateID: "crt_wildcard", AutoRenew: true, RenewBeforeDays: 30,
	}
	missingAccounts := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/domains", request, "Bearer "+adminToken)
	if missingAccounts.Code != http.StatusBadRequest {
		t.Fatalf("missing renewal accounts returned %d: %s", missingAccounts.Code, missingAccounts.Body.String())
	}

	request.ACMEAccountID = "acme_letsencrypt"
	request.DNSAccountID = "dns_cloudflare"
	created := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/domains", request, "Bearer "+adminToken)
	if created.Code != http.StatusAccepted {
		t.Fatalf("create domain returned %d: %s", created.Code, created.Body.String())
	}

	snapshot := stateStore.Snapshot()
	certificate := snapshot.Certificates["crt_wildcard"]
	if !certificate.AutoRenew || certificate.ACMEAccountID != request.ACMEAccountID || certificate.DNSAccountID != request.DNSAccountID {
		t.Fatalf("certificate renewal link was not persisted: %+v", certificate)
	}
}

func TestRenewalReusesCertificateRecord(t *testing.T) {
	box, err := securebox.New(bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	controller := &Server{box: box}
	now := time.Now().UTC()
	createdAt := now.Add(-60 * 24 * time.Hour)
	state := model.NewState()
	state.Domains["dom_api"] = model.Domain{
		ID: "dom_api", Name: "api.example.com", NodeID: "node_primary", CertificateID: "crt_existing",
		AutoRenew: true, ACMEAccountID: "acme_letsencrypt", DNSAccountID: "dns_cloudflare",
	}
	state.Certificates["crt_existing"] = model.Certificate{
		ID: "crt_existing", Domain: "api.example.com", CreatedAt: createdAt,
		DeployedNodeIDs: []string{"node_primary", "node_backup"},
	}
	certPEM, keyPEM := makeServerTestCertificate(t, "api.example.com", now)
	prepared, err := controller.prepareCertificateResult(state, model.Job{
		ID: "job_renew", NodeID: "node_primary", DomainID: "dom_api", Type: protocol.JobIssueCertificate,
	}, &protocol.CertificateBundle{FullchainPEM: string(certPEM), PrivateKeyPEM: string(keyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ID != "crt_existing" || !prepared.CreatedAt.Equal(createdAt) {
		t.Fatalf("renewal replaced certificate identity: %+v", prepared)
	}
	if len(prepared.DeployedNodeIDs) != 2 {
		t.Fatalf("renewal lost deployment metadata: %+v", prepared.DeployedNodeIDs)
	}
}

func TestTakeoverExistingNginxDomainQueuesTransactionalReplacement(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("t", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_takeover"] = model.Node{
			ID: "node_takeover", Name: "Takeover", Status: model.NodeOnline, CreatedAt: now,
			NginxSites: []model.NginxSiteMeta{{
				Domain: "legacy.example.com", ConfigPath: "/etc/nginx/sites-enabled/legacy.conf",
				UpstreamHost: "127.0.0.1", UpstreamPort: 9000,
			}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	recorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/domains/adopt", map[string]any{
		"node_id": "node_takeover", "domain": "legacy.example.com",
		"config_path": "/etc/nginx/sites-enabled/legacy.conf", "takeover": true,
	}, "Bearer "+adminToken)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("takeover returned %d: %s", recorder.Code, recorder.Body.String())
	}
	snapshot := stateStore.Snapshot()
	var domain model.Domain
	for _, candidate := range snapshot.Domains {
		domain = candidate
	}
	if domain.ObservedOnly || !domain.TakenOver || domain.LastJobID == "" {
		t.Fatalf("takeover state is incomplete: %+v", domain)
	}
	job := snapshot.Jobs[domain.LastJobID]
	if job.Type != protocol.JobApplyDomain {
		t.Fatalf("unexpected takeover job: %+v", job)
	}
	var spec applyDomainSpec
	if err := json.Unmarshal(job.Payload, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.ReplaceConfigPath != domain.ConfigPath {
		t.Fatalf("takeover job did not preserve original path: %+v", spec)
	}
}

func TestTakeoverPassesSharedWildcardCertificateDirectory(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.Repeat("w", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_wildcard"] = model.Node{
			ID: "node_wildcard", Name: "Wildcard", Status: model.NodeOnline, CreatedAt: now,
			Certificates: []model.CertificateMeta{{
				Domain: "example.com", DNSNames: []string{"*.example.com", "example.com"},
				NotAfter: now.Add(60 * 24 * time.Hour), KeyMatches: true,
			}},
			NginxSites: []model.NginxSiteMeta{{
				Domain: "api.example.com", ConfigPath: "/etc/nginx/sites-enabled/fandai.conf",
				UpstreamHost: "127.0.0.1", UpstreamPort: 8080, TLS: true,
				CertificatePath: "/etc/ssl/example.com/fullchain.pem",
			}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	recorder := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/domains/adopt", map[string]any{
		"node_id": "node_wildcard", "domain": "api.example.com",
		"config_path": "/etc/nginx/sites-enabled/fandai.conf", "takeover": true,
	}, "Bearer "+adminToken)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("takeover returned %d: %s", recorder.Code, recorder.Body.String())
	}
	snapshot := stateStore.Snapshot()
	var domain model.Domain
	for _, candidate := range snapshot.Domains {
		domain = candidate
	}
	job := snapshot.Jobs[domain.LastJobID]
	var spec applyDomainSpec
	if err := json.Unmarshal(job.Payload, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.LocalCertificateDir != "/etc/ssl/example.com" {
		t.Fatalf("expected shared cert dir, got %+v", spec)
	}
	if !spec.UseLocalCertificate || spec.ReplaceConfigPath != "/etc/nginx/sites-enabled/fandai.conf" {
		t.Fatalf("unexpected takeover spec: %+v", spec)
	}
}

func TestNodeHasValidCertificateRequiresCoverage(t *testing.T) {
	now := time.Now().UTC()
	node := model.Node{
		Certificates: []model.CertificateMeta{{
			Domain: "other.example.com", DNSNames: []string{"other.example.com"},
			NotAfter: now.Add(time.Hour),
		}},
		NginxSites: []model.NginxSiteMeta{{
			Domain: "api.example.com", TLS: true,
		}},
	}
	if nodeHasValidCertificate(node, "api.example.com") {
		t.Fatal("expected missing certificate coverage to fail")
	}
	node.Certificates = append(node.Certificates, model.CertificateMeta{
		Domain: "example.com", DNSNames: []string{"*.example.com", "example.com"},
	})
	if !nodeHasValidCertificate(node, "api.example.com") {
		t.Fatal("expected wildcard coverage to pass")
	}
}

func TestRenameNodeUpdatesOnlyDisplayName(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x74}, 32))
	adminToken := strings.Repeat("u", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = stateStore.Update(func(state *model.State) error {
		state.Nodes["node_rename"] = model.Node{ID: "node_rename", Name: "Old name", SecretHash: "secret", Status: model.NodeOnline, CreatedAt: now}
		return nil
	})
	recorder := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/nodes/node_rename", map[string]string{"name": "Tokyo edge"}, "Bearer "+adminToken)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rename returned %d: %s", recorder.Code, recorder.Body.String())
	}
	node := stateStore.Snapshot().Nodes["node_rename"]
	if node.Name != "Tokyo edge" || node.SecretHash != "secret" {
		t.Fatalf("rename changed unexpected node state: %+v", node)
	}
}

func TestCertificateAutomationSupportsWildcardSANs(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := securebox.New(bytes.Repeat([]byte{0x75}, 32))
	adminToken := strings.Repeat("v", 32)
	controller, err := New(Config{AdminToken: adminToken}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = stateStore.Update(func(state *model.State) error {
		state.Nodes["node_issue"] = model.Node{ID: "node_issue", Name: "Issuer", Status: model.NodeOnline, CreatedAt: now}
		state.DNSAccounts["dns_cf"] = model.DNSAccount{ID: "dns_cf", Name: "Cloudflare", Provider: "cloudflare"}
		state.ACMEAccounts["acme_le"] = model.ACMEAccount{ID: "acme_le", Name: "Let's Encrypt", Email: "ops@example.com", DirectoryURL: letsEncryptDirectory}
		state.Certificates["crt_san"] = model.Certificate{ID: "crt_san", Domain: "nanami.im", DNSNames: []string{"nanami.im"}, NotAfter: now.Add(60 * 24 * time.Hour), CreatedAt: now, UpdatedAt: now}
		return nil
	})
	recorder := performJSON(t, controller.Handler(), http.MethodPut, "/api/v1/certificates/crt_san/automation", map[string]any{
		"node_id": "node_issue", "dns_account_id": "dns_cf", "acme_account_id": "acme_le",
		"auto_renew": true, "renew_before_days": 21, "dns_names": []string{"nanami.im", "*.nanami.im"},
	}, "Bearer "+adminToken)
	if recorder.Code != http.StatusOK {
		t.Fatalf("automation update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	certificate := stateStore.Snapshot().Certificates["crt_san"]
	if !certificate.AutoRenew || certificate.RenewBeforeDays != 21 || len(certificate.RequestedDNSNames) != 2 || certificate.RequestedDNSNames[1] != "*.nanami.im" {
		t.Fatalf("SAN automation was not saved: %+v", certificate)
	}
}

func TestCloudflareClientEditsExistingRecordWithBearerToken(t *testing.T) {
	var patched cloudflareRecordRequest
	var authorized bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized = authorized || r.Header.Get("Authorization") == "Bearer test-token"
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zone-1","name":"example.com"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-1/dns_records":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"record-1","type":"A","name":"api.example.com","content":"192.0.2.1"}]}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/zones/zone-1/dns_records/record-1":
			_ = json.NewDecoder(r.Body).Decode(&patched)
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"record-1"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	client, err := newCloudflareClient(api.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	zone, err := client.findZone(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	records, err := client.listRecords(context.Background(), zone.ID, "A", "api.example.com")
	if err != nil || len(records) != 1 {
		t.Fatalf("list records failed: %v %+v", err, records)
	}
	if err := client.editRecord(context.Background(), zone.ID, records[0].ID, cloudflareRecordRequest{Type: "A", Name: "api.example.com", Content: "198.51.100.8", TTL: 1, Proxied: true}); err != nil {
		t.Fatal(err)
	}
	if !authorized || patched.Content != "198.51.100.8" || !patched.Proxied || patched.TTL != 1 {
		t.Fatalf("unexpected Cloudflare request: authorized=%v payload=%+v", authorized, patched)
	}
}

func TestTakeoverPathRequiresExactNginxDirectoryBoundary(t *testing.T) {
	valid := []string{
		"/etc/nginx/conf.d/legacy.conf",
		"/etc/nginx/sites-enabled/example.com",
		"/etc/nginx/conf.d/nested/../legacy.conf",
	}
	for _, value := range valid {
		if !validReportedTakeoverPath(value) {
			t.Fatalf("expected takeover path to be accepted: %s", value)
		}
	}
	invalid := []string{
		"/etc/nginx/conf.d",
		"/etc/nginx/conf.d-archive/legacy.conf",
		"/etc/nginx/sites-enabled-old/example.com",
		"/etc/nginx/conf.d/../../passwd",
		"relative.conf",
	}
	for _, value := range invalid {
		if validReportedTakeoverPath(value) {
			t.Fatalf("expected takeover path to be rejected: %s", value)
		}
	}
}

func TestVersionUpdateAvailableOnlyAllowsNewerRelease(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{current: "0.1.0", latest: "0.2.0", want: true},
		{current: "v1.9.9", latest: "v2.0.0", want: true},
		{current: "1.2.0-rc.1", latest: "1.2.0", want: true},
		{current: "1.2.0", latest: "1.2.0", want: false},
		{current: "1.3.0", latest: "1.2.9", want: false},
		{current: "dev", latest: "1.0.0", want: false},
		{current: "broken", latest: "1.0.0", want: false},
	}
	for _, test := range tests {
		if got := versionUpdateAvailable(test.current, test.latest); got != test.want {
			t.Errorf("versionUpdateAvailable(%q, %q) = %v, want %v", test.current, test.latest, got, test.want)
		}
	}
}

func makeServerTestCertificate(t *testing.T, domain string, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func performJSON(t *testing.T, handler http.Handler, method, path string, body any, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeRecorder(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	data, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode response: %v: %s", err, data)
	}
}
