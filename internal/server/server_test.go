package server

import (
	"bytes"
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
