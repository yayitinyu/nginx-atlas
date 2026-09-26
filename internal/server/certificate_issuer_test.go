package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
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

type certificateWriterRunner struct {
	certificate []byte
	privateKey  []byte
	credentials map[string]string
}

func (r *certificateWriterRunner) Run(_ context.Context, _ string, args []string, env map[string]string) ([]byte, error) {
	r.credentials = env
	var root string
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--path" {
			root = args[index+1]
			break
		}
	}
	if root == "" {
		return nil, os.ErrInvalid
	}
	directory := filepath.Join(root, "certificates")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(directory, "api.example.com.crt"), r.certificate, 0o600); err != nil {
		return nil, err
	}
	return nil, os.WriteFile(filepath.Join(directory, "api.example.com.key"), r.privateKey, 0o600)
}

func TestControllerIssueQueuesCertificateDistribution(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := box.Seal("dns-account:dns_test", []byte(`{"CLOUDFLARE_DNS_API_TOKEN":"private-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	certificate, privateKey := makeServerTestCertificate(t, "api.example.com", time.Now())
	controller, err := New(Config{AdminToken: strings.Repeat("a", 32), DataRoot: t.TempDir()}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	controller.certificateRoots = x509.NewCertPool()
	if !controller.certificateRoots.AppendCertsFromPEM(certificate) {
		t.Fatal("failed to trust test certificate")
	}
	runner := &certificateWriterRunner{certificate: certificate, privateKey: privateKey}
	controller.certificateRunner = runner
	var issuance model.Job
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_first"] = model.Node{ID: "node_first", Name: "First", Status: model.NodeOffline}
		state.Nodes["node_second"] = model.Node{ID: "node_second", Name: "Second", Status: model.NodeOnline}
		state.DNSAccounts["dns_test"] = model.DNSAccount{ID: "dns_test", Provider: "cloudflare", CredentialsCiphertext: credentials}
		state.ACMEAccounts["acme_test"] = model.ACMEAccount{ID: "acme_test", Email: "admin@example.com", DirectoryURL: "https://acme.example.com/directory"}
		issuance, err = enqueueJob(state, "node_first", "", protocol.JobIssueCertificate, issueCertificateSpec{
			Domain: "api.example.com", DNSNames: []string{"api.example.com"},
			ACMEAccountID: "acme_test", DNSAccountID: "dns_test", Install: true,
			SyncNodeIDs: []string{"node_second"},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := controller.issueNextCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := stateStore.Snapshot()
	if snapshot.Jobs[issuance.ID].Status != model.JobSucceeded {
		t.Fatalf("certificate job did not finish: %+v", snapshot.Jobs[issuance.ID])
	}
	if runner.credentials["CLOUDFLARE_DNS_API_TOKEN"] != "private-token" {
		t.Fatal("controller did not decrypt DNS credentials for lego")
	}
	if len(snapshot.Certificates) != 1 {
		t.Fatalf("created %d certificates, want one", len(snapshot.Certificates))
	}
	var stored model.Certificate
	for _, item := range snapshot.Certificates {
		stored = item
	}
	if len(stored.DeployedNodeIDs) != 0 {
		t.Fatalf("certificate marked deployed before node confirmed it: %v", stored.DeployedNodeIDs)
	}
	var syncCount int
	for _, job := range snapshot.Jobs {
		if job.Type != protocol.JobSyncCertificate {
			continue
		}
		syncCount++
		wired, err := controller.buildWireJob(job, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var payload protocol.SyncCertificatePayload
		if err := json.Unmarshal(wired.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Domain != "api.example.com" || payload.Certificate.FullchainPEM != string(certificate) || payload.Certificate.PrivateKeyPEM != string(privateKey) {
			t.Fatalf("node %s received the wrong certificate", job.NodeID)
		}
	}
	if syncCount != 2 {
		t.Fatalf("queued %d sync jobs, want two", syncCount)
	}
}
