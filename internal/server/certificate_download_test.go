package server

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/certutil"
	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

func TestCertificateDownloadRequiresStepUpAndReturnsProtectedBundle(t *testing.T) {
	stateStore, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := securebox.New(bytes.Repeat([]byte{0x64}, 32))
	if err != nil {
		t.Fatal(err)
	}
	password := "correct horse battery staple"
	passwordHash, err := hashAdminPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	fullchain, privateKey := makeServerTestCertificate(t, "download.example.com", now)
	info, err := certutil.Validate(fullchain, privateKey, "download.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	fullchainCiphertext, err := box.Seal("certificate:crt_download:fullchain", fullchain)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyCiphertext, err := box.Seal("certificate:crt_download:private-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateStore.Update(func(state *model.State) error {
		state.AdminPasswordHash = passwordHash
		state.Certificates["crt_download"] = model.Certificate{
			ID: "crt_download", Domain: "download.example.com", Source: model.CertificateUpload,
			FullchainCiphertext: fullchainCiphertext, PrivateKeyCiphertext: privateKeyCiphertext,
			FingerprintSHA256: info.FingerprintSHA256, Issuer: info.Issuer, SerialNumber: info.SerialNumber,
			NotBefore: info.NotBefore, NotAfter: info.NotAfter, DNSNames: info.DNSNames,
			CreatedAt: now, UpdatedAt: now,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	controller, err := New(Config{AdminToken: strings.Repeat("d", 32)}, stateStore, box, nil)
	if err != nil {
		t.Fatal(err)
	}
	loginNow := now
	controller.loginNow = func() time.Time { return loginNow }

	unauthorized := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/certificates/crt_download/download", map[string]string{"current_password": password}, "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("download without session returned %d", unauthorized.Code)
	}
	login := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/session", map[string]string{"password": password}, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	decodeRecorder(t, login, &session)
	authorization := "Bearer " + session.Token

	wrongPassword := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/certificates/crt_download/download", map[string]string{"current_password": "wrong password"}, authorization)
	if wrongPassword.Code != http.StatusUnauthorized || bytes.Contains(wrongPassword.Body.Bytes(), privateKey) {
		t.Fatalf("wrong-password download returned %d: %s", wrongPassword.Code, wrongPassword.Body.String())
	}

	for {
		allowed, _ := controller.reservePasswordAttempt()
		if !allowed {
			break
		}
	}
	rateLimited := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/certificates/crt_download/download", map[string]string{"current_password": password}, authorization)
	if rateLimited.Code != http.StatusTooManyRequests || rateLimited.Header().Get("Retry-After") == "" {
		t.Fatalf("globally rate-limited download returned %d: %s", rateLimited.Code, rateLimited.Body.String())
	}
	loginNow = loginNow.Add(passwordAttemptRefill)

	download := performJSON(t, controller.Handler(), http.MethodPost, "/api/v1/certificates/crt_download/download", map[string]string{"current_password": password}, authorization)
	if download.Code != http.StatusOK {
		t.Fatalf("download returned %d: %s", download.Code, download.Body.String())
	}
	if got := download.Header().Get("Content-Type"); got != "application/zip" {
		t.Fatalf("content type = %q", got)
	}
	if got := download.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
	if got := download.Header().Get("Content-Disposition"); got != `attachment; filename="download.example.com-certificate.zip"` {
		t.Fatalf("content disposition = %q", got)
	}

	reader, err := zip.NewReader(bytes.NewReader(download.Body.Bytes()), int64(download.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.File) != 2 {
		t.Fatalf("archive has %d files", len(reader.File))
	}
	entries := make(map[string][]byte, len(reader.File))
	permissions := make(map[string]uint32, len(reader.File))
	for _, file := range reader.File {
		opened, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(opened)
		_ = opened.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries[file.Name] = data
		permissions[file.Name] = uint32(file.Mode().Perm())
	}
	if !bytes.Equal(entries["fullchain.pem"], fullchain) || !bytes.Equal(entries["privkey.pem"], privateKey) {
		t.Fatal("downloaded certificate bundle contents do not match stored material")
	}
	if permissions["fullchain.pem"] != 0o644 || permissions["privkey.pem"] != 0o600 {
		t.Fatalf("archive permissions = %#o and %#o", permissions["fullchain.pem"], permissions["privkey.pem"])
	}
	if events := stateStore.Snapshot().Audit; len(events) == 0 || events[0].Action != "certificate.downloaded" {
		t.Fatalf("download audit event missing: %+v", events)
	}
}

func TestBuildCertificateBundleDoesNotUseCallerControlledPaths(t *testing.T) {
	bundle, err := buildCertificateBundle([]byte("certificate"), []byte("private-key"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reader.File {
		if strings.Contains(file.Name, "/") || strings.Contains(file.Name, "\\") || strings.Contains(file.Name, "..") {
			t.Fatalf("unsafe archive path %q", file.Name)
		}
	}
}
