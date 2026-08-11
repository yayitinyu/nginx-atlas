package agent

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/certutil"
	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/nginxconfig"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const maxCommandOutput = 16 << 10

const maxAtlasReleaseSize = 128 << 20

var (
	providerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envNamePattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,127}$`)
)

type ExecutorConfig struct {
	NginxBinary    string
	Systemctl      string
	LegoBinary     string
	NginxConfigDir string
	SSLRoot        string
	DataRoot       string
}

type Executor struct {
	config ExecutorConfig
	runner CommandRunner
	now    func() time.Time
}

func NewExecutor(config ExecutorConfig, runner CommandRunner) *Executor {
	if config.NginxBinary == "" {
		config.NginxBinary = "nginx"
	}
	if config.Systemctl == "" {
		config.Systemctl = "systemctl"
	}
	if config.LegoBinary == "" {
		config.LegoBinary = "lego"
	}
	if config.NginxConfigDir == "" {
		config.NginxConfigDir = "/etc/nginx/conf.d"
	}
	if config.SSLRoot == "" {
		config.SSLRoot = "/etc/ssl"
	}
	if config.DataRoot == "" {
		config.DataRoot = "/var/lib/nginx-atlas"
	}
	if runner == nil {
		runner = OSCommandRunner{}
	}
	return &Executor{config: config, runner: runner, now: time.Now}
}

func (e *Executor) Execute(ctx context.Context, job protocol.WireJob) protocol.JobResultRequest {
	var result protocol.JobResultRequest
	var err error
	switch job.Type {
	case protocol.JobApplyDomain:
		var payload protocol.ApplyDomainPayload
		err = decodePayload(job.Payload, &payload)
		if err == nil {
			result, err = e.applyDomain(ctx, payload)
		}
	case protocol.JobDeleteDomain:
		var payload protocol.DeleteDomainPayload
		err = decodePayload(job.Payload, &payload)
		if err == nil {
			result, err = e.deleteDomain(ctx, payload)
		}
	case protocol.JobSyncCertificate:
		var payload protocol.SyncCertificatePayload
		err = decodePayload(job.Payload, &payload)
		if err == nil {
			result, err = e.syncCertificate(ctx, payload)
		}
	case protocol.JobIssueCertificate:
		var payload protocol.IssueCertificatePayload
		err = decodePayload(job.Payload, &payload)
		if err == nil {
			result, err = e.issueCertificate(ctx, payload)
		}
	case protocol.JobCaptureCertificate:
		var payload protocol.CaptureCertificatePayload
		err = decodePayload(job.Payload, &payload)
		if err == nil {
			result, err = e.captureCertificate(payload)
		}
	case protocol.JobReloadNginx:
		result, err = e.validateAndReload(ctx)
	case protocol.JobUpdateAtlas:
		var payload protocol.UpdateAtlasPayload
		err = decodePayload(job.Payload, &payload)
		if err == nil {
			result, err = e.updateAtlas(ctx, payload)
		}
	case protocol.JobUpdateSystem:
		var payload protocol.UpdateSystemPayload
		err = decodePayload(job.Payload, &payload)
		if err == nil {
			result, err = e.updateSystem(ctx, payload)
		}
	default:
		err = fmt.Errorf("unsupported job type %q", job.Type)
	}
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		if result.Message == "" {
			result.Message = "任务执行失败"
		}
		return result
	}
	result.Success = true
	return result
}

func (e *Executor) applyDomain(ctx context.Context, payload protocol.ApplyDomainPayload) (protocol.JobResultRequest, error) {
	domain := strings.ToLower(strings.TrimSpace(payload.Domain))
	certDir := filepath.Join(e.config.SSLRoot, domain)
	config, err := nginxconfig.Render(nginxconfig.Site{
		Domain: domain, UpstreamHost: payload.UpstreamHost, UpstreamPort: payload.UpstreamPort,
		TLS: payload.TLS, CertificateDir: certDir,
	})
	if err != nil {
		return protocol.JobResultRequest{}, err
	}
	filename, err := nginxconfig.ConfigFileName(domain)
	if err != nil {
		return protocol.JobResultRequest{}, err
	}
	paths := []string{filepath.Join(e.config.NginxConfigDir, filename)}
	if payload.TLS {
		paths = append(paths, filepath.Join(certDir, "fullchain.pem"), filepath.Join(certDir, "privkey.pem"))
	}
	backup, err := captureFiles(paths)
	if err != nil {
		return protocol.JobResultRequest{}, err
	}
	takeoverChanged := false
	rollback := func() {
		_ = restoreFiles(backup)
		if takeoverChanged {
			_, _ = e.restoreTakeoverConfig(payload.ReplaceConfigPath)
		}
	}

	if payload.Certificate != nil {
		if err := e.installCertificate(domain, *payload.Certificate); err != nil {
			rollback()
			return protocol.JobResultRequest{}, err
		}
	} else if payload.TLS && payload.UseLocalCertificate {
		sourceDir := strings.TrimSpace(payload.LocalCertificateDir)
		if sourceDir == "" {
			sourceDir = certDir
		}
		if err := e.ensureLocalCertificate(domain, sourceDir); err != nil {
			return protocol.JobResultRequest{}, fmt.Errorf("local certificate is unavailable: %w", err)
		}
	} else if payload.TLS {
		return protocol.JobResultRequest{}, errors.New("TLS is enabled but no certificate was supplied")
	}
	if payload.ReplaceConfigPath != "" {
		takeoverChanged, err = e.disableTakeoverConfig(payload.ReplaceConfigPath, paths[0], domain)
		if err != nil {
			rollback()
			return protocol.JobResultRequest{}, fmt.Errorf("disable original nginx site: %w", err)
		}
	}
	if err := writeAtomic(paths[0], config, 0o644); err != nil {
		rollback()
		return protocol.JobResultRequest{}, fmt.Errorf("write nginx site: %w", err)
	}
	output, err := e.runner.Run(ctx, e.config.NginxBinary, []string{"-t"}, nil)
	if err != nil {
		rollback()
		_, _ = e.runner.Run(ctx, e.config.NginxBinary, []string{"-t"}, nil)
		return protocol.JobResultRequest{NginxOutput: limitOutput(output)}, fmt.Errorf("nginx configuration validation failed: %w", err)
	}
	if _, err := e.runner.Run(ctx, e.config.Systemctl, []string{"reload", "nginx"}, nil); err != nil {
		rollback()
		_, _ = e.runner.Run(ctx, e.config.NginxBinary, []string{"-t"}, nil)
		_, _ = e.runner.Run(ctx, e.config.Systemctl, []string{"reload", "nginx"}, nil)
		return protocol.JobResultRequest{NginxOutput: limitOutput(output)}, fmt.Errorf("reload nginx: %w", err)
	}
	result := protocol.JobResultRequest{Message: "Nginx 配置已验证并重载", NginxOutput: limitOutput(output)}
	if payload.CaptureCertificate && payload.TLS {
		bundle, err := e.readAndValidateCertificate(domain)
		if err != nil {
			return result, fmt.Errorf("configuration applied but certificate capture failed: %w", err)
		}
		result.Certificate = &bundle
	}
	return result, nil
}

func (e *Executor) deleteDomain(ctx context.Context, payload protocol.DeleteDomainPayload) (protocol.JobResultRequest, error) {
	domain := strings.ToLower(strings.TrimSpace(payload.Domain))
	filename, err := nginxconfig.ConfigFileName(domain)
	if err != nil {
		return protocol.JobResultRequest{}, err
	}
	path := filepath.Join(e.config.NginxConfigDir, filename)
	backup, err := captureFiles([]string{path})
	if err != nil {
		return protocol.JobResultRequest{}, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return protocol.JobResultRequest{}, fmt.Errorf("remove nginx site: %w", err)
	}
	restoredTakeover := false
	if payload.RestoreConfigPath != "" {
		restored, err := e.restoreTakeoverConfig(payload.RestoreConfigPath)
		if err != nil {
			_ = restoreFiles(backup)
			return protocol.JobResultRequest{}, fmt.Errorf("restore original nginx site: %w", err)
		}
		restoredTakeover = restored
	}
	output, err := e.runner.Run(ctx, e.config.NginxBinary, []string{"-t"}, nil)
	if err != nil {
		if restoredTakeover {
			_, _ = e.disableTakeoverConfig(payload.RestoreConfigPath, path, domain)
		}
		_ = restoreFiles(backup)
		return protocol.JobResultRequest{NginxOutput: limitOutput(output)}, fmt.Errorf("nginx validation after removal failed: %w", err)
	}
	if _, err := e.runner.Run(ctx, e.config.Systemctl, []string{"reload", "nginx"}, nil); err != nil {
		if restoredTakeover {
			_, _ = e.disableTakeoverConfig(payload.RestoreConfigPath, path, domain)
		}
		_ = restoreFiles(backup)
		return protocol.JobResultRequest{NginxOutput: limitOutput(output)}, fmt.Errorf("reload nginx: %w", err)
	}
	message := "域名配置已移除并重载 Nginx"
	if restoredTakeover {
		message = "Atlas 配置已移除，原 Nginx 规则已恢复并重载"
	}
	return protocol.JobResultRequest{Message: message, NginxOutput: limitOutput(output)}, nil
}

func (e *Executor) syncCertificate(ctx context.Context, payload protocol.SyncCertificatePayload) (protocol.JobResultRequest, error) {
	domain := strings.ToLower(strings.TrimSpace(payload.Domain))
	paths := []string{filepath.Join(e.config.SSLRoot, domain, "fullchain.pem"), filepath.Join(e.config.SSLRoot, domain, "privkey.pem")}
	backup, err := captureFiles(paths)
	if err != nil {
		return protocol.JobResultRequest{}, err
	}
	if err := e.installCertificate(domain, payload.Certificate); err != nil {
		_ = restoreFiles(backup)
		return protocol.JobResultRequest{}, err
	}
	if !payload.ReloadNginx {
		return protocol.JobResultRequest{Message: "证书已安全写入节点"}, nil
	}
	result, err := e.validateAndReload(ctx)
	if err != nil {
		_ = restoreFiles(backup)
		_, _ = e.runner.Run(ctx, e.config.Systemctl, []string{"reload", "nginx"}, nil)
		return result, err
	}
	result.Message = "证书已同步，Nginx 配置已验证并重载"
	return result, nil
}

func (e *Executor) issueCertificate(ctx context.Context, payload protocol.IssueCertificatePayload) (protocol.JobResultRequest, error) {
	domains := normalizeRequestedDomains(payload.Domain, payload.Domains)
	if len(domains) == 0 {
		return protocol.JobResultRequest{}, errors.New("certificate domain is missing")
	}
	domain := domains[0]
	if _, err := nginxconfig.ConfigFileName(domain); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("invalid certificate domain: %w", err)
	}
	if !providerPattern.MatchString(payload.DNSProvider) || payload.DNSProvider == "manual" || payload.DNSProvider == "exec" {
		return protocol.JobResultRequest{}, errors.New("DNS provider is invalid or unsafe for unattended execution")
	}
	if _, err := mail.ParseAddress(payload.Email); err != nil {
		return protocol.JobResultRequest{}, errors.New("ACME account email is invalid")
	}
	directory, err := url.Parse(payload.DirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" {
		return protocol.JobResultRequest{}, errors.New("ACME directory must be an HTTPS URL")
	}
	env := make(map[string]string, len(payload.Credentials))
	for key, value := range payload.Credentials {
		if !envNamePattern.MatchString(key) || strings.TrimSpace(value) == "" {
			return protocol.JobResultRequest{}, fmt.Errorf("invalid DNS credential variable %q", key)
		}
		env[key] = value
	}
	accountHash := sha256.Sum256([]byte(strings.ToLower(payload.Email) + "\x00" + payload.DirectoryURL + "\x00" + payload.DNSProvider))
	legoPath := filepath.Join(e.config.DataRoot, "lego", hex.EncodeToString(accountHash[:8]))
	if err := os.MkdirAll(legoPath, 0o700); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("create lego data directory: %w", err)
	}
	args := []string{"run", "--path", legoPath, "--email", payload.Email, "--server", payload.DirectoryURL,
		"--dns", payload.DNSProvider, "--accept-tos", "--renew-days", "30"}
	for _, requestedDomain := range domains {
		if err := validateCertificateName(requestedDomain); err != nil {
			return protocol.JobResultRequest{}, err
		}
		args = append(args, "--domains", requestedDomain)
	}
	if payload.EABKID != "" || payload.EABHMAC != "" {
		if payload.EABKID == "" || payload.EABHMAC == "" {
			return protocol.JobResultRequest{}, errors.New("both EAB KID and HMAC are required")
		}
		args = append(args, "--eab", "--eab.kid", payload.EABKID, "--eab.hmac", payload.EABHMAC)
	}
	output, err := e.runner.Run(ctx, e.config.LegoBinary, args, env)
	if err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(output)}, fmt.Errorf("ACME DNS-01 issuance failed: %w", err)
	}
	certPath, keyPath, err := findLegoCertificate(legoPath, domain)
	if err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(output)}, err
	}
	fullchain, err := os.ReadFile(certPath)
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("read issued certificate: %w", err)
	}
	privateKey, err := os.ReadFile(keyPath)
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("read issued private key: %w", err)
	}
	info, err := certutil.Validate(fullchain, privateKey, domain, e.now())
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("validate issued certificate: %w", err)
	}
	if err := ensureRequestedNames(info.DNSNames, domains); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("validate issued certificate names: %w", err)
	}
	bundle := protocol.CertificateBundle{FullchainPEM: string(fullchain), PrivateKeyPEM: string(privateKey)}
	if payload.Install {
		installed, err := e.syncCertificate(ctx, protocol.SyncCertificatePayload{
			Domain: domain, Certificate: bundle, ReloadNginx: payload.ReloadNginx,
		})
		installed.Certificate = &bundle
		installed.NginxOutput = limitOutput(append(append(output, '\n'), []byte(installed.NginxOutput)...))
		if err != nil {
			return installed, fmt.Errorf("install issued certificate: %w", err)
		}
		installed.Message = "Let's Encrypt DNS-01 证书已签发并安全写入节点"
		return installed, nil
	}
	return protocol.JobResultRequest{
		Message:     "Let's Encrypt DNS-01 证书签发成功",
		Certificate: &bundle,
		NginxOutput: limitOutput(output),
	}, nil
}

func (e *Executor) captureCertificate(payload protocol.CaptureCertificatePayload) (protocol.JobResultRequest, error) {
	domain := strings.ToLower(strings.TrimSpace(payload.Domain))
	if _, err := nginxconfig.ConfigFileName(domain); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("invalid certificate domain: %w", err)
	}
	bundle, err := e.readAndValidateCertificate(domain)
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("capture local certificate: %w", err)
	}
	return protocol.JobResultRequest{Message: "节点现有证书已接管", Certificate: &bundle}, nil
}

func (e *Executor) validateAndReload(ctx context.Context) (protocol.JobResultRequest, error) {
	output, err := e.runner.Run(ctx, e.config.NginxBinary, []string{"-t"}, nil)
	result := protocol.JobResultRequest{NginxOutput: limitOutput(output)}
	if err != nil {
		return result, fmt.Errorf("nginx configuration validation failed: %w", err)
	}
	if _, err := e.runner.Run(ctx, e.config.Systemctl, []string{"reload", "nginx"}, nil); err != nil {
		return result, fmt.Errorf("reload nginx: %w", err)
	}
	result.Message = "Nginx 配置已验证并重载"
	return result, nil
}

func (e *Executor) installCertificate(domain string, bundle protocol.CertificateBundle) error {
	fullchain := []byte(bundle.FullchainPEM)
	privateKey := []byte(bundle.PrivateKeyPEM)
	if _, err := certutil.Validate(fullchain, privateKey, domain, e.now()); err != nil {
		return fmt.Errorf("validate certificate bundle: %w", err)
	}
	dir := filepath.Join(e.config.SSLRoot, domain)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, "fullchain.pem"), fullchain, 0o644); err != nil {
		return fmt.Errorf("write fullchain.pem: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, "privkey.pem"), privateKey, 0o600); err != nil {
		return fmt.Errorf("write privkey.pem: %w", err)
	}
	return nil
}

func (e *Executor) readAndValidateCertificate(domain string) (protocol.CertificateBundle, error) {
	return e.readAndValidateCertificateFrom(filepath.Join(e.config.SSLRoot, domain), domain)
}

func (e *Executor) InventoryCertificates() []model.CertificateMeta {
	entries, err := os.ReadDir(e.config.SSLRoot)
	if err != nil {
		return nil
	}
	result := make([]model.CertificateMeta, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domain := strings.ToLower(entry.Name())
		if _, err := nginxconfig.ConfigFileName(domain); err != nil {
			continue
		}
		dir := filepath.Join(e.config.SSLRoot, entry.Name())
		fullchain, certErr := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
		privateKey, keyErr := os.ReadFile(filepath.Join(dir, "privkey.pem"))
		meta := model.CertificateMeta{Domain: domain, Path: dir}
		if certErr != nil || keyErr != nil {
			meta.Error = "fullchain.pem or privkey.pem is missing or unreadable"
			result = append(result, meta)
			continue
		}
		info, validateErr := certutil.Validate(fullchain, privateKey, domain, e.now())
		if validateErr != nil {
			meta.Error = validateErr.Error()
			result = append(result, meta)
			continue
		}
		meta.FingerprintSHA256 = info.FingerprintSHA256
		meta.Issuer = info.Issuer
		meta.NotAfter = info.NotAfter
		meta.DNSNames = info.DNSNames
		meta.KeyMatches = true
		result = append(result, meta)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Domain < result[j].Domain })
	return result
}

func (e *Executor) updateAtlas(ctx context.Context, payload protocol.UpdateAtlasPayload) (protocol.JobResultRequest, error) {
	if !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(payload.SHA256) {
		return protocol.JobResultRequest{}, errors.New("release checksum is invalid")
	}
	downloadURL, err := url.Parse(strings.TrimSpace(payload.DownloadURL))
	if err != nil || !isTrustedReleaseURL(downloadURL) {
		return protocol.JobResultRequest{}, errors.New("release URL is not a trusted HTTPS GitHub URL")
	}
	if strings.TrimSpace(payload.ExpectedVersion) == "" || len(payload.ExpectedVersion) > 64 {
		return protocol.JobResultRequest{}, errors.New("expected release version is invalid")
	}
	if err := os.MkdirAll(filepath.Join(e.config.DataRoot, "updates"), 0o700); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("create update directory: %w", err)
	}
	archive, err := os.CreateTemp(filepath.Join(e.config.DataRoot, "updates"), "atlas-*.tar.gz")
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("create update download: %w", err)
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)
	client := &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if !isTrustedReleaseURL(request.URL) {
				return errors.New("release download redirected to an untrusted host")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		_ = archive.Close()
		return protocol.JobResultRequest{}, err
	}
	request.Header.Set("User-Agent", "nginx-atlas-agent")
	response, err := client.Do(request)
	if err != nil {
		_ = archive.Close()
		return protocol.JobResultRequest{}, fmt.Errorf("download release: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		_ = archive.Close()
		return protocol.JobResultRequest{}, fmt.Errorf("download release returned HTTP %d", response.StatusCode)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(response.Body, maxAtlasReleaseSize+1))
	closeErr := response.Body.Close()
	archiveCloseErr := archive.Close()
	if copyErr != nil || closeErr != nil || archiveCloseErr != nil {
		return protocol.JobResultRequest{}, errors.Join(copyErr, closeErr, archiveCloseErr)
	}
	if written > maxAtlasReleaseSize {
		return protocol.JobResultRequest{}, errors.New("release archive is too large")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), payload.SHA256) {
		return protocol.JobResultRequest{}, errors.New("release SHA-256 verification failed")
	}
	executable, err := os.Executable()
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("locate current binary: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("resolve current binary: %w", err)
	}
	staged, err := os.CreateTemp(filepath.Dir(executable), ".nginx-atlas-update-*")
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("stage updated binary: %w", err)
	}
	stagedPath := staged.Name()
	_ = staged.Close()
	defer os.Remove(stagedPath)
	if err := extractAtlasBinary(archivePath, stagedPath); err != nil {
		return protocol.JobResultRequest{}, err
	}
	if err := os.Chmod(stagedPath, 0o755); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("make updated binary executable: %w", err)
	}
	versionOutput, err := e.runner.Run(ctx, stagedPath, []string{"version"}, nil)
	if err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("verify updated binary: %w", err)
	}
	actualVersion := strings.TrimSpace(string(versionOutput))
	if strings.TrimPrefix(actualVersion, "v") != strings.TrimPrefix(strings.TrimSpace(payload.ExpectedVersion), "v") {
		return protocol.JobResultRequest{}, fmt.Errorf("updated binary version %q does not match expected %q", actualVersion, payload.ExpectedVersion)
	}
	backupDir := filepath.Join(e.config.DataRoot, "update-backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("create update backup directory: %w", err)
	}
	backupPath := filepath.Join(backupDir, "nginx-atlas-"+e.now().UTC().Format("20060102T150405Z"))
	if err := copyRegularFile(executable, backupPath, 0o700); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("back up current binary: %w", err)
	}
	if err := os.Rename(stagedPath, executable); err != nil {
		return protocol.JobResultRequest{}, fmt.Errorf("install updated binary: %w", err)
	}
	services := []string{"nginx-atlas-agent.service"}
	if _, err := os.Stat("/etc/systemd/system/nginx-atlas-server.service"); err == nil {
		services = append([]string{"nginx-atlas-server.service"}, services...)
	}
	return protocol.JobResultRequest{
		Message:         "Nginx Atlas 已更新至 " + actualVersion + "，服务将在结果确认后重启",
		RestartServices: services,
	}, nil
}

func (e *Executor) updateSystem(ctx context.Context, payload protocol.UpdateSystemPayload) (protocol.JobResultRequest, error) {
	if payload.PackageManager != "apt" {
		return protocol.JobResultRequest{}, errors.New("only the apt package manager is supported")
	}
	var combined []byte
	run := func(name string, args []string, env map[string]string) error {
		output, err := e.runner.Run(ctx, name, args, env)
		combined = append(combined, output...)
		combined = append(combined, '\n')
		return err
	}
	if err := run(e.config.NginxBinary, []string{"-t"}, nil); err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(combined)}, fmt.Errorf("nginx validation before package update failed: %w", err)
	}
	environment := map[string]string{"DEBIAN_FRONTEND": "noninteractive"}
	if err := run("apt-get", []string{"update"}, environment); err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(combined)}, fmt.Errorf("apt update failed: %w", err)
	}
	aptOptions := []string{"-y", "-o", "Dpkg::Options::=--force-confold"}
	if err := run("apt-get", append(append([]string{}, aptOptions...), "upgrade"), environment); err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(combined)}, fmt.Errorf("apt package upgrade failed: %w", err)
	}
	nginxArgs := append(append([]string{}, aptOptions...), "install", "--only-upgrade", "nginx")
	if err := run("apt-get", nginxArgs, environment); err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(combined)}, fmt.Errorf("nginx package upgrade failed: %w", err)
	}
	if err := run(e.config.NginxBinary, []string{"-t"}, nil); err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(combined)}, fmt.Errorf("nginx validation after package update failed: %w", err)
	}
	if err := run(e.config.Systemctl, []string{"enable", "nginx"}, nil); err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(combined)}, fmt.Errorf("enable nginx service: %w", err)
	}
	if err := run(e.config.Systemctl, []string{"reload", "nginx"}, nil); err != nil {
		return protocol.JobResultRequest{NginxOutput: limitOutput(combined)}, fmt.Errorf("reload nginx after package update: %w", err)
	}
	return protocol.JobResultRequest{Message: "APT 软件包与 Nginx 已更新，配置验证通过并完成重载", NginxOutput: limitOutput(combined)}, nil
}

func (e *Executor) disableTakeoverConfig(sourcePath, managedPath, domain string) (bool, error) {
	sourcePath, err := validateTakeoverPath(sourcePath)
	if err != nil {
		return false, err
	}
	if filepath.Clean(sourcePath) == filepath.Clean(managedPath) {
		return false, errors.New("refusing to replace the Atlas-managed configuration itself")
	}
	backupPath := e.takeoverBackupPath(sourcePath)
	_, sourceErr := os.Lstat(sourcePath)
	_, backupErr := os.Lstat(backupPath)
	if errors.Is(sourceErr, os.ErrNotExist) && backupErr == nil {
		// Whole-file takeover already completed earlier; nothing else to move.
		return false, nil
	}
	if sourceErr != nil {
		return false, fmt.Errorf("inspect original config: %w", sourceErr)
	}
	if backupErr == nil {
		// A previous partial/surgical takeover left a backup. Re-apply the
		// domain removal against the current file without clobbering the
		// original full-file backup.
		return e.reapplyTakeoverRemoval(sourcePath, domain)
	}
	if !errors.Is(backupErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect takeover backup: %w", backupErr)
	}
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return false, fmt.Errorf("read original config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		return false, err
	}
	// Preserve the pristine original before any mutation.
	if err := writeAtomic(backupPath, content, 0o600); err != nil {
		return false, fmt.Errorf("write takeover backup: %w", err)
	}
	modified, removed, err := removeServerBlocksForDomain(content, domain)
	if err != nil {
		_ = os.Remove(backupPath)
		return false, err
	}
	if removed == 0 {
		// Domain not found as an isolated server block (unusual). Fall back to
		// whole-file disable so takeover still progresses safely for single-
		// site files that use unusual formatting.
		if err := os.Remove(backupPath); err != nil {
			return false, err
		}
		if err := movePath(sourcePath, backupPath); err != nil {
			return false, err
		}
		return true, nil
	}
	if onlyNginxWhitespace(modified) {
		if err := os.Remove(sourcePath); err != nil {
			_ = os.Remove(backupPath)
			return false, err
		}
		return true, nil
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		_ = os.Remove(backupPath)
		return false, err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0o644
	}
	if err := writeAtomic(sourcePath, modified, mode); err != nil {
		_ = os.Remove(backupPath)
		return false, fmt.Errorf("rewrite shared nginx config: %w", err)
	}
	return true, nil
}

// restoreTakeoverConfig restores a previously disabled original site. It
// returns whether a restore actually happened. Missing backups while the
// original path still exists are treated as a successful no-op so failed
// takeovers that never disabled the original site can still be cleaned up.
func (e *Executor) restoreTakeoverConfig(sourcePath string) (bool, error) {
	sourcePath, err := validateTakeoverPath(sourcePath)
	if err != nil {
		return false, err
	}
	backupPath := e.takeoverBackupPath(sourcePath)
	_, sourceErr := os.Lstat(sourcePath)
	_, backupErr := os.Lstat(backupPath)
	if errors.Is(backupErr, os.ErrNotExist) {
		if sourceErr == nil || errors.Is(sourceErr, os.ErrNotExist) {
			// Takeover never disabled the original file (or it was already
			// restored). Nothing destructive remains to undo.
			return false, nil
		}
		return false, fmt.Errorf("inspect original config: %w", sourceErr)
	}
	if backupErr != nil {
		return false, fmt.Errorf("inspect takeover backup: %w", backupErr)
	}
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return false, fmt.Errorf("read takeover backup: %w", err)
	}
	if sourceErr == nil {
		// Surgical takeovers leave the path occupied with a modified file.
		// Whole-file takeovers leave it missing. Always prefer the pristine
		// backup when present.
		info, err := os.Lstat(sourcePath)
		mode := fs.FileMode(0o644)
		if err == nil && info.Mode().IsRegular() {
			mode = info.Mode().Perm()
		}
		if err := writeAtomic(sourcePath, content, mode); err != nil {
			return false, fmt.Errorf("restore original config: %w", err)
		}
		if err := os.Remove(backupPath); err != nil {
			return false, err
		}
		return true, nil
	}
	if !errors.Is(sourceErr, os.ErrNotExist) {
		return false, sourceErr
	}
	if err := movePath(backupPath, sourcePath); err != nil {
		return false, err
	}
	return true, nil
}

func (e *Executor) reapplyTakeoverRemoval(sourcePath, domain string) (bool, error) {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return false, fmt.Errorf("read shared nginx config: %w", err)
	}
	modified, removed, err := removeServerBlocksForDomain(content, domain)
	if err != nil {
		return false, err
	}
	if removed == 0 {
		return false, nil
	}
	if onlyNginxWhitespace(modified) {
		if err := os.Remove(sourcePath); err != nil {
			return false, err
		}
		return true, nil
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return false, err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0o644
	}
	if err := writeAtomic(sourcePath, modified, mode); err != nil {
		return false, err
	}
	return true, nil
}

// ensureLocalCertificate makes sure /etc/ssl/<domain> has a usable cert that
// covers the vhost. When the real material lives in a shared directory (common
// with wildcard certs), files are linked or copied into the domain directory.
func (e *Executor) ensureLocalCertificate(domain, sourceDir string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	sourceDir = filepath.Clean(strings.TrimSpace(sourceDir))
	if sourceDir == "" || sourceDir == "." || sourceDir == string(filepath.Separator) {
		return errors.New("local certificate directory is invalid")
	}
	targetDir := filepath.Join(e.config.SSLRoot, domain)
	if _, err := e.readAndValidateCertificateFrom(sourceDir, domain); err != nil {
		return err
	}
	if filepath.Clean(sourceDir) == filepath.Clean(targetDir) {
		return nil
	}
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		src := filepath.Join(sourceDir, name)
		dst := filepath.Join(targetDir, name)
		if err := linkOrCopyFile(src, dst); err != nil {
			return fmt.Errorf("materialize %s: %w", name, err)
		}
	}
	if _, err := e.readAndValidateCertificate(domain); err != nil {
		return err
	}
	return nil
}

func (e *Executor) readAndValidateCertificateFrom(dir, domain string) (protocol.CertificateBundle, error) {
	fullchain, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return protocol.CertificateBundle{}, fmt.Errorf("read fullchain.pem: %w", err)
	}
	privateKey, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return protocol.CertificateBundle{}, fmt.Errorf("read privkey.pem: %w", err)
	}
	if _, err := certutil.Validate(fullchain, privateKey, domain, e.now()); err != nil {
		return protocol.CertificateBundle{}, err
	}
	return protocol.CertificateBundle{FullchainPEM: string(fullchain), PrivateKeyPEM: string(privateKey)}, nil
}

func linkOrCopyFile(source, destination string) error {
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(source, destination); err == nil {
		return nil
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if filepath.Base(destination) == "privkey.pem" {
		mode = 0o600
	} else if mode == 0 {
		mode = 0o644
	}
	return copyRegularFile(source, destination, mode)
}

// removeServerBlocksForDomain drops server { ... } blocks whose server_name
// includes the given domain. Other vhosts in the same file are preserved so
// multi-site configs (common with sites-enabled aggregates) survive takeover.
func removeServerBlocksForDomain(content []byte, domain string) ([]byte, int, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, 0, errors.New("domain is required to surgically disable a shared nginx config")
	}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	var (
		output      []string
		block       []string
		depth       int
		inBlock     bool
		removed     int
		keepNewline = strings.HasSuffix(text, "\n")
	)
	flushBlock := func() {
		if !inBlock {
			return
		}
		joined := strings.Join(block, "\n")
		if serverBlockNamesDomain(joined, domain) {
			removed++
		} else {
			output = append(output, block...)
		}
		block = nil
		inBlock = false
		depth = 0
	}
	for _, raw := range lines {
		if !inBlock {
			cleaned := stripNginxComment(raw)
			if serverStartPattern.MatchString(cleaned) {
				inBlock = true
				block = []string{raw}
				depth = braceDelta(cleaned)
				if depth <= 0 {
					flushBlock()
				}
				continue
			}
			output = append(output, raw)
			continue
		}
		block = append(block, raw)
		depth += braceDelta(stripNginxComment(raw))
		if depth <= 0 {
			flushBlock()
		}
	}
	if inBlock {
		// Unbalanced braces: refuse to rewrite so we never corrupt the file.
		return nil, 0, errors.New("nginx config has unbalanced braces; refusing surgical takeover")
	}
	result := strings.Join(output, "\n")
	if keepNewline && !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return []byte(result), removed, nil
}

func serverBlockNamesDomain(block, domain string) bool {
	match := serverNamePattern.FindStringSubmatch(block)
	if len(match) != 2 {
		return false
	}
	for _, name := range strings.Fields(match[1]) {
		name = strings.ToLower(strings.Trim(name, `"'`))
		if name == domain {
			return true
		}
	}
	return false
}

func onlyNginxWhitespace(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(stripNginxComment(line)) != "" {
			return false
		}
	}
	return true
}

func (e *Executor) takeoverBackupPath(sourcePath string) string {
	hash := sha256.Sum256([]byte(filepath.Clean(sourcePath)))
	return filepath.Join(e.config.DataRoot, "takeovers", hex.EncodeToString(hash[:16])+".disabled")
}

func validateTakeoverPath(value string) (string, error) {
	// Nginx nodes are Linux hosts. Using path rather than filepath keeps this
	// security boundary deterministic in cross-platform tests as well.
	cleaned := path.Clean(strings.TrimSpace(value))
	if !path.IsAbs(cleaned) {
		return "", errors.New("takeover config path must be absolute")
	}
	allowed := strings.HasPrefix(cleaned, "/etc/nginx/conf.d/") ||
		strings.HasPrefix(cleaned, "/etc/nginx/sites-enabled/")
	if !allowed {
		return "", errors.New("takeover is limited to /etc/nginx/conf.d and /etc/nginx/sites-enabled")
	}
	return cleaned, nil
}

func movePath(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if err := os.Rename(source, destination); err == nil {
		return nil
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(source)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, destination); err != nil {
			return err
		}
	} else if info.Mode().IsRegular() {
		if err := copyRegularFile(source, destination, info.Mode().Perm()); err != nil {
			return err
		}
	} else {
		return errors.New("takeover source must be a regular file or symbolic link")
	}
	if err := os.Remove(source); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

func copyRegularFile(source, destination string, mode fs.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func extractAtlasBinary(archivePath, destination string) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("open release gzip: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read release archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(filepath.Clean(header.Name)) != "nginx-atlas" {
			continue
		}
		if header.Size <= 0 || header.Size > maxAtlasReleaseSize {
			return errors.New("release binary size is invalid")
		}
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(tarReader, maxAtlasReleaseSize+1))
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if written != header.Size {
			return errors.New("release binary is truncated")
		}
		return nil
	}
	return errors.New("release archive does not contain nginx-atlas")
}

func isTrustedReleaseURL(value *url.URL) bool {
	if value == nil || value.Scheme != "https" {
		return false
	}
	host := strings.ToLower(value.Hostname())
	return host == "github.com" || host == "objects.githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
}

func normalizeRequestedDomains(primary string, requested []string) []string {
	values := append([]string{primary}, requested...)
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func validateCertificateName(value string) error {
	base := value
	if strings.HasPrefix(value, "*.") {
		base = strings.TrimPrefix(value, "*.")
	} else if strings.Contains(value, "*") {
		return fmt.Errorf("invalid wildcard certificate name %q", value)
	}
	if _, err := nginxconfig.ConfigFileName(base); err != nil {
		return fmt.Errorf("invalid certificate name %q", value)
	}
	return nil
}

func ensureRequestedNames(actual, requested []string) error {
	actualSet := make(map[string]bool, len(actual))
	for _, value := range actual {
		actualSet[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range requested {
		if strings.HasPrefix(value, "*.") {
			if !actualSet[value] {
				return fmt.Errorf("certificate does not contain %s", value)
			}
			continue
		}
		if !certutil.CoversHostname(actual, value) {
			return fmt.Errorf("certificate does not cover %s", value)
		}
	}
	return nil
}

type fileBackup struct {
	Path    string
	Data    []byte
	Mode    fs.FileMode
	Existed bool
}

func captureFiles(paths []string) ([]fileBackup, error) {
	backups := make([]fileBackup, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			backups = append(backups, fileBackup{Path: path})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("back up %s: %w", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", path, err)
		}
		backups = append(backups, fileBackup{Path: path, Data: data, Mode: info.Mode().Perm(), Existed: true})
	}
	return backups, nil
}

func restoreFiles(backups []fileBackup) error {
	var joined error
	for _, backup := range backups {
		if !backup.Existed {
			if err := os.Remove(backup.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				joined = errors.Join(joined, err)
			}
			continue
		}
		if err := writeAtomic(backup.Path, backup.Data, backup.Mode); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".atlas-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func findLegoCertificate(root, domain string) (string, string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") || strings.HasSuffix(entry.Name(), ".issuer.crt") {
			return nil
		}
		matches = append(matches, path)
		return nil
	})
	if err != nil {
		return "", "", fmt.Errorf("scan lego certificates: %w", err)
	}
	for _, certPath := range matches {
		keyPath := strings.TrimSuffix(certPath, ".crt") + ".key"
		fullchain, certErr := os.ReadFile(certPath)
		privateKey, keyErr := os.ReadFile(keyPath)
		if certErr != nil || keyErr != nil {
			continue
		}
		if _, err := certutil.Validate(fullchain, privateKey, domain, time.Now()); err == nil {
			return certPath, keyPath, nil
		}
	}
	return "", "", fmt.Errorf("lego did not produce a valid certificate for %s", domain)
}

func decodePayload(data json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode job payload: %w", err)
	}
	return nil
}

func limitOutput(output []byte) string {
	if len(output) > maxCommandOutput {
		output = output[len(output)-maxCommandOutput:]
	}
	return strings.TrimSpace(string(output))
}
