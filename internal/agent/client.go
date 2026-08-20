package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const maxAgentResponseBytes = 8 << 20

type ClientConfig struct {
	ServerURL       string
	NodeName        string
	EnrollmentToken string
	StatePath       string
	CACertPath      string
	PollInterval    time.Duration
	Version         string
}

type Client struct {
	config       ClientConfig
	executor     *Executor
	runner       CommandRunner
	http         *http.Client
	logger       *slog.Logger
	state        clientState
	nextReportAt time.Time
	startedAt    time.Time
}

type clientState struct {
	NodeID string `json:"node_id"`
	Secret string `json:"secret"`
}

type apiResponseError struct {
	Status  int
	Code    string
	Message string
}

func (err *apiResponseError) Error() string {
	if err.Message != "" {
		return fmt.Sprintf("server returned %d: %s", err.Status, err.Message)
	}
	return fmt.Sprintf("server returned %d", err.Status)
}

func NewClient(config ClientConfig, executor *Executor, runner CommandRunner, logger *slog.Logger) (*Client, error) {
	if config.ServerURL == "" {
		return nil, errors.New("server URL is required")
	}
	parsed, err := url.Parse(config.ServerURL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()))) {
		return nil, errors.New("server URL must use HTTPS; HTTP is allowed only for loopback development")
	}
	config.ServerURL = strings.TrimRight(parsed.String(), "/")
	if strings.TrimSpace(config.NodeName) == "" {
		hostname, _ := os.Hostname()
		config.NodeName = hostname
	}
	if config.StatePath == "" {
		config.StatePath = "/var/lib/nginx-atlas/agent.json"
	}
	if config.PollInterval < 3*time.Second {
		config.PollInterval = 10 * time.Second
	}
	if executor == nil {
		return nil, errors.New("executor is required")
	}
	if runner == nil {
		runner = OSCommandRunner{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CACertPath != "" {
		pemData, err := os.ReadFile(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read custom CA certificate: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, errors.New("custom CA file contains no valid certificate")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	client := &Client{
		config: config, executor: executor, runner: runner, logger: logger,
		http: &http.Client{Timeout: 45 * time.Second, Transport: transport}, startedAt: time.Now(),
	}
	if err := client.loadState(); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) Run(ctx context.Context) error {
	if c.state.NodeID == "" {
		if err := c.enroll(ctx); err != nil {
			return err
		}
	}
	c.logger.Info("agent connected", "server", c.config.ServerURL, "node_id", c.state.NodeID)
	for {
		pollAfter, err := c.pollOnce(ctx)
		if err != nil {
			var responseErr *apiResponseError
			if errors.As(err, &responseErr) && responseErr.Status == http.StatusUnauthorized && responseErr.Code == "node_unauthorized" {
				return c.decommissionRevokedAgent(responseErr)
			}
			c.logger.Error("agent poll failed", "error", err)
			pollAfter = c.config.PollInterval
		}
		if pollAfter < 3*time.Second || pollAfter > 5*time.Minute {
			pollAfter = c.config.PollInterval
		}
		timer := time.NewTimer(pollAfter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// Unregister revokes this agent's controller credential before local files are
// removed. The controller retains a hidden tombstone for audit references.
func (c *Client) Unregister(ctx context.Context) error {
	if c.state.NodeID == "" || c.state.Secret == "" {
		return errors.New("agent is not enrolled")
	}
	if err := c.doJSON(ctx, http.MethodDelete, "/api/v1/agent/self", struct{}{}, nil, true); err != nil {
		return fmt.Errorf("unregister agent: %w", err)
	}
	return nil
}

func (c *Client) enroll(ctx context.Context) error {
	if strings.TrimSpace(c.config.EnrollmentToken) == "" {
		return errors.New("agent is not enrolled and no enrollment token was provided")
	}
	request := protocol.EnrollRequest{Token: c.config.EnrollmentToken, Name: c.config.NodeName, Report: c.report(ctx)}
	var response protocol.EnrollResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/enroll", request, &response, false); err != nil {
		return fmt.Errorf("enroll agent: %w", err)
	}
	if response.NodeID == "" || response.NodeSecret == "" {
		return errors.New("enrollment response did not contain node credentials")
	}
	c.state = clientState{NodeID: response.NodeID, Secret: response.NodeSecret}
	if err := c.saveState(); err != nil {
		return err
	}
	return nil
}

func (c *Client) pollOnce(ctx context.Context) (time.Duration, error) {
	var response protocol.PollResponse
	request := protocol.PollRequest{}
	if c.nextReportAt.IsZero() || !time.Now().Before(c.nextReportAt) {
		report := c.report(ctx)
		request.Report = &report
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/poll", request, &response, true); err != nil {
		return c.config.PollInterval, err
	}
	if err := c.confirmPendingUpdate(ctx); err != nil {
		c.logger.Warn("updated service health confirmation is pending", "error", err)
	}
	reportAfter := time.Duration(response.ReportAfter) * time.Second
	if reportAfter < 3*time.Second || reportAfter > 5*time.Minute {
		reportAfter = time.Duration(response.PollAfter) * time.Second
	}
	if reportAfter < 3*time.Second || reportAfter > 5*time.Minute {
		reportAfter = c.config.PollInterval
	}
	nextReportAt := time.Now().Add(reportAfter)
	if request.Report != nil || c.nextReportAt.IsZero() || nextReportAt.Before(c.nextReportAt) {
		c.nextReportAt = nextReportAt
	}
	if response.Job == nil {
		return time.Duration(response.PollAfter) * time.Second, nil
	}
	c.logger.Info("executing job", "job_id", response.Job.ID, "type", response.Job.Type)
	jobTimeout := 15 * time.Minute
	if response.Job.Type == protocol.JobUpdateSystem {
		jobTimeout = 75 * time.Minute
	}
	jobCtx, cancel := context.WithTimeout(ctx, jobTimeout)
	result := c.executor.Execute(jobCtx, *response.Job)
	cancel()
	rollbackScheduled := false
	if result.Success && result.UpdateMarker != "" {
		scheduleCtx, scheduleCancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := scheduleUpdateRollback(scheduleCtx, c.runner, c.executor.config.SystemdRun, c.executor.config.Systemctl, result)
		scheduleCancel()
		if err != nil {
			rollbackErr := rollbackUpdatedBinary(result)
			if rollbackErr == nil {
				_ = os.Remove(result.UpdateMarker)
				_ = os.Remove(result.RollbackHelper)
			}
			result.Success = false
			result.Error = errors.Join(err, rollbackErr).Error()
			result.Message = "更新未激活，旧版本已恢复"
			result.RestartServices = nil
		} else {
			rollbackScheduled = true
		}
	}
	var acknowledgement map[string]any
	path := "/api/v1/agent/jobs/" + url.PathEscape(response.Job.ID) + "/result"
	if err := c.doJSON(ctx, http.MethodPost, path, result, &acknowledgement, true); err != nil {
		if result.UpdateMarker != "" {
			if rollbackErr := rollbackUpdatedBinary(result); rollbackErr == nil {
				_ = os.Remove(result.UpdateMarker)
				_ = os.Remove(result.RollbackHelper)
				if rollbackScheduled {
					cancelUpdateRollback(context.Background(), c.runner, c.executor.config.Systemctl, result.RollbackUnit)
				}
			}
		}
		return c.config.PollInterval, fmt.Errorf("report job result: %w", err)
	}
	c.logger.Info("job completed", "job_id", response.Job.ID, "success", result.Success)
	if result.Success && len(result.RestartServices) > 0 {
		restartCtx, restartCancel := context.WithTimeout(context.Background(), 15*time.Second)
		args := append([]string{"restart", "--no-block"}, result.RestartServices...)
		if _, err := c.runner.Run(restartCtx, c.executor.config.Systemctl, args, nil); err != nil {
			c.logger.Error("updated binary restart failed; restoring previous binary", "error", err)
			if rollbackErr := rollbackUpdatedBinary(result); rollbackErr != nil {
				c.logger.Error("restore previous binary failed", "error", rollbackErr)
			} else if _, rollbackRestartErr := c.runner.Run(restartCtx, c.executor.config.Systemctl, args, nil); rollbackRestartErr != nil {
				c.logger.Error("previous binary restored but service restart failed", "error", rollbackRestartErr)
			} else {
				_ = os.Remove(result.UpdateMarker)
				_ = os.Remove(result.RollbackHelper)
				cancelUpdateRollback(restartCtx, c.runner, c.executor.config.Systemctl, result.RollbackUnit)
			}
		}
		restartCancel()
	}
	return time.Second, nil
}

func rollbackUpdatedBinary(result protocol.JobResultRequest) error {
	if strings.TrimSpace(result.RollbackBinary) == "" || strings.TrimSpace(result.InstalledBinary) == "" {
		return errors.New("update rollback paths are unavailable")
	}
	backup, err := filepath.EvalSymlinks(result.RollbackBinary)
	if err != nil {
		return fmt.Errorf("resolve update backup: %w", err)
	}
	installed, err := filepath.EvalSymlinks(result.InstalledBinary)
	if err != nil {
		installed = result.InstalledBinary
	}
	if err := replaceRegularFile(backup, installed, 0o755); err != nil {
		return fmt.Errorf("restore update backup: %w", err)
	}
	return nil
}

func (c *Client) report(ctx context.Context) protocol.NodeReport {
	hostname, _ := os.Hostname()
	osName, osVersion := readOSRelease()
	report := protocol.NodeReport{
		Hostname: hostname, IPAddresses: interfaceAddresses(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		OSName: osName, OSVersion: osVersion, PackageManager: detectPackageManager(), ControllerInstalled: fileExists("/etc/systemd/system/nginx-atlas-server.service"),
		AgentVersion: c.config.Version, Certificates: c.executor.InventoryCertificates(),
	}
	if output, err := c.runner.Run(ctx, c.executor.config.NginxBinary, []string{"-v"}, nil); err == nil {
		report.NginxVersion = strings.TrimSpace(string(output))
	}
	if _, err := c.runner.Run(ctx, c.executor.config.NginxBinary, []string{"-t"}, nil); err != nil {
		report.LastError = "nginx configuration test failed"
		return report
	}
	report.NginxHealthy = true
	if output, err := c.runner.Run(ctx, c.executor.config.NginxBinary, []string{"-T"}, nil); err == nil {
		report.NginxSites = ParseNginxSites(output)
	} else {
		// nginx -T includes the complete configuration in its combined output.
		// Never report that output because directives may contain credentials.
		report.LastError = "nginx inventory is temporarily unavailable"
	}
	return report
}

func readOSRelease() (string, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	name := values["PRETTY_NAME"]
	if name == "" {
		name = values["NAME"]
	}
	return name, values["VERSION_ID"]
}

func detectPackageManager() string {
	for _, candidate := range []struct {
		name  string
		paths []string
	}{
		{name: "apt", paths: []string{"/usr/bin/apt-get", "/bin/apt-get"}},
		{name: "dnf", paths: []string{"/usr/bin/dnf", "/bin/dnf"}},
		{name: "yum", paths: []string{"/usr/bin/yum", "/bin/yum"}},
	} {
		for _, path := range candidate.paths {
			if fileExists(path) {
				return candidate.name
			}
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody, responseBody any, authenticate bool) error {
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.config.ServerURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if authenticate {
		req.Header.Set("Authorization", "AtlasNode "+c.state.NodeID+"."+c.state.Secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxAgentResponseBytes {
		return errors.New("server response is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiError protocol.APIError
		if json.Unmarshal(body, &apiError) == nil && apiError.Error != "" {
			return &apiResponseError{Status: resp.StatusCode, Code: apiError.Code, Message: apiError.Error}
		}
		return &apiResponseError{Status: resp.StatusCode}
	}
	if responseBody != nil && len(body) > 0 {
		if err := json.Unmarshal(body, responseBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) loadState() error {
	if _, err := os.Stat(c.config.StatePath + ".revoked"); err == nil {
		return errors.New("agent credential was revoked; reinstall with a new enrollment token")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect revoked agent marker: %w", err)
	}
	data, err := os.ReadFile(c.config.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read agent state: %w", err)
	}
	if err := json.Unmarshal(data, &c.state); err != nil {
		return fmt.Errorf("decode agent state: %w", err)
	}
	if c.state.NodeID == "" || c.state.Secret == "" {
		return errors.New("agent state is incomplete")
	}
	return nil
}

func (c *Client) decommissionRevokedAgent(cause error) error {
	nodeID := c.state.NodeID
	c.state = clientState{}
	if err := os.Remove(c.config.StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove revoked agent credential: %w", err)
	}
	marker := []byte("revoked_at=" + time.Now().UTC().Format(time.RFC3339) + "\nnode_id=" + nodeID + "\n")
	if err := writeAtomic(c.config.StatePath+".revoked", marker, 0o600); err != nil {
		return fmt.Errorf("write revoked agent marker: %w", err)
	}
	commandCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = c.runner.Run(commandCtx, c.executor.config.Systemctl, []string{"disable", "nginx-atlas-agent.service"}, nil)
	_, _ = c.runner.Run(commandCtx, c.executor.config.Systemctl, []string{"stop", "--no-block", "nginx-atlas-agent.service"}, nil)
	return fmt.Errorf("controller revoked this agent; local credential removed: %w", cause)
}

func (c *Client) saveState() error {
	if err := os.MkdirAll(filepath.Dir(c.config.StatePath), 0o700); err != nil {
		return fmt.Errorf("create agent state directory: %w", err)
	}
	data, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(c.config.StatePath, data, 0o600); err != nil {
		return fmt.Errorf("save agent state: %w", err)
	}
	return nil
}

func interfaceAddresses() []string {
	addresses, _ := net.InterfaceAddrs()
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		result = append(result, ip.String())
	}
	return result
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
