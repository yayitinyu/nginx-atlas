package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

type sequenceRunner struct{ nginxTests int }

func (runner *sequenceRunner) Run(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	if name == "nginx" && len(args) == 1 && args[0] == "-t" {
		runner.nginxTests++
		if runner.nginxTests == 1 {
			return []byte("nginx: configuration test failed"), errors.New("exit status 1")
		}
	}
	return []byte("ok"), nil
}

func TestApplyDomainRestoresConfigWhenNginxTestFails(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "nginx")
	sslRoot := filepath.Join(root, "ssl")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "atlas-api.example.com.conf")
	oldConfig := []byte("# previous working config\n")
	if err := os.WriteFile(configPath, oldConfig, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &sequenceRunner{}
	executor := NewExecutor(ExecutorConfig{
		NginxBinary: "nginx", Systemctl: "systemctl", NginxConfigDir: configDir,
		SSLRoot: sslRoot, DataRoot: filepath.Join(root, "data"),
	}, runner)
	payload, _ := json.Marshal(protocol.ApplyDomainPayload{Domain: "api.example.com", UpstreamHost: "127.0.0.1", UpstreamPort: 8080})
	result := executor.Execute(context.Background(), protocol.WireJob{ID: "job_test", Type: protocol.JobApplyDomain, Payload: payload})
	if result.Success {
		t.Fatal("expected nginx validation failure")
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(oldConfig) {
		t.Fatalf("config was not restored: %q", restored)
	}
	if runner.nginxTests < 2 {
		t.Fatal("expected the rolled-back configuration to be validated")
	}
}

func TestValidateTakeoverPathRejectsSiblingDirectoriesAndTraversal(t *testing.T) {
	valid := []string{
		"/etc/nginx/conf.d/legacy.conf",
		"/etc/nginx/sites-enabled/example.com",
		"/etc/nginx/conf.d/nested/../legacy.conf",
	}
	for _, value := range valid {
		if _, err := validateTakeoverPath(value); err != nil {
			t.Errorf("validateTakeoverPath(%q): %v", value, err)
		}
	}
	invalid := []string{
		"/etc/nginx/conf.d",
		"/etc/nginx/conf.d-old/legacy.conf",
		"/etc/nginx/sites-enabled-backup/example.com",
		"/etc/nginx/conf.d/../../passwd",
		"legacy.conf",
	}
	for _, value := range invalid {
		if _, err := validateTakeoverPath(value); err == nil {
			t.Errorf("validateTakeoverPath(%q) unexpectedly succeeded", value)
		}
	}
}
