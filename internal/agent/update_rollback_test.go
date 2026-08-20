package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

type recordedCommand struct {
	name string
	args []string
}

type recordingCommandRunner struct {
	calls []recordedCommand
}

func (runner *recordingCommandRunner) Run(_ context.Context, name string, args []string, _ map[string]string) ([]byte, error) {
	runner.calls = append(runner.calls, recordedCommand{name: name, args: append([]string(nil), args...)})
	return nil, nil
}

func TestReplaceRegularFileAtomicallyReplacesInstalledBinary(t *testing.T) {
	root := t.TempDir()
	backup := filepath.Join(root, "backup")
	installed := filepath.Join(root, "nginx-atlas")
	if err := os.WriteFile(backup, []byte("known-good"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, []byte("broken-update"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceRegularFile(backup, installed, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "known-good" {
		t.Fatalf("installed binary = %q", got)
	}
}

func TestScheduleUpdateRollbackUsesIndependentShellHelper(t *testing.T) {
	runner := &recordingCommandRunner{}
	result := protocol.JobResultRequest{
		UpdateMarker:    "/var/lib/nginx-atlas/agent/updates/pending-update.json",
		RollbackBinary:  "/var/lib/nginx-atlas/agent/update-backups/nginx-atlas-old",
		InstalledBinary: "/usr/local/bin/nginx-atlas",
		RollbackHelper:  "/var/lib/nginx-atlas/agent/updates/rollback.sh",
		RollbackUnit:    "nginx-atlas-update-rollback-test",
		RestartServices: []string{"nginx-atlas-server.service", "nginx-atlas-agent.service"},
	}
	if err := scheduleUpdateRollback(context.Background(), runner, "systemd-run", "systemctl", result); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "systemd-run" {
		t.Fatalf("calls = %+v", runner.calls)
	}
	joined := strings.Join(runner.calls[0].args, " ")
	if !strings.Contains(joined, "/bin/sh "+result.RollbackHelper) || strings.Contains(joined, result.RollbackBinary+" rollback-update") {
		t.Fatalf("rollback is not independent from the old binary: %s", joined)
	}
}

func TestConfirmPendingUpdateRequiresStableMatchingAgentAndActiveServices(t *testing.T) {
	root := t.TempDir()
	markerPath := pendingUpdatePath(root)
	helperPath := filepath.Join(root, "updates", "rollback.sh")
	if err := writeRollbackHelper(helperPath); err != nil {
		t.Fatal(err)
	}
	update := pendingUpdate{
		ExpectedVersion: "v1.2.3",
		InstalledBinary: filepath.Join(root, "nginx-atlas"),
		RollbackBinary:  filepath.Join(root, "nginx-atlas-old"),
		RollbackHelper:  helperPath,
		RestartServices: []string{"nginx-atlas-agent.service"},
		RollbackUnit:    "nginx-atlas-update-rollback-test",
	}
	if err := writePendingUpdate(markerPath, update); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{}
	client := &Client{
		config:    ClientConfig{Version: "1.2.3"},
		executor:  NewExecutor(ExecutorConfig{DataRoot: root, Systemctl: "systemctl"}, runner),
		runner:    runner,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		startedAt: time.Now().Add(-updateConfirmationDelay - time.Second),
	}
	if err := client.confirmPendingUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("confirmed marker still exists: %v", err)
	}
	if _, err := os.Stat(helperPath); !os.IsNotExist(err) {
		t.Fatalf("confirmed rollback helper still exists: %v", err)
	}
	if len(runner.calls) != 2 || runner.calls[0].args[0] != "is-active" || runner.calls[1].args[0] != "stop" {
		t.Fatalf("health confirmation calls = %+v", runner.calls)
	}
}
