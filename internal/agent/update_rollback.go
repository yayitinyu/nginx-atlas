package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const (
	pendingUpdateName       = "pending-update.json"
	updateConfirmationDelay = 30 * time.Second
)

type pendingUpdate struct {
	ExpectedVersion string    `json:"expected_version"`
	InstalledBinary string    `json:"installed_binary"`
	RollbackBinary  string    `json:"rollback_binary"`
	RestartServices []string  `json:"restart_services"`
	RollbackUnit    string    `json:"rollback_unit"`
	RollbackHelper  string    `json:"rollback_helper"`
	CreatedAt       time.Time `json:"created_at"`
}

func pendingUpdatePath(dataRoot string) string {
	return filepath.Join(dataRoot, "updates", pendingUpdateName)
}

func writePendingUpdate(path string, update pendingUpdate) error {
	if _, err := os.Stat(path); err == nil {
		return errors.New("a previous update is still awaiting health confirmation")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect pending update: %w", err)
	}
	if update.CreatedAt.IsZero() {
		update.CreatedAt = time.Now().UTC()
	}
	encoded, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("encode pending update: %w", err)
	}
	if err := writeAtomic(path, encoded, 0o600); err != nil {
		return fmt.Errorf("write pending update: %w", err)
	}
	return nil
}

func readPendingUpdate(path string) (pendingUpdate, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return pendingUpdate{}, err
	}
	if len(encoded) > 16<<10 {
		return pendingUpdate{}, errors.New("pending update marker is too large")
	}
	var update pendingUpdate
	if err := json.Unmarshal(encoded, &update); err != nil {
		return pendingUpdate{}, fmt.Errorf("decode pending update: %w", err)
	}
	if strings.TrimSpace(update.ExpectedVersion) == "" || !filepath.IsAbs(update.InstalledBinary) || !filepath.IsAbs(update.RollbackBinary) || !filepath.IsAbs(update.RollbackHelper) || len(update.RestartServices) == 0 {
		return pendingUpdate{}, errors.New("pending update marker is incomplete")
	}
	return update, nil
}

func writeRollbackHelper(path string) error {
	const helper = `#!/bin/sh
set -eu
helper=$1
marker=$2
backup=$3
installed=$4
systemctl=$5
shift 5
if [ ! -f "$marker" ]; then
  rm -f -- "$helper"
  exit 0
fi
tmp="${installed}.rollback.$$"
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
install -m 0755 -- "$backup" "$tmp"
mv -f -- "$tmp" "$installed"
"$systemctl" restart --no-block "$@"
rm -f -- "$marker" "$helper"
trap - EXIT HUP INT TERM
`
	if err := writeAtomic(path, []byte(helper), 0o700); err != nil {
		return fmt.Errorf("write update rollback helper: %w", err)
	}
	return nil
}

func scheduleUpdateRollback(ctx context.Context, runner CommandRunner, systemdRun, systemctl string, result protocol.JobResultRequest) error {
	if result.UpdateMarker == "" || result.RollbackBinary == "" || result.RollbackUnit == "" || result.RollbackHelper == "" {
		return errors.New("update rollback metadata is incomplete")
	}
	args := []string{
		"--unit=" + result.RollbackUnit,
		"--on-active=90s",
		"--property=Type=oneshot",
		"/bin/sh",
		result.RollbackHelper,
		result.RollbackHelper,
		result.UpdateMarker,
		result.RollbackBinary,
		result.InstalledBinary,
		systemctl,
	}
	args = append(args, result.RestartServices...)
	if _, err := runner.Run(ctx, systemdRun, args, nil); err != nil {
		return fmt.Errorf("schedule external update rollback: %w", err)
	}
	return nil
}

func cancelUpdateRollback(ctx context.Context, runner CommandRunner, systemctl, unit string) {
	if strings.TrimSpace(unit) == "" {
		return
	}
	_, _ = runner.Run(ctx, systemctl, []string{"stop", unit + ".timer", unit + ".service"}, nil)
}

func (c *Client) confirmPendingUpdate(ctx context.Context) error {
	markerPath := pendingUpdatePath(c.executor.config.DataRoot)
	update, err := readPendingUpdate(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if normalizeVersion(update.ExpectedVersion) != normalizeVersion(c.config.Version) || time.Since(c.startedAt) < updateConfirmationDelay {
		return nil
	}
	for _, service := range update.RestartServices {
		if _, err := c.runner.Run(ctx, c.executor.config.Systemctl, []string{"is-active", "--quiet", service}, nil); err != nil {
			return fmt.Errorf("updated service %s is not healthy: %w", service, err)
		}
	}
	if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("confirm updated services: %w", err)
	}
	cancelUpdateRollback(ctx, c.runner, c.executor.config.Systemctl, update.RollbackUnit)
	_ = os.Remove(update.RollbackHelper)
	c.logger.Info("updated services passed health confirmation", "version", update.ExpectedVersion)
	return nil
}

func replaceRegularFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("rollback source is not a regular file")
	}
	destinationDir := filepath.Dir(destination)
	temporary, err := os.CreateTemp(destinationDir, ".nginx-atlas-rollback-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, input); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	committed = true
	if runtime.GOOS != "windows" {
		directory, err := os.Open(destinationDir)
		if err != nil {
			return err
		}
		defer directory.Close()
		if err := directory.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func normalizeVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}
