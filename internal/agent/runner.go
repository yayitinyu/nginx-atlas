package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, extraEnv map[string]string) ([]byte, error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, name string, args []string, extraEnv map[string]string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append([]string(nil), os.Environ()...)
	for key, value := range extraEnv {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s failed: %w", commandLabel(name, args), err)
	}
	return output, nil
}

func commandLabel(name string, args []string) string {
	safe := make([]string, 0, len(args)+1)
	safe = append(safe, name)
	redactNext := false
	for _, arg := range args {
		if redactNext {
			safe = append(safe, "[redacted]")
			redactNext = false
			continue
		}
		if strings.Contains(strings.ToLower(arg), "hmac") {
			safe = append(safe, arg)
			redactNext = true
			continue
		}
		safe = append(safe, arg)
	}
	return strings.Join(safe, " ")
}
