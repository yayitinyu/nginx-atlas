package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/agent"
	"github.com/yayitinyu/nginx-atlas/internal/securebox"
	"github.com/yayitinyu/nginx-atlas/internal/server"
	"github.com/yayitinyu/nginx-atlas/internal/store"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("nginx-atlas stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return usageError()
	}
	switch os.Args[1] {
	case "server":
		return runServer(os.Args[2:])
	case "agent":
		return runAgent(os.Args[2:])
	case "generate-secrets":
		return generateSecrets()
	case "version", "--version", "-version":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return usageError()
	}
}

func runServer(args []string) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	address := flags.String("addr", envOr("ATLAS_ADDR", "127.0.0.1:9090"), "HTTP listen address")
	publicURL := flags.String("public-url", os.Getenv("ATLAS_PUBLIC_URL"), "public HTTPS URL")
	statePath := flags.String("state", envOr("ATLAS_STATE_PATH", "/var/lib/nginx-atlas/state.json"), "state file path")
	masterKeyValue := flags.String("master-key", os.Getenv("ATLAS_MASTER_KEY"), "32-byte encoded encryption key")
	adminToken := flags.String("admin-token", os.Getenv("ATLAS_ADMIN_TOKEN"), "administrator bearer token")
	demo := flags.Bool("demo", envBool("ATLAS_DEMO"), "seed safe demonstration data when state is empty")
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := securebox.ParseKey(*masterKeyValue)
	if err != nil {
		return fmt.Errorf("ATLAS_MASTER_KEY: %w", err)
	}
	box, err := securebox.New(key)
	if err != nil {
		return err
	}
	stateStore, err := store.Open(*statePath)
	if err != nil {
		return err
	}
	controller, err := server.New(server.Config{
		Address: *address, PublicURL: *publicURL, AdminToken: *adminToken, Demo: *demo,
	}, stateStore, box, slog.Default())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return controller.ListenAndServe(ctx)
}

func runAgent(args []string) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	serverURL := flags.String("server", os.Getenv("ATLAS_SERVER_URL"), "controller HTTPS URL")
	nodeName := flags.String("name", os.Getenv("ATLAS_NODE_NAME"), "node display name")
	token := flags.String("token", os.Getenv("ATLAS_ENROLLMENT_TOKEN"), "single-use enrollment token")
	statePath := flags.String("state", envOr("ATLAS_AGENT_STATE_PATH", "/var/lib/nginx-atlas/agent.json"), "agent credential state")
	caCert := flags.String("ca-cert", os.Getenv("ATLAS_CA_CERT"), "optional private CA certificate")
	pollInterval := flags.Duration("poll", envDuration("ATLAS_POLL_INTERVAL", 10*time.Second), "poll interval")
	nginxBinary := flags.String("nginx", envOr("ATLAS_NGINX_BINARY", "nginx"), "nginx binary")
	systemctlBinary := flags.String("systemctl", envOr("ATLAS_SYSTEMCTL_BINARY", "systemctl"), "systemctl binary")
	legoBinary := flags.String("lego", envOr("ATLAS_LEGO_BINARY", "lego"), "lego ACME binary")
	nginxConfigDir := flags.String("nginx-config-dir", envOr("ATLAS_NGINX_CONFIG_DIR", "/etc/nginx/conf.d"), "managed nginx configuration directory")
	sslRoot := flags.String("ssl-root", envOr("ATLAS_SSL_ROOT", "/etc/ssl"), "domain certificate root")
	dataRoot := flags.String("data-root", envOr("ATLAS_DATA_ROOT", "/var/lib/nginx-atlas"), "agent data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	runner := agent.OSCommandRunner{}
	executor := agent.NewExecutor(agent.ExecutorConfig{
		NginxBinary: *nginxBinary, Systemctl: *systemctlBinary, LegoBinary: *legoBinary,
		NginxConfigDir: *nginxConfigDir, SSLRoot: *sslRoot, DataRoot: *dataRoot,
	}, runner)
	client, err := agent.NewClient(agent.ClientConfig{
		ServerURL: *serverURL, NodeName: *nodeName, EnrollmentToken: *token,
		StatePath: *statePath, CACertPath: *caCert, PollInterval: *pollInterval, Version: version,
	}, executor, runner, slog.Default())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return client.Run(ctx)
}

func generateSecrets() error {
	masterKey, err := securebox.GenerateKey()
	if err != nil {
		return err
	}
	adminRaw := make([]byte, 32)
	if _, err := rand.Read(adminRaw); err != nil {
		return err
	}
	fmt.Printf("ATLAS_MASTER_KEY=%s\n", masterKey)
	fmt.Printf("ATLAS_ADMIN_TOKEN=%s\n", base64.RawURLEncoding.EncodeToString(adminRaw))
	return nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string) bool {
	value, _ := strconv.ParseBool(os.Getenv(name))
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func usageError() error {
	printUsage()
	return errors.New("a subcommand is required")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: atlas <server|agent|generate-secrets|version> [options]")
}
