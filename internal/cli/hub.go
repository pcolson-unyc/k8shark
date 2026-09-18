package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pablocolson/k8shark/internal/config"
	"github.com/pablocolson/k8shark/internal/hub"
	"github.com/spf13/cobra"
)

func hubCmd() *cobra.Command {
	var port int
	var uiDir string
	var apiToken string
	var workerToken string
	var adminToken string
	var bufferSize int
	var bufferBytes int64
	var allowOrigins []string
	var tlsCert, tlsKey string
	var exportFile, exportWebhook string
	var exportFileMaxBytes int64
	var exportWebhookInterval time.Duration
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Run the hub server (aggregates worker traffic, serves the API)",
		Long: "Runs the central hub that receives entries from workers and streams\n" +
			"them to front-end clients. This is what the hub container runs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if bufferSize < 0 || bufferBytes < 0 {
				return fmt.Errorf("--buffer and --buffer-bytes must be non-negative")
			}
			if apiToken == "" {
				apiToken = os.Getenv("K8SHARK_API_TOKEN")
			}
			if workerToken == "" {
				workerToken = os.Getenv("K8SHARK_WORKER_TOKEN")
			}
			if adminToken == "" {
				adminToken = os.Getenv("K8SHARK_ADMIN_TOKEN")
			}
			if (tlsCert == "") != (tlsKey == "") {
				return fmt.Errorf("--tls-cert and --tls-key must be set together")
			}
			s := hub.New(log, hub.Options{
				UIDir:                 uiDir,
				APIToken:              apiToken,
				WorkerToken:           workerToken,
				AdminToken:            adminToken,
				BufferSize:            bufferSize,
				BufferBytes:           bufferBytes,
				AllowedOrigins:        allowOrigins,
				TLSCert:               tlsCert,
				TLSKey:                tlsKey,
				ExportFile:            exportFile,
				ExportFileMaxBytes:    exportFileMaxBytes,
				ExportWebhook:         exportWebhook,
				ExportWebhookInterval: exportWebhookInterval,
			})
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return s.Run(ctx, fmt.Sprintf(":%d", port))
		},
	}
	cmd.Flags().IntVar(&port, "port", config.DefaultHubPort, "listen port")
	cmd.Flags().StringVar(&uiDir, "serve-ui", "", "serve a built front from this directory (local dev)")
	cmd.Flags().StringVar(&apiToken, "api-token", "", "require this bearer token on /api and WebSocket endpoints (default $K8SHARK_API_TOKEN; empty disables auth)")
	cmd.Flags().StringVar(&workerToken, "worker-token", "", "distinct bearer token required on /ws/worker (default $K8SHARK_WORKER_TOKEN; empty falls back to the API token)")
	cmd.Flags().StringVar(&adminToken, "admin-token", "", "distinct bearer token required on mutating /api calls, also grants reads (default $K8SHARK_ADMIN_TOKEN; empty falls back to the API token)")
	cmd.Flags().IntVar(&bufferSize, "buffer", 0, "in-memory entry buffer size (0 = default 10000)")
	cmd.Flags().Int64Var(&bufferBytes, "buffer-bytes", 0, "serialized history byte budget (0 = default 64MiB)")
	cmd.Flags().StringArrayVar(&allowOrigins, "allow-origin", nil, "extra browser Origin allowed on the API and WebSockets, repeatable (default: same-origin only; \"*\" allows any)")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "PEM certificate file; with --tls-key, serve HTTPS/wss instead of plain HTTP")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "PEM private key file for --tls-cert")
	cmd.Flags().StringVar(&exportFile, "export-file", "", "also append each entry as JSONL to this file (rotates by size)")
	cmd.Flags().Int64Var(&exportFileMaxBytes, "export-file-max-bytes", 0, "rotate the export file past this size (0 = default)")
	cmd.Flags().StringVar(&exportWebhook, "export-webhook", "", "also POST batches of entries (JSON array) to this URL")
	cmd.Flags().DurationVar(&exportWebhookInterval, "export-webhook-interval", 0, "flush a partial webhook batch after this long (0 = default)")
	return cmd
}
