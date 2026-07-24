package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/pablocolson/k8shark/internal/worker"
	"github.com/spf13/cobra"
)

func workerCmd() *cobra.Command {
	opts := worker.Options{}
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Run the node worker (captures traffic, streams to the hub)",
		Long: "Captures packets on this node, reconstructs L7 traffic and streams\n" +
			"entries to the hub. This is what the worker DaemonSet runs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Node == "" {
				opts.Node, _ = os.Hostname()
			}
			if opts.HubToken == "" {
				opts.HubToken = os.Getenv("K8SHARK_API_TOKEN")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return worker.Run(ctx, log, opts)
		},
	}
	cmd.Flags().StringVar(&opts.HubURL, "hub", "ws://localhost:8898/ws/worker", "hub worker WebSocket URL")
	cmd.Flags().StringVar(&opts.HubToken, "hub-token", "", "bearer token for the hub connection (default $K8SHARK_API_TOKEN)")
	cmd.Flags().StringVar(&opts.HubCA, "hub-ca", "", "PEM file with the CA verifying a wss:// hub certificate (default: system roots)")
	cmd.Flags().StringVar(&opts.Node, "node", "", "node name to report (default: hostname)")
	cmd.Flags().StringVar(&opts.NodeIP, "node-ip", "", "node host IP to report (default: omitted; the Helm chart injects status.hostIP)")
	cmd.Flags().StringVar(&opts.Iface, "iface", "", "capture interface (default: any)")
	cmd.Flags().BoolVar(&opts.Demo, "demo", false, "generate synthetic traffic instead of capturing")
	cmd.Flags().IntVar(&opts.DemoRPS, "demo-rps", 25, "synthetic entries per second in demo mode")
	cmd.Flags().StringVar(&opts.PcapFile, "pcap-file", "", "replay a pcap file through the dissectors instead of capturing live (offline analysis; works on any OS)")
	cmd.Flags().IntSliceVar(&opts.RedisPorts, "redis-ports", nil, "extra RESP ports labelled redis")
	cmd.Flags().IntSliceVar(&opts.ValkeyPorts, "valkey-ports", nil, "RESP ports labelled valkey")
	cmd.Flags().IntSliceVar(&opts.AMQPPorts, "amqp-ports", nil, "extra AMQP 0-9-1 ports (in addition to 5672)")
	cmd.Flags().IntSliceVar(&opts.HTTPPorts, "http-ports", nil, "extra TCP ports to admit through the kernel capture filter for HTTP traffic (in addition to 80/8080); userspace already dissects HTTP on any unclaimed port, this only unblocks the kernel filter")
	cmd.Flags().BoolVar(&opts.CaptureBodies, "capture-bodies", true, "capture and store request/response bodies")
	cmd.Flags().BoolVar(&opts.RedactHeaders, "redact-headers", true, "scrub credential-bearing HTTP header values (authorization, cookie, ...), sensitive query params (token, api_key, ...) and RESP auth command args (AUTH, HELLO, CONFIG SET requirepass); raw hex capture is separate — use --raw-bytes=-1 to disable that too")
	cmd.Flags().BoolVar(&opts.RedactPGParams, "redact-pg-params", false, "replace all Postgres Bind parameter values with [REDACTED] (all-or-nothing: bind params carry no name to redact selectively)")
	cmd.Flags().IntVar(&opts.BodyBytes, "body-bytes", 0, "max body bytes per direction (0=default 4096)")
	cmd.Flags().IntVar(&opts.RawBytes, "raw-bytes", 0, "max raw bytes hex-dumped per direction (0=default 2048, <0 disables)")
	cmd.Flags().BoolVar(&opts.EnableTLS, "enable-tls", false, "attach eBPF uprobes to OpenSSL/boringssl to capture decrypted TLS traffic (linux only)")
	cmd.Flags().BoolVar(&opts.EnableGoTLS, "enable-go-tls", false, "attach eBPF uprobes to Go crypto/tls (not yet implemented)")
	cmd.Flags().StringVar(&opts.ProcRoot, "proc-root", "/proc", "proc filesystem root for eBPF TLS target discovery (e.g. /host/proc when bind-mounted)")
	return cmd
}
