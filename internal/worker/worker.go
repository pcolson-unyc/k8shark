// Package worker runs on every node. It captures packets (AF_PACKET on Linux),
// reassembles TCP streams, dissects L7 protocols and ships paired entries to the
// hub. When live capture is unavailable (non-Linux, or no privileges) it falls
// back to a synthetic demo feed so the dashboard is always populated.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/pablocolson/k8shark/internal/worker/capture"
	"github.com/pablocolson/k8shark/pkg/api"
)

// Options configures a worker run.
type Options struct {
	HubURL   string // ws:// (or wss://, when the hub serves TLS) URL of the hub worker endpoint
	HubToken string // bearer token for the hub connection ("" = no auth)
	HubCA    string // PEM file with the CA verifying a wss:// hub cert ("" = system roots)
	Node     string // node name this worker reports as
	NodeIP   string // node's host IP this worker reports as ("" = omitted from entries)
	Iface    string // capture interface ("" = any)
	Demo     bool   // force synthetic traffic instead of live capture
	DemoRPS  int    // synthetic entries/sec in demo mode
	// PcapFile, when set, replays a pcap file through the dissectors instead of
	// capturing live (offline analysis / dev without a cluster). Pure Go, so it
	// works on any platform, unlike live AF_PACKET capture.
	PcapFile string

	// RESP (Redis wire protocol) port labelling. Valkey and Redis are wire
	// identical, so the label is operator-supplied config, not wire-detected.
	// Default (both empty) is port 6379 -> redis, matching prior behavior.
	RedisPorts  []int // extra RESP ports labelled "redis" (in addition to the 6379 default)
	ValkeyPorts []int // RESP ports labelled "valkey"
	AMQPPorts   []int // extra AMQP 0-9-1 ports (in addition to the 5672 default)

	// HTTPPorts lists extra TCP ports to admit through the kernel-level
	// capture filter for HTTP traffic (in addition to the 80/8080 defaults).
	// Userspace dispatch already sniffs HTTP on any port that isn't claimed
	// by redis/postgres/amqp (see consumeStream's "else" branch) — this flag
	// only exists because the kernel filter can't do that same "else"
	// dispatch and must be told explicit ports up front.
	HTTPPorts []int

	// Capture-depth bounds (all per-direction). Defaults preserve prior behavior.
	CaptureBodies bool // capture & render request/response bodies (default true)
	BodyBytes     int  // per-direction body cap (0 => DefaultBodyCaptureBytes)
	RawBytes      int  // per-direction raw hex cap (0 => DefaultRawCaptureBytes; <0 disables raw)

	// RedactHeaders scrubs the values of well-known credential-bearing HTTP
	// headers (authorization, cookie, ...), sensitive HTTP query params
	// (token, api_key, ...) and RESP auth command arguments (AUTH, HELLO's
	// AUTH clause, CONFIG SET requirepass/masterauth) from captured entries.
	// Note the raw hex view still contains the original bytes — set
	// RawBytes < 0 to close that path too.
	RedactHeaders bool

	// RedactPGParams replaces every Postgres Bind parameter value with
	// [REDACTED]. Off by default, unlike RedactHeaders: Bind params carry no
	// name at the wire level, so redaction can't target just the sensitive
	// ones — it's all params or none, which trades away query-value
	// visibility that's usually the point of watching Postgres traffic.
	RedactPGParams bool

	// eBPF TLS uprobe capture (hybrid layer, additive to AF_PACKET). Off by
	// default: AF_PACKET alone is unaffected either way. Linux-only; a
	// non-Linux worker logs a warning and continues on AF_PACKET alone.
	EnableTLS   bool   // attach uprobes to OpenSSL/boringssl libssl/libcrypto
	EnableGoTLS bool   // Phase 2b, not yet implemented — logs a warning if set
	ProcRoot    string // "" => "/proc"; use "/host/proc" when hostPID mounts proc elsewhere
}

// Run starts the worker and blocks until ctx is cancelled.
func Run(ctx context.Context, log *slog.Logger, opts Options) error {
	if opts.DemoRPS <= 0 {
		opts.DemoRPS = 25
	}
	s := newSink(opts.HubURL, opts.HubToken, opts.Node, log)
	if opts.HubCA != "" {
		if err := s.setHubCA(opts.HubCA); err != nil {
			return fmt.Errorf("loading --hub-ca: %w", err)
		}
	}
	go s.run(ctx)

	stop := ctx.Done()

	if opts.Demo {
		log.Info("worker started (demo mode)", "node", opts.Node, "rps", opts.DemoRPS)
		runDemo(s, opts.Node, opts.NodeIP, opts.DemoRPS, stop)
		return nil
	}

	// AF_PACKET and eBPF TLS both feed one pipeline and are independent: either
	// can be unavailable without disabling the other. Build the pipeline first.
	p := newPipeline(s, opts.Node, opts.NodeIP, log)
	if len(opts.RedisPorts) > 0 || len(opts.ValkeyPorts) > 0 {
		p.respPorts = buildRespPorts(opts.RedisPorts, opts.ValkeyPorts)
	}
	if len(opts.AMQPPorts) > 0 {
		p.amqpPorts = buildAMQPPorts(opts.AMQPPorts)
	}
	p.applyCaptureOpts(opts)

	// AF_PACKET ring geometry (see afpacketComputeSize) — reused verbatim by
	// reopenLive below so a post-pause reopen matches the startup config.
	const snaplen = 65536

	// Offline pcap ingest (EXT-2) takes precedence over live capture and needs
	// no privileges — replay a file through the same dissectors.
	var src capture.PacketSource
	// reopenLive recreates the AF_PACKET source exactly as it was opened
	// below; nil unless that succeeds. captureLoop calls it to reopen the
	// kernel ring on resume after closing it on pause (see captureLoop and
	// sink.pauseChanged) — pcap replay and demo have no such source to
	// toggle, so they leave this nil and keep today's instant pause/resume.
	var reopenLive func() (capture.PacketSource, error)
	if opts.PcapFile != "" {
		fs, err := capture.NewFileSource(opts.PcapFile)
		if err != nil {
			return fmt.Errorf("opening --pcap-file: %w", err)
		}
		src = fs
		defer src.Close()
		s.captureLive.Store(true)
		log.Info("pcap file ingest started", "node", opts.Node, "path", opts.PcapFile)
	} else if live, err := capture.NewLive(opts.Iface, snaplen, capturePorts(opts)); err != nil {
		// AF_PACKET (plaintext L3/L4/L7) — best effort. A failure here does NOT
		// fall back to synthetic traffic: demo is opt-in (--demo) only, so a
		// broken capture surfaces loudly instead of masquerading as realistic
		// data (which once hid a non-root worker silently emitting a fake
		// "shop" namespace).
		log.Error("AF_PACKET capture unavailable", "err", err,
			"hint", "worker likely not root or missing NET_RAW; pass --demo for synthetic traffic")
	} else {
		src = live
		// Owned by captureLoop from here on (including at shutdown): it may
		// replace src with a freshly reopened one across a pause/resume
		// cycle, so this function no longer knows which handle is live by
		// the time Run() returns — no defer src.Close() here.
		s.captureLive.Store(true)
		log.Info("AF_PACKET capture started", "node", opts.Node, "iface", opts.Iface)
		reopenLive = func() (capture.PacketSource, error) {
			return capture.NewLive(opts.Iface, snaplen, capturePorts(opts))
		}
	}

	// eBPF TLS (decrypted plaintext) — independent of AF_PACKET, so it still
	// starts even when AF_PACKET above failed. Feeds the same pipeline p.
	tlsUp := false
	if opts.EnableTLS {
		tlsUp = startTLSCapture(ctx, log, p, opts)
		s.captureTLS.Store(tlsUp)
	}

	if src == nil && !tlsUp {
		log.Error("no capture source available — worker idle, no traffic will be reported",
			"hint", "check privileges (root, NET_RAW, BPF) or pass --demo for synthetic traffic")
	}

	return captureLoop(ctx, log, p, src, reopenLive)
}

// Bounds on tcpassembly's out-of-order reassembly buffer (gopacket pages are
// ~1900 bytes each). Left at the library default (0 = unlimited), a lossy
// capture — dropped ring-buffer segments, a node-wide packet storm — makes
// out-of-order pages accumulate for up to the flush window with no ceiling,
// which can OOMKill the worker DaemonSet well before FlushOlderThan ever
// runs. maxBufferedPagesTotal (~95 MB) leaves headroom under the chart's
// default 512Mi worker memory limit for flow maps and everything else the
// process holds; maxBufferedPagesPerConnection (~7.5 MB) keeps one noisy or
// lossy connection from consuming that whole budget by itself. Past either
// bound, tcpassembly degrades to discarding the oldest buffered page instead
// of growing further — the affected stream is truncated, not the process.
const (
	maxBufferedPagesTotal         = 50000
	maxBufferedPagesPerConnection = 4000
)

// captureLoop drives packet consumption plus the periodic flush/gc tickers.
// src may be nil (AF_PACKET unavailable): the gc/flush loop still runs so an
// eBPF-TLS-only worker prunes its pipeline state, and it blocks until ctx is
// cancelled rather than exiting.
//
// reopen recreates src exactly as it was first opened; non-nil only for a
// live AF_PACKET source (see Run). When set, a hub pause/resume command
// (p.sink.pauseChanged) closes src — actually stopping the kernel ring and
// freeing its mmap, not just gating route() — and reopens it on resume.
// pcap replay and demo pass reopen == nil and keep the prior instant-toggle
// behavior: pausing them wouldn't free any comparable resource, and a pcap
// file's channel closing on EOF must still read as "done", not "paused".
func captureLoop(ctx context.Context, log *slog.Logger, p *pipeline, src capture.PacketSource, reopen func() (capture.PacketSource, error)) error {
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(&tcpStreamFactory{p: p}))
	assembler.MaxBufferedPagesTotal = maxBufferedPagesTotal
	assembler.MaxBufferedPagesPerConnection = maxBufferedPagesPerConnection

	var packets <-chan gopacket.Packet
	if src != nil {
		packets = src.Packets()
	}

	flush := time.NewTicker(30 * time.Second)
	defer flush.Stop()
	gc := time.NewTicker(15 * time.Second)
	defer gc.Stop()

	for {
		select {
		case <-ctx.Done():
			// Only close what this loop itself may have reopened — a pcap/demo
			// source (reopen == nil) is still owned by Run's own defer.
			if src != nil && reopen != nil {
				_ = src.Close()
			}
			return nil
		case <-p.sink.pauseChanged:
			if reopen == nil {
				continue // nothing to close/reopen for this source kind
			}
			if p.sink.paused() {
				if src == nil {
					continue // already closed (e.g. a coalesced duplicate wakeup)
				}
				log.Info("capture paused by hub — closing the AF_PACKET source")
				_ = src.Close()
				src, packets = nil, nil
				p.sink.captureLive.Store(false)
			} else {
				if src != nil {
					continue // already open
				}
				newSrc, err := reopen()
				if err != nil {
					// Stays closed until the next pause/resume edge retries —
					// captureLive=false at /api/workers makes this visible
					// cluster-side rather than only in this log line.
					log.Error("failed to reopen AF_PACKET capture on resume", "err", err)
					continue
				}
				log.Info("capture resumed by hub — reopened the AF_PACKET source")
				src = newSrc
				packets = src.Packets()
				p.sink.captureLive.Store(true)
			}
		case <-flush.C:
			assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
			// Piggyback the ring-stats probe on the same 30s ticker rather
			// than adding a dedicated one — this is a coarse "is the kernel
			// dropping packets" gauge, not something that needs tighter
			// freshness than the sink's own 10s self-report cadence.
			if src != nil {
				if rs, ok := src.Stats(); ok {
					p.sink.ringPackets.Store(rs.Packets)
					p.sink.ringDrops.Store(rs.Drops)
				}
			}
		case <-gc.C:
			p.gc()
			p.flushFlows(20 * time.Second)
		case pkt, ok := <-packets:
			if !ok {
				// AF_PACKET stream ended on its own (not via pause above);
				// stop selecting on it but keep the gc loop alive for any
				// eBPF TLS capture still feeding the pipeline. A dead capture
				// must be loud — and visible at /api/workers.
				log.Error("AF_PACKET packet stream ended — live capture stopped",
					"hint", "no further plaintext traffic will be reported by this worker")
				p.sink.captureLive.Store(false)
				src, packets = nil, nil
				continue
			}
			p.route(assembler, pkt)
		}
	}
}

// buildRespPorts merges the default RESP port (6379 -> redis) with operator
// overrides. RedisPorts entries are applied first, then ValkeyPorts, so a port
// listed in both wins as "valkey".
func buildRespPorts(redisPorts, valkeyPorts []int) map[int]api.Protocol {
	respPorts := map[int]api.Protocol{redisPort: api.ProtocolRedis}
	for _, port := range redisPorts {
		respPorts[port] = api.ProtocolRedis
	}
	for _, port := range valkeyPorts {
		respPorts[port] = api.ProtocolValkey
	}
	return respPorts
}

// buildAMQPPorts merges the default AMQP port (5672) with operator-supplied
// extra ports.
func buildAMQPPorts(extra []int) map[int]bool {
	ports := map[int]bool{amqpPort: true}
	for _, port := range extra {
		ports[port] = true
	}
	return ports
}

// defaultHTTPPorts are admitted through the kernel filter even when the
// operator hasn't set --http-ports, matching the ports the old hardcoded
// filter always let through.
var defaultHTTPPorts = []int{80, 8080}

// capturePorts builds the kernel-level BPF filter's TCP/UDP port lists (see
// capture.Ports) from every port source the worker knows about: the fixed
// protocol defaults plus every operator override. A port missing from this
// list never reaches userspace at all — the kernel drops it before route()
// or any dissector sees it — so this must stay a superset of every port
// buildRespPorts/buildAMQPPorts/consumeStream's HTTP fallback can dispatch.
func capturePorts(opts Options) capture.Ports {
	tcp := map[int]bool{
		redisPort: true, pgPort: true, amqpPort: true, dnsPort: true,
		mysqlPort: true, mongoPort: true, kafkaPort: true,
	}
	for _, p := range defaultHTTPPorts {
		tcp[p] = true
	}
	for _, p := range opts.RedisPorts {
		tcp[p] = true
	}
	for _, p := range opts.ValkeyPorts {
		tcp[p] = true
	}
	for _, p := range opts.AMQPPorts {
		tcp[p] = true
	}
	for _, p := range opts.HTTPPorts {
		tcp[p] = true
	}

	ports := capture.Ports{UDP: []int{53}} // DNS
	for p := range tcp {
		ports.TCP = append(ports.TCP, p)
	}
	sort.Ints(ports.TCP) // deterministic program, easier to reason about and test
	return ports
}

// route dispatches a packet: TCP goes to the L7 assembler and the L4 flow
// tracker; UDP goes to the DNS handler or the L4 flow tracker; ICMP is emitted
// per-packet. Anything L7-dissected is flagged so it isn't double-counted as a
// generic flow.
func (p *pipeline) route(assembler *tcpassembly.Assembler, pkt gopacket.Packet) {
	if p.sink.paused() {
		return // hub told this worker to stop turning capture into entries
	}
	net := pkt.NetworkLayer()
	if net == nil {
		return
	}
	ts := pkt.Metadata().Timestamp
	length := pkt.Metadata().Length
	if length == 0 {
		length = len(pkt.Data())
	}

	if tl := pkt.Layer(layers.LayerTypeTCP); tl != nil {
		tcp, _ := tl.(*layers.TCP)
		meta := extractL4Meta(pkt)
		assembler.AssembleWithTimestamp(net.NetworkFlow(), tcp, ts)
		p.trackTCP(net.NetworkFlow(), tcp.TransportFlow(), tcp, length, ts, meta)
		return
	}
	if ul := pkt.Layer(layers.LayerTypeUDP); ul != nil {
		udp, _ := ul.(*layers.UDP)
		if dl := pkt.Layer(layers.LayerTypeDNS); dl != nil {
			dns, _ := dl.(*layers.DNS)
			p.handleDNS(net.NetworkFlow(), udp, dns, dl.LayerContents())
			return
		}
		p.trackUDP(net.NetworkFlow(), udp.TransportFlow(), length, ts, udp.Payload)
		return
	}
	if il := pkt.Layer(layers.LayerTypeICMPv4); il != nil {
		icmp, _ := il.(*layers.ICMPv4)
		p.handleICMP(net.NetworkFlow(), icmp, length, ts)
		return
	}
	if il := pkt.Layer(layers.LayerTypeICMPv6); il != nil {
		icmp, _ := il.(*layers.ICMPv6)
		p.handleICMPv6(net.NetworkFlow(), icmp, length, ts)
	}
}

// l4meta is the per-packet L3/L4 header data trackTCP needs to build L4Info.
// It is extracted in route() while the raw packet layers are still available
// (the reassembled L7 stream the dissectors see has already lost them).
//
// It deliberately carries the *unrendered* header bytes rather than a finished
// hexdump, and leaves the MAC / fragment-flag strings unformatted. Every one of
// those values is copied into the flow exactly once (trackTCP's `if f.X == ""`
// guards) and is dropped entirely for a packet the CAP-8 dedup rejects — but
// extractL4Meta runs for *every* TCP packet, so formatting them here meant
// rendering a hexdump and three strings per packet to keep one per flow.
// Rendering now happens inside those guards instead (see renderHeaderHex).
//
// eth/ip4/ip6/tcp point into the capture buffer's packet data and are only
// valid for the duration of the route() call that produced them. That is safe
// because route() hands the l4meta straight to trackTCP, which renders
// everything it needs synchronously and retains none of the slices — the same
// contract route() already relies on when it passes *layers.TCP through.
type l4meta struct {
	eth       *layers.Ethernet
	ip4       *layers.IPv4
	ip6       *layers.IPv6
	tcp       *layers.TCP
	ipVersion int
	ttl       int
}

// extractL4Meta picks the Ethernet/IP/TCP layers out of a packet and reads the
// two cheap scalar fields (IP version, TTL). Everything string-shaped is left
// to trackTCP — see the l4meta doc comment.
func extractL4Meta(pkt gopacket.Packet) l4meta {
	var m l4meta
	if eth, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		m.eth = eth
	}
	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		m.ip4 = ip4
		m.ipVersion = 4
		m.ttl = int(ip4.TTL)
	} else if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		m.ip6 = ip6
		m.ipVersion = 6
		m.ttl = int(ip6.HopLimit)
	}
	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		m.tcp = tcp
	}
	return m
}

// macStrings renders the Ethernet source/destination MACs, or ("", "") when the
// packet had no Ethernet layer (e.g. a raw-IP capture interface).
func (m l4meta) macStrings() (src, dst string) {
	if m.eth == nil {
		return "", ""
	}
	return m.eth.SrcMAC.String(), m.eth.DstMAC.String()
}

// ipFlagStr renders the IPv4 DF/MF fragment flags ("" for IPv6 or no IP layer,
// matching what the old eager extraction stored).
func (m l4meta) ipFlagStr() string {
	if m.ip4 == nil {
		return ""
	}
	return ipv4Flags(m.ip4.Flags)
}

// renderHeaderHex builds the bounded eth+ip+tcp header hexdump, capped at
// capBytes (<=0 or no header layers => ""). This is the expensive half of the
// old extractL4Meta and is now called once per flow, from trackTCP, instead of
// once per packet. The concatenation buffer is sized to what will actually be
// dumped so the cap bounds the allocation too.
func (m l4meta) renderHeaderHex(capBytes int) string {
	if capBytes <= 0 {
		return ""
	}
	var parts [3][]byte
	if m.eth != nil {
		parts[0] = m.eth.LayerContents()
	}
	switch {
	case m.ip4 != nil:
		parts[1] = m.ip4.LayerContents()
	case m.ip6 != nil:
		parts[1] = m.ip6.LayerContents()
	}
	if m.tcp != nil {
		parts[2] = m.tcp.LayerContents()
	}
	total := len(parts[0]) + len(parts[1]) + len(parts[2])
	if total == 0 {
		return ""
	}
	if total > capBytes {
		total = capBytes
	}
	hdr := make([]byte, 0, total)
	for _, part := range parts {
		room := total - len(hdr)
		if room <= 0 {
			break
		}
		if len(part) > room {
			part = part[:room]
		}
		hdr = append(hdr, part...)
	}
	return hexDump(hdr, capBytes)
}

// ipv4Flags renders the DF/MF fragment flags.
func ipv4Flags(f layers.IPv4Flag) string {
	var out []string
	if f&layers.IPv4DontFragment != 0 {
		out = append(out, "DF")
	}
	if f&layers.IPv4MoreFragments != 0 {
		out = append(out, "MF")
	}
	return strings.Join(out, ",")
}
