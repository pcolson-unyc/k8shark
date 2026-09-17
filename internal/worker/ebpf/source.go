// Package ebpf captures decrypted TLS plaintext from userspace TLS libraries
// (OpenSSL/boringssl today, Go crypto/tls behind --enable-go-tls later) via
// uprobe/uretprobe hooks on SSL_read/SSL_write. It complements — does not
// replace — AF_PACKET: AF_PACKET still handles plaintext L3/L4/L7 and
// Cilium-transparent-encrypted traffic is out of reach either way, but TLS/
// mTLS application traffic is opaque to AF_PACKET (it only sees the TLS
// record layer). Uprobes read the buffer inside the process before it is
// encrypted (SSL_write) or after it is decrypted (SSL_read), bypassing the
// network datapath — and Cilium's own eBPF programs — entirely.
//
// Real capture (loader_linux.go/attach.go, backed by github.com/cilium/ebpf)
// only compiles and runs on Linux with BTF present; New returns
// ErrUnsupported elsewhere (see loader_other.go), matching the existing
// internal/worker/capture package's AF_PACKET/non-Linux split.
package ebpf

import (
	"errors"
	"log/slog"
	"time"
)

// ErrUnsupported is returned when the TLS uprobe layer is requested on a
// non-Linux host.
var ErrUnsupported = errors.New("eBPF TLS capture is only supported on linux")

// ErrNoBTF is returned when the node has no BTF (/sys/kernel/btf/vmlinux),
// which CO-RE relocation needs to load the program against the running
// kernel's exact struct layout.
var ErrNoBTF = errors.New("eBPF TLS capture requires BTF (/sys/kernel/btf/vmlinux not found)")

// ErrNotCapable is returned when the process lacks the privileges (BPF,
// PERFMON, SYS_ADMIN, SYS_PTRACE — see the worker DaemonSet securityContext)
// to load programs or attach uprobes.
var ErrNotCapable = errors.New("eBPF TLS capture requires BPF/PERFMON/SYS_ADMIN/SYS_PTRACE capabilities")

// TLSDirection marks which side of SSL_read/SSL_write a record was captured
// on.
type TLSDirection uint8

const (
	// TLSDirUnknown is the zero value; never produced by a real capture.
	TLSDirUnknown TLSDirection = iota
	// TLSDirWrite is plaintext about to be encrypted (SSL_write/_ex entry).
	TLSDirWrite
	// TLSDirRead is plaintext just decrypted (SSL_read/_ex uretprobe return).
	TLSDirRead
)

// TLSRecord is one plaintext buffer captured at a TLS library boundary.
//
// ConnID is a synthetic identity derived from the SSL* pointer (unique per
// TLS connection in a process), used to fan the two directions of one
// connection together. SrcIP/DstIP/SrcPort/DstPort carry the real 4-tuple
// once the tcp_sendmsg/tcp_recvmsg kprobes have resolved this thread's socket
// (Phase 2b); until then (or for IPv6, not yet resolved) they are empty/zero
// and the consumer falls back to a pid:<n> endpoint.
type TLSRecord struct {
	PID, TID  uint32
	ConnID    uint64
	Direction TLSDirection

	SrcIP, DstIP     string
	SrcPort, DstPort uint16

	// Data ownership transfers to the consumer when sent on Records. The source
	// must never mutate or reuse this backing buffer after sending the record.
	Data []byte

	// Lagged marks a data-less tombstone: backpressure forced the drop of one
	// of this connection's interior chunks, so the byte stream has a hole the
	// parser must never see. The consumer closes the stream with a clean
	// truncation (exactly chanPipe's own lag policy); no further records for
	// this ConnID will follow.
	Lagged bool
}

// Config configures a Source.
type Config struct {
	// ProcRoot is the filesystem root used to discover TLS libraries loaded
	// by other processes (walks ProcRoot/<pid>/maps and resolves symbols via
	// ProcRoot/<pid>/root/...). Typically "/proc" when the worker has
	// hostPID, or "/host/proc" when /proc is bind-mounted under a different
	// path (see the worker.tls.enabled Helm mounts). Defaults to "/proc".
	ProcRoot string
	// Rescan is how often discoverTargets re-walks ProcRoot for new
	// processes (pod churn). Defaults to 10s.
	Rescan time.Duration
	// Log receives attach/detach/drop diagnostics. Defaults to a discard
	// logger.
	Log *slog.Logger
}

// Source streams decrypted TLS records from every process the loader has
// successfully attached to.
type Source interface {
	// Records returns the channel TLSRecords arrive on. Closed after Close.
	Records() <-chan TLSRecord
	// Attach loads the eBPF program and starts scanning ProcRoot for uprobe
	// targets. Safe to call once; New does not attach implicitly so the
	// caller can decide when capture starts.
	Attach() error
	// Close detaches every uprobe, unloads the program and closes Records().
	Close() error
}

// New constructs a Source for the current platform. On Linux it loads the
// CO-RE eBPF program and prepares (but does not start — call Attach) uprobe
// discovery; everywhere else it returns ErrUnsupported so callers can
// warn-and-continue on AF_PACKET alone (see worker.Run).
func New(cfg Config) (Source, error) {
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.Rescan <= 0 {
		cfg.Rescan = 10 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return newSource(cfg)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
