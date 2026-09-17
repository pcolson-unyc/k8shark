//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// eventHeaderSize is the byte offset of struct event's data[] field in
// bpf/tls.bpf.c — see that file's field-order comment. Kept in sync by hand
// since this package decodes ring buffer records itself rather than trusting
// bpf2go's -type codegen (whose exact generated field names we can't inspect
// without a working bpf target toolchain, which macOS's Apple clang lacks —
// see gen.go).
const (
	eventOffPID       = 0
	eventOffTID       = 4
	eventOffSSLCtx    = 8
	eventOffSAddr     = 16 // 16 bytes; only the first 4 are meaningful for AF_INET
	eventOffDAddr     = 32
	eventOffDataLen   = 48
	eventOffSPort     = 52
	eventOffDPort     = 54
	eventOffFamily    = 56
	eventOffDirection = 57
	eventOffData      = 58
)

// Linux AF_* constants (bits/socket.h) — matches AF_INET/AF_INET6 in
// bpf/tls.bpf.c's struct event.family.
const (
	afInet  = 2
	afInet6 = 10
)

func decodeEvent(raw []byte) (TLSRecord, error) {
	if len(raw) < eventOffData {
		return TLSRecord{}, fmt.Errorf("ebpf: short ring buffer record (%d bytes)", len(raw))
	}
	dataLen := binary.LittleEndian.Uint32(raw[eventOffDataLen:])
	end := eventOffData + int(dataLen)
	if end > len(raw) {
		end = len(raw) // defensive: never index past what the kernel actually gave us
	}
	rec := TLSRecord{
		PID:       binary.LittleEndian.Uint32(raw[eventOffPID:]),
		TID:       binary.LittleEndian.Uint32(raw[eventOffTID:]),
		ConnID:    binary.LittleEndian.Uint64(raw[eventOffSSLCtx:]),
		Direction: TLSDirection(raw[eventOffDirection]),
		SrcPort:   binary.LittleEndian.Uint16(raw[eventOffSPort:]),
		DstPort:   binary.LittleEndian.Uint16(raw[eventOffDPort:]),
	}
	// saddr/daddr are network-order addresses as the kernel stored them (4
	// bytes for AF_INET, all 16 for AF_INET6); an all-zero address, or an
	// unrecognised family (0 = the tcp_sendmsg/tcp_recvmsg kprobe hasn't
	// resolved this thread's socket yet), means the Go side keeps the
	// synthetic pid:<n> endpoint instead.
	switch raw[eventOffFamily] {
	case afInet:
		if sa := raw[eventOffSAddr : eventOffSAddr+4]; !isZero(sa) {
			rec.SrcIP = ipv4String(sa)
		}
		if da := raw[eventOffDAddr : eventOffDAddr+4]; !isZero(da) {
			rec.DstIP = ipv4String(da)
		}
	case afInet6:
		if sa := raw[eventOffSAddr : eventOffSAddr+16]; !isZero(sa) {
			rec.SrcIP = ipv6String(sa)
		}
		if da := raw[eventOffDAddr : eventOffDAddr+16]; !isZero(da) {
			rec.DstIP = ipv6String(da)
		}
	}
	if end > eventOffData {
		rec.Data = append([]byte(nil), raw[eventOffData:end]...)
	}
	return rec, nil
}

// ipv4String formats 4 network-order bytes as a dotted-quad.
func ipv4String(b []byte) string {
	return net.IP(b[:4]).To4().String()
}

// ipv6String formats 16 network-order bytes as a canonical IPv6 address.
func ipv6String(b []byte) string {
	return net.IP(b[:16]).String()
}

// isZero reports whether every byte is 0 (the sentinel for "unresolved").
func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// probeNames maps our stable program-name strings (used by attach.go's
// sslSymbols table) to the *cebpf.Program the collection loaded for the
// matching SEC() in bpf/tls.bpf.c. Isolating the bpf2go-generated field names
// to this one function keeps attach.go decoupled from codegen naming.
func probeNames(objs *tlsObjects) map[string]*cebpf.Program {
	return map[string]*cebpf.Program{
		"uprobe_ssl_write":       objs.UprobeSslWrite,
		"uprobe_ssl_write_ex":    objs.UprobeSslWriteEx,
		"uretprobe_ssl_write_ex": objs.UretprobeSslWriteEx,
		"uprobe_ssl_read":        objs.UprobeSslRead,
		"uretprobe_ssl_read":     objs.UretprobeSslRead,
		"uprobe_ssl_read_ex":     objs.UprobeSslReadEx,
		"uretprobe_ssl_read_ex":  objs.UretprobeSslReadEx,
	}
}

// linuxSource is the real Source: a loaded BPF collection, a ring buffer
// reader draining it, and a rescanning attacher discovering new uprobe
// targets as pods churn.
type linuxSource struct {
	cfg  Config
	objs tlsObjects
	rd   *ringbuf.Reader

	out chan TLSRecord

	mu          sync.Mutex
	attached    map[string]*attachment // devIno -> owned dynamic uprobes
	staticLinks []link.Link
	grace       time.Duration

	closeOnce sync.Once
	stop      chan struct{}
	wg        sync.WaitGroup
}

type attachment struct {
	links    []link.Link
	lastSeen time.Time
}

func newSource(cfg Config) (Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock rlimit: %w", err)
	}

	s := &linuxSource{
		cfg:      cfg,
		out:      make(chan TLSRecord, 4096),
		attached: map[string]*attachment{},
		grace:    60 * time.Second,
		stop:     make(chan struct{}),
	}
	if err := loadTlsObjects(&s.objs, nil); err != nil {
		var ve *cebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf: load program (verifier): %w\n%+v", err, ve)
		}
		return nil, fmt.Errorf("ebpf: load program: %w", err)
	}

	rd, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		s.objs.Close()
		return nil, fmt.Errorf("ebpf: open ring buffer: %w", err)
	}
	s.rd = rd
	return s, nil
}

func (s *linuxSource) Records() <-chan TLSRecord { return s.out }

// Attach starts the ring-buffer-drain goroutine and the periodic
// discoverTargets/attach scan. It never returns an error for "no targets
// found yet" (pods matching TLS libraries may not exist at startup) — only
// for conditions that make capture structurally impossible.
func (s *linuxSource) Attach() error {
	// Global kprobes for 4-tuple resolution (Phase 2b): attached once, not
	// per-pid. A failure here is non-fatal — the SSL uprobes still work, the
	// records just keep their synthetic pid:<n> endpoints.
	for fn, prog := range map[string]*cebpf.Program{
		"tcp_sendmsg": s.objs.KprobeTcpSendmsg,
		"tcp_recvmsg": s.objs.KprobeTcpRecvmsg,
	} {
		if prog == nil {
			continue
		}
		l, err := link.Kprobe(fn, prog, nil)
		if err != nil {
			s.cfg.Log.Warn("ebpf: kprobe attach failed (endpoints stay synthetic)", "fn", fn, "err", err)
			continue
		}
		s.mu.Lock()
		s.staticLinks = append(s.staticLinks, l)
		s.mu.Unlock()
	}

	s.wg.Add(2)
	go s.drainLoop()
	go s.scanLoop()
	return nil
}

// maxLaggedConns bounds drainLoop's lagged-connection set. There is no
// connection-close event to prune on, so on overflow the set is cleared —
// the worst case is a pruned connection getting a second tombstone or a
// stale one resuming misparsed, both strictly better than unbounded growth.
const maxLaggedConns = 4096

// drainLoop copies ring buffer records into s.out. On backpressure it drops
// the oldest buffered record — but that record is an interior chunk of some
// connection's byte stream, exactly the mid-stream hole chanPipe
// (tls_pipeline.go) refuses to create because it desyncs the parser for the
// rest of the connection. So the victim's ConnID is marked lagged: its
// remaining records are discarded and a single data-less Lagged tombstone is
// forwarded instead, telling the consumer to close that stream with a clean
// truncation. Consistent with sink.emit's drop-newest-not-block policy in
// spirit: a stalled consumer never blocks uprobe delivery or grows memory.
func (s *linuxSource) drainLoop() {
	defer s.wg.Done()
	// lagged tracks connections that lost an interior chunk; the value is
	// whether their tombstone has been delivered yet. Owned exclusively by
	// this goroutine — no locking.
	lagged := map[uint64]bool{}
	for {
		rec, err := s.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			s.cfg.Log.Warn("ebpf: ring buffer read error", "err", err)
			continue
		}
		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			s.cfg.Log.Debug("ebpf: drop malformed record", "err", err)
			continue
		}
		if sent, isLagged := lagged[ev.ConnID]; isLagged {
			if sent {
				continue // stream already truncated; discard the tail
			}
			tomb := TLSRecord{PID: ev.PID, TID: ev.TID, ConnID: ev.ConnID, Lagged: true}
			select {
			case s.out <- tomb:
				lagged[ev.ConnID] = true
			default:
			}
			continue
		}
		select {
		case s.out <- ev:
			continue
		default:
		}
		// Channel full: evict the oldest buffered record and lag its
		// connection (a tombstone victim just re-arms its pending state).
		select {
		case victim := <-s.out:
			if len(lagged) >= maxLaggedConns {
				s.cfg.Log.Warn("ebpf: lagged-connection set overflow, clearing", "size", len(lagged))
				lagged = map[uint64]bool{}
			}
			lagged[victim.ConnID] = false
		default:
		}
		select {
		case s.out <- ev:
		default:
		}
	}
}

// scanLoop runs discoverTargets/attachTarget immediately and then every
// cfg.Rescan, so pods started after the worker are picked up without a
// restart.
func (s *linuxSource) scanLoop() {
	defer s.wg.Done()
	s.rescan()
	t := time.NewTicker(s.cfg.Rescan)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.rescan()
		}
	}
}

func (s *linuxSource) rescan() {
	targets, complete, err := discoverTargets(s.cfg.ProcRoot, s.cfg.Log)
	if err != nil {
		s.cfg.Log.Warn("ebpf: discover targets", "err", err)
		return
	}
	prog := probeNames(&s.objs)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcileAttachments(targets, complete, time.Now(), func(t libTarget) ([]link.Link, error) {
		return attachTarget(prog, t, s.cfg.Log)
	})
}

// Caller owns mu; keeping discovery and attachment injection separate allows
// lifecycle checks without installing real kernel probes.
func (s *linuxSource) reconcileAttachments(targets []libTarget, complete bool, now time.Time, attach func(libTarget) ([]link.Link, error)) {
	for _, t := range targets {
		if a := s.attached[t.devIno]; a != nil {
			a.lastSeen = now
			continue
		}
		links, err := attach(t)
		if err != nil {
			s.cfg.Log.Debug("ebpf: attach failed", "lib", t.pathname, "pid", t.pid, "err", err)
			// Not marked attached: retry on the next rescan (the process
			// might still be starting up, e.g. its libssl mapping raced us).
			continue
		}
		s.attached[t.devIno] = &attachment{links: links, lastSeen: now}
		s.cfg.Log.Info("ebpf: attached TLS uprobes", "lib", t.pathname, "pid", t.pid, "hooks", len(links))
	}
	if complete {
		for key, a := range s.attached {
			if now.Sub(a.lastSeen) <= s.grace {
				continue
			}
			for _, l := range a.links {
				_ = l.Close()
			}
			delete(s.attached, key)
		}
	}
}

func (s *linuxSource) closeAttachments() {
	for _, l := range s.staticLinks {
		_ = l.Close()
	}
	s.staticLinks = nil
	for key, a := range s.attached {
		for _, l := range a.links {
			_ = l.Close()
		}
		delete(s.attached, key)
	}
}

func (s *linuxSource) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		_ = s.rd.Close() // unblocks drainLoop's Read()
		s.wg.Wait()

		s.mu.Lock()
		s.closeAttachments()
		s.mu.Unlock()

		s.objs.Close()
		close(s.out)
	})
	return nil
}
