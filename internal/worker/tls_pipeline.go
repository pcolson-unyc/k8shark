package worker

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pablocolson/k8shark/internal/worker/ebpf"
	"github.com/pablocolson/k8shark/pkg/api"
)

const (
	maxTLSStreams           = 4096
	maxTLSQueuedBytes int64 = 64 << 20
)

type tlsByteBudget struct {
	mu            sync.Mutex
	used          int64
	limit         int64
	drops         atomic.Uint64
	reportedDrops *atomic.Uint64
}

func newTLSByteBudget(limit int64) *tlsByteBudget {
	if limit <= 0 {
		limit = maxTLSQueuedBytes
	}
	return &tlsByteBudget{limit: limit}
}

func (b *tlsByteBudget) reserve(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+int64(n) > b.limit {
		b.drops.Add(1)
		if b.reportedDrops != nil {
			b.reportedDrops.Add(1)
		}
		return false
	}
	b.used += int64(n)
	return true
}
func (b *tlsByteBudget) release(n int) { b.mu.Lock(); b.used -= int64(n); b.mu.Unlock() }

// startTLSCapture wires the eBPF TLS uprobe layer (internal/worker/ebpf) into
// the given pipeline, running it alongside AF_PACKET. It never blocks and
// never fails Run(): a load/attach error (non-Linux, missing BTF, missing
// capabilities, no BTF, ...) is logged and the worker continues on AF_PACKET
// alone — eBPF is a hybrid, additive bonus, not a dependency.
// startTLSCapture starts the eBPF TLS uprobe capture feeding p. It reports
// whether capture actually started, so the caller can tell whether any source
// (this or AF_PACKET) is live. It is independent of AF_PACKET: it runs whether
// or not AF_PACKET is available.
func startTLSCapture(ctx context.Context, log *slog.Logger, p *pipeline, opts Options) bool {
	procRoot := opts.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	if opts.EnableGoTLS {
		log.Warn("--enable-go-tls is not implemented yet (WS1 Phase 2b); ignoring — OpenSSL/boringssl uprobes are unaffected")
	}

	src, err := ebpf.New(ebpf.Config{ProcRoot: procRoot, Log: log})
	if err != nil {
		log.Warn("eBPF TLS capture unavailable", "err", err)
		return false
	}
	if err := src.Attach(); err != nil {
		log.Warn("eBPF TLS capture attach failed", "err", err)
		_ = src.Close()
		return false
	}
	log.Info("eBPF TLS uprobe capture enabled", "procRoot", procRoot)

	go p.consumeTLS(ctx, src)
	go func() {
		<-ctx.Done()
		_ = src.Close()
	}()
	return true
}

// tlsIdleTimeout matches the AF_PACKET flow GC cadence (worker.go's gc
// ticker) so an idle synthetic TLS connection doesn't outlive its AF_PACKET
// counterpart in memory.
const tlsIdleTimeout = 30 * time.Second

// consumeTLS maps decrypted TLS records from the eBPF uprobe layer onto the
// same connID-keyed dissectors AF_PACKET uses (see conn.go, consumeStreamID).
// It is the single reader of src.Records() and owns the streams map
// exclusively, so no locking is needed here.
//
// Phase 2a limitation (no in-kernel 4-tuple resolution — that's Phase 2b):
// the connID is synthetic, built from (pid, tid, ssl pointer), so
// consumeStreamID's port-based dispatch (respPorts/amqpPorts/pgPort) never
// matches and every eBPF-fed stream is dissected as HTTP. That is the
// intended target (TLS-terminated traffic is overwhelmingly HTTPS in this
// deployment), but Redis/Postgres/AMQP running *over TLS* will not be
// recognized as such until Phase 2b supplies real ports, or a content-sniff
// dispatch is added ahead of it.
func (p *pipeline) consumeTLS(ctx context.Context, src ebpf.Source) {
	budget := newTLSByteBudget(maxTLSQueuedBytes)
	budget.reportedDrops = &p.sink.tlsBudgetDrops
	p.consumeTLSBounded(ctx, src, maxTLSStreams, budget)
}

func (p *pipeline) consumeTLSBounded(ctx context.Context, src ebpf.Source, streamLimit int, budget *tlsByteBudget) {
	streams := map[uint64]*tlsStream{}
	gc := time.NewTicker(15 * time.Second)
	defer gc.Stop()
	closeAll := func() {
		for _, st := range streams {
			st.close()
		}
	}
	for {
		select {
		case <-ctx.Done():
			closeAll()
			return
		case <-gc.C:
			cutoff := time.Now().Add(-tlsIdleTimeout)
			for k, st := range streams {
				if st.lastSeen.Before(cutoff) {
					st.close()
					delete(streams, k)
				}
			}
		case rec, ok := <-src.Records():
			if !ok {
				closeAll()
				return
			}
			if rec.Lagged {
				// Backpressure dropped an interior chunk of this connection
				// upstream (see ebpf loader drainLoop): close the stream so
				// its dissectors see a clean truncation instead of a hole.
				if st := streams[rec.ConnID]; st != nil {
					st.close()
					delete(streams, rec.ConnID)
					p.sink.tlsLagDrops.Add(1)
				}
				continue
			}
			if p.sink.paused() {
				continue // hub told this worker to stop turning capture into entries
			}
			st := streams[rec.ConnID]
			if st == nil {
				if len(streams) >= streamLimit {
					p.sink.tlsBudgetDrops.Add(1)
					continue
				}
				st = newTLSStream(p, rec, budget)
				streams[rec.ConnID] = st
			}
			st.lastSeen = time.Now()
			st.feed(rec)
		}
	}
}

// tlsStream fans one eBPF-observed SSL connection out into its two directional
// byte streams (mirroring how AF_PACKET hands the TCP reassembler two
// gopacket.Flow directions). Both directions share one connID, so request and
// response pair through the same p.conns/p.flows key.
//
// Dispatch is by content-sniff (consumeSniffedID / sniffTLS), NOT by port:
// the synthetic connID has no real port, so the AF_PACKET port dispatch would
// send everything to HTTP. The request/response role
// is taken from the stream's content (Postgres/Redis message direction, HTTP
// self-detection) so capture works whether the traced process is the CLIENT
// or the SERVER — e.g. hooking a CNPG Postgres server's OpenSSL captures every
// client's queries decrypted regardless of the client's TLS library. The
// write/read direction is only a fallback hint for the few message bytes that
// are ambiguous between the two directions.
type tlsStream struct {
	write, read *chanPipe
	lastSeen    time.Time
}

func newTLSStream(p *pipeline, rec ebpf.TLSRecord, budget *tlsByteBudget) *tlsStream {
	// The connID is fixed once, at stream creation, and shared by both
	// directions so request/response always pair — even though the tcp_*
	// kprobes may resolve the real 4-tuple only after some records. Phase 2b:
	// if the first record already carries a resolved tuple, use the real
	// IPs/ports; otherwise fall back to the synthetic pid:<n> identity (still
	// unique per SSL connection via the ssl_ctx pointer in ConnID).
	var c connID
	if rec.SrcIP != "" && rec.DstIP != "" {
		c = connID{
			srcIP:   rec.SrcIP,
			dstIP:   rec.DstIP,
			srcPort: int(rec.SrcPort),
			dstPort: int(rec.DstPort),
		}
	} else {
		c = connID{
			srcIP:   "pid:" + strconv.Itoa(int(rec.PID)),
			dstIP:   "pid:" + strconv.Itoa(int(rec.PID)) + ":tls",
			srcPort: int(rec.TID),
			dstPort: int(rec.ConnID % 65536),
		}
	}
	st := &tlsStream{write: newChanPipe(64, budget), read: newChanPipe(64, budget)}
	go func() { defer st.write.discard(); p.consumeSniffedID(c, st.write, true) }()
	go func() { defer st.read.discard(); p.consumeSniffedID(c, st.read, false) }()
	return st
}

// consumeSniffedID dispatches one direction of a stream to the right
// dissector by sniffing its opening bytes instead of its port. Used by two
// callers with no usable port to key on: the eBPF TLS path above (decrypted
// records carry a synthetic connID) and, from pipeline.go's consumeStreamID,
// the AF_PACKET fallback for a well-known protocol remapped onto a
// non-standard port. isRequest is the direction hint (see tlsStream doc for
// the eBPF case; consumeStreamID derives it from the ephemeral/higher-port
// heuristic instead) — sniffTLS only falls back to it for the handful of
// message types ambiguous from content alone.
func (p *pipeline) consumeSniffedID(c connID, r io.Reader, isRequest bool) {
	br := bufio.NewReader(r)
	proto, req := sniffTLS(br, isRequest)
	switch proto {
	case api.ProtocolPostgres:
		p.consumePostgresID(c, br, req)
	case api.ProtocolRedis:
		p.consumeRedisID(c, br, req, api.ProtocolRedis)
	case api.ProtocolAMQP:
		p.consumeAMQPID(c, br, req)
	default:
		// HTTP self-detects request vs. response from its own first bytes
		// (consumeHTTPID's "HTTP/" peek), and cleanly discards anything it
		// can't parse — so it is also the safe fallback for unrecognized data.
		p.consumeHTTPID(c, br)
	}
}

// sniffTLS peeks the head of a decrypted stream and returns the L7 protocol
// plus whether this direction is the request side. Peek-only: the bytes stay
// buffered for the dissector. Role is taken from content for the unambiguous
// client markers (a Postgres StartupMessage/SSLRequest or an AMQP protocol
// header can only be the client), otherwise from dirHint.
func sniffTLS(br *bufio.Reader, dirHint bool) (api.Protocol, bool) {
	// AMQP client opens with the literal 8-byte protocol header.
	if b, _ := br.Peek(4); len(b) == 4 && string(b) == "AMQP" {
		return api.ProtocolAMQP, true
	}
	b, _ := br.Peek(8)
	if len(b) >= 8 {
		// Postgres untyped StartupMessage/SSLRequest: [int32 len][int32 code],
		// code 0x00030000 (protocol 3.0), 80877103 (SSLRequest) or 80877102
		// (CancelRequest). len's high byte is 0 for any realistic size.
		if b[0] == 0x00 {
			switch binary.BigEndian.Uint32(b[4:8]) {
			case 0x00030000, 80877103, 80877102:
				return api.ProtocolPostgres, true // only the client sends these
			}
		}
	}
	if len(b) >= 2 {
		// Postgres typed message (either direction, e.g. mid-stream capture):
		// an ASCII type byte followed by an int32 length whose high byte is 0.
		// The b[1]==0x00 guard rejects HTTP methods ("GET ", "POST").
		if isPGTypeByte(b[0]) && b[1] == 0x00 {
			// Prefer the role the type byte itself implies (frontend vs
			// backend) — this is what makes SERVER-side capture work: the
			// server's SSL_write carries backend messages (R/K/Z/T...) so it's
			// the response side even though it's the "write" direction. Fall
			// back to dirHint only for the bytes shared by both directions.
			if role, ok := pgRole(b[0]); ok {
				return api.ProtocolPostgres, role
			}
			return api.ProtocolPostgres, dirHint
		}
		// RESP (Redis/Valkey): every value begins with one of these markers.
		// A leading '*' (array) is a command (request); a simple-status/error/
		// integer reply marks the response side — again content, not direction,
		// so server-side capture isn't inverted.
		switch b[0] {
		case '*':
			return api.ProtocolRedis, true
		case '+', '-', ':':
			return api.ProtocolRedis, false
		case '$', '>', '~', '%', '_', '#', ',', '(', '=':
			return api.ProtocolRedis, dirHint
		}
	}
	return api.ProtocolHTTP, dirHint
}

// isPGTypeByte reports whether b is a PostgreSQL message type byte we key on
// (frontend Q/P/B/E/D/C/S/X + backend R/S/K/Z/T/D/C/E/I/N), used only as a
// weak signal alongside the length-high-byte==0 check.
func isPGTypeByte(b byte) bool {
	switch b {
	case 'Q', 'P', 'B', 'E', 'D', 'C', 'S', 'X', 'R', 'K', 'Z', 'T', 'I', 'N':
		return true
	default:
		return false
	}
}

// pgRole classifies a Postgres message type byte as request (frontend) or
// response (backend) when it is unambiguous. Several bytes are shared by both
// directions (D=Describe/DataRow, C=Close/CommandComplete, S=Sync/
// ParameterStatus, E=Execute/ErrorResponse) — for those ok is false and the
// caller keeps the direction hint. The first message on a fresh connection is
// always unambiguous (client: StartupMessage/Query; server: Authentication
// 'R'), so a connection captured from its start is oriented correctly on both
// directions regardless of whether the client or the server process is traced.
func pgRole(b byte) (isRequest bool, ok bool) {
	switch b {
	case 'Q', 'P', 'B', 'X': // Query, Parse, Bind, Terminate — frontend only
		return true, true
	case 'R', 'K', 'Z', 'T', 'I', 'N': // Auth, BackendKeyData, ReadyForQuery, RowDescription, EmptyQuery, NoticeResponse — backend only
		return false, true
	default: // D/C/S/E shared, or not classified
		return false, false
	}
}

func (st *tlsStream) feed(rec ebpf.TLSRecord) {
	if len(rec.Data) == 0 {
		return
	}
	switch rec.Direction {
	case ebpf.TLSDirWrite:
		st.write.push(rec.Data)
	case ebpf.TLSDirRead:
		st.read.push(rec.Data)
	}
}

func (st *tlsStream) close() {
	st.write.Close()
	st.read.Close()
}

// chanPipe is a bounded, non-blocking io.Reader fed by discrete []byte chunks.
// Standard io.Pipe blocks the writer until a reader drains it; here the writer
// (the eBPF ring-buffer drain loop, indirectly) must never block on a
// slow/stuck dissector goroutine.
//
// On overflow it does NOT drop an interior chunk: for a byte-stream dissector a
// hole in the middle desyncs the parser and yields garbled entries for the rest
// of the connection. Instead the pipe marks itself lagged and, once the
// already-buffered chunks drain, Read returns EOF — a consistent truncated
// prefix beats corruption. (sink.go's emit() can drop whole entries because
// each is self-contained; a stream chunk is not.)
type chanPipe struct {
	mu        sync.Mutex
	ch        chan []byte
	closed    chan struct{}
	done      bool
	lagged    atomic.Bool
	buf       []byte
	bufCharge int
	budget    *tlsByteBudget
}

func newChanPipe(size int, budget ...*tlsByteBudget) *chanPipe {
	var b *tlsByteBudget
	if len(budget) > 0 {
		b = budget[0]
	}
	return &chanPipe{ch: make(chan []byte, size), closed: make(chan struct{}), budget: b}
}

// push appends a chunk without ever blocking. If the buffer is full the pipe
// marks itself lagged (rather than dropping an interior chunk, which would
// desync the stream parser); Read then delivers EOF once the buffered chunks
// drain. Single-writer: only the consumeTLS goroutine calls push per pipe.
func (c *chanPipe) push(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	if c.lagged.Load() {
		return
	}
	if c.budget != nil && !c.budget.reserve(len(b)) {
		c.lagged.Store(true)
		if !c.done {
			c.done = true
			close(c.closed)
		}
		return
	}
	select {
	case c.ch <- b:
	default:
		if c.budget != nil {
			c.budget.release(len(b))
		}
		c.lagged.Store(true)
		c.done = true
		close(c.closed)
	}
}

func (c *chanPipe) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			if n == len(c.buf) {
				if c.budget != nil {
					c.budget.release(c.bufCharge)
				}
				c.buf = nil
				c.bufCharge = 0
			} else {
				c.buf = c.buf[n:]
			}
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		// Prefer draining a buffered chunk over observing lag/close, so the
		// already-enqueued prefix is always delivered in full.
		select {
		case b, ok := <-c.ch:
			if !ok {
				return 0, io.EOF
			}
			c.mu.Lock()
			c.buf, c.bufCharge = b, len(b)
			c.mu.Unlock()
			continue
		default:
		}
		if c.lagged.Load() {
			// Buffered chunks drained and subsequent data was dropped: stop with
			// a clean truncation rather than a mid-stream hole.
			return 0, io.EOF
		}
		select {
		case b, ok := <-c.ch:
			if !ok {
				return 0, io.EOF
			}
			c.mu.Lock()
			c.buf, c.bufCharge = b, len(b)
			c.mu.Unlock()
		case <-c.closed:
			// A writer may have queued a final chunk before Close won the
			// blocking select. Deliver that prefix before returning EOF.
			select {
			case b := <-c.ch:
				c.mu.Lock()
				c.buf, c.bufCharge = b, len(b)
				c.mu.Unlock()
			default:
				return 0, io.EOF
			}
		}
	}
}

// Close unblocks any in-progress or future Read with io.EOF. Safe to call
// more than once.
func (c *chanPipe) Close() {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return
	}
	c.done = true
	close(c.closed)
	c.mu.Unlock()
}

// discard is called by the reader owner after its parser returns.
func (c *chanPipe) discard() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done {
		c.done = true
		close(c.closed)
	}
	if c.budget != nil {
		if c.bufCharge > 0 {
			c.budget.release(c.bufCharge)
		}
	}
	c.buf = nil
	c.bufCharge = 0
	for {
		select {
		case b := <-c.ch:
			if c.budget != nil {
				c.budget.release(len(b))
			}
		default:
			return
		}
	}
}
