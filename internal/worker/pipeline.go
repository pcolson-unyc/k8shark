package worker

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/pablocolson/k8shark/internal/config"
	"github.com/pablocolson/k8shark/pkg/api"
)

// Well-known service ports used to pick a TCP dissector.
const (
	redisPort = 6379
	pgPort    = 5432
	amqpPort  = 5672
	dnsPort   = 53
	mysqlPort = 3306
	mongoPort = 27017
	kafkaPort = 9092
)

// pipeline turns reassembled TCP streams and UDP datagrams into paired L7
// entries. It owns the request/response correlation state, which is protocol
// agnostic: each dissector enqueues a request and later completes it with a
// response, and the pipeline pairs them FIFO per connection.
type pipeline struct {
	sink   *sink
	node   string
	nodeIP string
	log    *slog.Logger

	seq atomic.Uint64

	mu    sync.Mutex
	conns map[string]*connState    // request/response pairing, keyed by canonical conn
	dns   map[string]*dnsPending   // DNS query pairing, keyed by client+message-id
	mongo map[string]*mongoPending // MongoDB pairing, keyed by conn+requestID (see dissect_mongo.go)
	kafka map[string]*kafkaPending // Kafka pairing, keyed by conn+correlationID (see dissect_kafka.go)

	redisDB map[string]*redisDBState // per-connection Redis DB index (tracked from SELECT n), guarded by mu

	flowMu sync.Mutex
	flows  map[string]*flowState // generic L4 flow accounting, keyed by canonical conn

	// respPorts maps a RESP (Redis wire protocol) port to the protocol label it
	// should be emitted under (redis|valkey). Defaults to {6379: redis}.
	respPorts map[int]api.Protocol

	// amqpPorts is the set of ports carrying AMQP 0-9-1 (RabbitMQ). Defaults to
	// {5672: true}.
	amqpPorts map[int]bool

	// Capture-depth bounds (per direction). Defaults from config; overridden by
	// applyCaptureOpts from the worker Options.
	captureBodies bool
	bodyCap       int // max body bytes per direction
	rawCap        int // max raw hex bytes per direction (<0 disables raw capture)
	headerHexCap  int // max L2/L3/L4 header hexdump bytes

	// redactHeaders scrubs credential-bearing HTTP header values, query
	// params and RESP auth command arguments (the raw hex view is separate —
	// disable it via rawCap < 0 for full scrubbing).
	redactHeaders bool

	// redactPGParams replaces every Postgres Bind parameter value with
	// [REDACTED] (see pgResponses' 'E' case) when set. Unlike redactHeaders,
	// this defaults off: Bind params are positional wire values with no
	// name attached, so there's no way to redact just the sensitive ones —
	// only a blanket replace-everything is possible, which throws away
	// query-value visibility that's usually the whole point of watching
	// Postgres traffic. Opt in when queries in your cluster do carry
	// unparameterized secrets in bind values.
	redactPGParams bool
}

func newPipeline(s *sink, node, nodeIP string, log *slog.Logger) *pipeline {
	return &pipeline{
		sink:          s,
		node:          node,
		nodeIP:        nodeIP,
		log:           log,
		conns:         map[string]*connState{},
		dns:           map[string]*dnsPending{},
		mongo:         map[string]*mongoPending{},
		kafka:         map[string]*kafkaPending{},
		redisDB:       map[string]*redisDBState{},
		flows:         map[string]*flowState{},
		respPorts:     map[int]api.Protocol{redisPort: api.ProtocolRedis},
		amqpPorts:     map[int]bool{amqpPort: true},
		captureBodies: true,
		bodyCap:       config.DefaultBodyCaptureBytes,
		rawCap:        config.DefaultRawCaptureBytes,
		headerHexCap:  config.DefaultHeaderHexBytes,
	}
}

// applyCaptureOpts overrides the capture-depth bounds from the worker Options.
// A BodyBytes/RawBytes of 0 keeps the default; a negative RawBytes disables raw
// capture entirely.
func (p *pipeline) applyCaptureOpts(opts Options) {
	p.captureBodies = opts.CaptureBodies
	p.redactHeaders = opts.RedactHeaders
	p.redactPGParams = opts.RedactPGParams
	if opts.BodyBytes > 0 {
		p.bodyCap = opts.BodyBytes
	}
	switch {
	case opts.RawBytes < 0:
		p.rawCap = -1
	case opts.RawBytes > 0:
		p.rawCap = opts.RawBytes
	}
}

// connState holds requests awaiting their response on one TCP connection.
// HTTP/1.x, RESP and the Postgres protocol are all request-ordered per
// connection, so FIFO pairing is correct.
type connState struct {
	reqs []*pendingReq
}

type pendingReq struct {
	protocol api.Protocol
	req      api.Payload
	src, dst api.Endpoint
	ts       time.Time
}

// reqBacklogCap bounds the per-connection pending-request queue. FIFO pairing
// (see completeResponse) means a connection whose responses are never seen — or
// that desynced after a missed response — would otherwise grow this slice
// without limit; on overflow the oldest pending request is dropped.
const reqBacklogCap = 1024

// enqueueRequest records a request awaiting its response.
func (p *pipeline) enqueueRequest(key string, proto api.Protocol, req api.Payload, src, dst api.Endpoint) {
	pr := &pendingReq{protocol: proto, req: req, src: src, dst: dst, ts: time.Now()}
	p.mu.Lock()
	cs := p.conns[key]
	if cs == nil {
		cs = &connState{}
		p.conns[key] = cs
	}
	// PipelineDepth = requests already outstanding ahead of this one. Set through
	// the shared *RedisDetail pointer under the lock (before the pending request
	// becomes visible to the response goroutine) so it is race-free.
	if req.Redis != nil {
		req.Redis.PipelineDepth = len(cs.reqs)
	}
	cs.reqs = append(cs.reqs, pr)
	if len(cs.reqs) > reqBacklogCap {
		cs.reqs = cs.reqs[1:] // drop the oldest pending request to bound growth
	}
	p.mu.Unlock()

	// Flag this connection as L7-dissected so the generic L4 flow tracker does
	// not also emit a redundant flow entry for it.
	p.markL7(key)
}

// completeResponsePairRetries/Delay bound how long completeResponse waits for
// a request that hasn't been enqueued *yet*. AF_PACKET's request and response
// goroutines are ordered by real network causality (a response can't arrive
// before the request that produced it was fully sent), so the pending
// request is essentially always already there. The eBPF TLS path
// (tls_pipeline.go) has no such guarantee: consumeTLS feeds both directions
// back-to-back from in-memory records with no real network delay between
// them, so its two independently-scheduled per-direction goroutines can
// legitimately race — completeResponse observed before the matching
// enqueueRequest — dropping every entry on that connection. This bounded
// retry (worst case ~8ms) closes that race for both callers at negligible
// cost to the genuine "capture started mid-connection" case, which still
// correctly gives up and returns after the budget.
const (
	completeResponsePairRetries = 4
	completeResponsePairDelay   = 2 * time.Millisecond
)

// peekPendingMethod returns the HTTP method of the oldest pending request on
// key without consuming it (completeResponse does the actual pop once the
// full response is parsed). Returns "" if there is no pending request yet
// (e.g. capture started mid-response), in which case http.ReadResponse falls
// back to its nil-request/GET behavior, matching prior behavior.
func (p *pipeline) peekPendingMethod(key string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cs := p.conns[key]; cs != nil && len(cs.reqs) > 0 {
		return cs.reqs[0].req.Method
	}
	return ""
}

// isInterimStatus reports whether code is a 1xx informational response (100
// Continue, 103 Early Hints, ...). 101 Switching Protocols is excluded: it is
// the final response to its Upgrade request (and ends HTTP framing on the
// connection), not an interim one to be skipped.
func isInterimStatus(code int) bool {
	return code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols
}

// completeResponse pairs a response with the oldest pending request on the same
// connection and emits the finished entry.
//
// Known limitation: pairing is strict head-of-line FIFO with no request-id
// correlation, so a single missed response (capture started mid-response, a
// dropped segment, a dissector that failed to emit) shifts every subsequent
// response onto the wrong request for the rest of the connection, with no way
// to resync. The protocols dissected here are all strictly request-ordered per
// connection, so in the common lossless case FIFO is exact.
//
// firstByteTime is when the response's first byte was observed on the wire
// (used only to fill HTTPDetail.TTFBMs); pass the zero time.Time for
// protocols that don't populate resp.HTTP.
func (p *pipeline) completeResponse(key string, resp api.Payload, statusCode int, status string, firstByteTime time.Time) {
	var pr *pendingReq
	for attempt := 0; ; attempt++ {
		p.mu.Lock()
		cs := p.conns[key]
		if cs != nil && len(cs.reqs) > 0 {
			pr = cs.reqs[0]
			cs.reqs = cs.reqs[1:]
			p.mu.Unlock()
			break
		}
		p.mu.Unlock()
		if attempt >= completeResponsePairRetries {
			return // no request to pair with (capture started mid-connection)
		}
		time.Sleep(completeResponsePairDelay)
	}

	if resp.HTTP != nil && !firstByteTime.IsZero() {
		resp.HTTP.TTFBMs = firstByteTime.Sub(pr.ts).Milliseconds()
	}

	now := time.Now()
	entry := &api.Entry{
		ID:          p.node + "-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    pr.protocol,
		Timestamp:   pr.ts,
		ElapsedMs:   now.Sub(pr.ts).Milliseconds(),
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      pr.src,
		Destination: pr.dst,
		Request:     pr.req,
		Response:    resp,
		StatusCode:  statusCode,
		Status:      status,
	}
	// EXT-3: surface an end-to-end correlation id (W3C traceparent trace-id /
	// x-request-id / x-correlation-id) from the request headers as a top-level
	// Entry field, so a request can be followed across services. Only the HTTP
	// path populates Payload.Headers (see flattenHeaders), so this is a no-op
	// for the other protocols.
	entry.TraceID = correlationID(pr.req.Headers)
	// Snapshot L4 after p.mu is released (snapshotL4 takes only flowMu, never
	// nested inside mu). May be nil for a capture that started mid-connection.
	entry.L4 = p.snapshotL4(key)
	p.sink.emit(entry)
}

// --- TCP dispatch -----------------------------------------------------------

type tcpStreamFactory struct{ p *pipeline }

func (f *tcpStreamFactory) New(netFlow, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	// Surface a lost segment (AF_PACKET ring drop, FlushOlderThan discard) as a
	// tcpreader.DataLost error from Read instead of silently splicing over the
	// hole — see lossReader for how that is turned into a clean truncation.
	r.LossErrors = true
	go f.p.consumeStream(netFlow, transport, &r)
	return &r
}

// consumeStream routes one direction of an AF_PACKET-discovered TCP connection
// to the right dissector. It is a thin wrapper: consumeStreamID does the real
// work, keyed off connID rather than gopacket flows, so the same dispatch also
// serves eBPF-decrypted TLS streams (see tls_pipeline.go), which have no
// gopacket.Flow to offer.
//
// The AF_PACKET reader is wrapped in a lossReader so a dropped TCP segment
// (the ReaderStream has LossErrors enabled) purges this connection's pending
// requests and truncates the direction rather than desyncing the FIFO pairing.
// The eBPF TLS path calls consumeStreamID directly (it has its own Lagged
// handling, see tls_pipeline.go) and so is unaffected.
func (p *pipeline) consumeStream(netFlow, transport gopacket.Flow, r io.Reader) {
	c := connIDFromFlows(netFlow, transport)
	key := c.key()
	lr := &lossReader{r: r, onLoss: func() {
		p.purgePending(key)
		p.sink.tcpLossEvents.Add(1)
	}}
	p.consumeStreamID(c, lr)
}

// lossReader wraps an AF_PACKET tcpreader.ReaderStream (with LossErrors
// enabled) and converts a lost TCP segment — which tcpassembly would otherwise
// skip over silently, desyncing the FIFO request/response pairing for the rest
// of the connection — into a clean, loud truncation of the direction:
//
//  1. onLoss purges the connection's pending requests (better to drop a few
//     pairs than emit every subsequent one mispaired — see completeResponse's
//     documented FIFO limitation) and counts the event (surfaced at
//     /api/workers and /metrics as k8shark_worker_tcp_loss_events_total),
//  2. whatever remains on the stream is drained to EOF (so tcpassembly's
//     Reassembled never blocks on an unread stream), and
//  3. io.EOF is returned to the dissector, which stops this direction cleanly
//     instead of parsing across the hole.
//
// We deliberately truncate rather than attempt an in-band resync: the single
// consumeStreamID dispatch feeds the HTTP, Postgres, Redis, AMQP, DNS-over-TCP
// and WebSocket dissectors, and a robust "scan to the next message boundary"
// differs per protocol and is easy to get subtly wrong in one pass. Dropping
// the rest of the direction is the conservative choice that upholds the
// invariant: never emit a mispaired entry after a known gap. Because the
// bufio.Reader each dissector wraps around this reader still holds any bytes it
// buffered *before* the gap, those valid pre-gap messages are parsed as usual;
// only post-gap bytes are discarded.
type lossReader struct {
	r      io.Reader
	onLoss func()
	done   bool
}

func (l *lossReader) Read(p []byte) (int, error) {
	if l.done {
		return 0, io.EOF
	}
	n, err := l.r.Read(p)
	if errors.Is(err, tcpreader.DataLost) {
		if l.onLoss != nil {
			l.onLoss()
		}
		// Drain the rest of the stream past the gap so reassembly isn't blocked
		// on an unread stream; DiscardBytesToEOF (unlike io.Copy) reads through
		// any further DataLost errors until the real EOF.
		tcpreader.DiscardBytesToEOF(l.r)
		l.done = true
		if n > 0 {
			// tcpreader always reports DataLost with n==0, but stay correct if a
			// wrapper ever returns pre-gap bytes alongside it: deliver them now
			// and report EOF on the next call (the l.done guard above).
			return n, nil
		}
		return 0, io.EOF
	}
	return n, err
}

// purgePending drops every pending (unanswered) request on a connection. It is
// called when a lost TCP segment is detected on either direction: FIFO pairing
// (completeResponse) cannot survive a hole, so each still-outstanding request
// is discarded rather than risk pairing it — and every later response — against
// the wrong message.
func (p *pipeline) purgePending(key string) {
	p.mu.Lock()
	delete(p.conns, key)
	p.mu.Unlock()
}

// consumeStreamID routes one direction of a TCP connection to the right
// dissector, chosen by the well-known server port (falling back to HTTP
// sniffing). Shared dispatch point for consumeStream (AF_PACKET) and
// consumeTLS (eBPF-decrypted plaintext).
func (p *pipeline) consumeStreamID(c connID, r io.Reader) {
	src, dst := c.srcPort, c.dstPort
	// Valkey and Redis are wire-identical (same RESP2/RESP3 protocol, usually the
	// same port), so the label emitted here is config-driven (an operator-supplied
	// port list, see Options.RedisPorts/ValkeyPorts in worker.go) rather than
	// something detected from the bytes on the wire.
	if proto, ok := p.respPorts[dst]; ok {
		p.consumeRedisID(c, r, true, proto)
		return
	}
	if proto, ok := p.respPorts[src]; ok {
		p.consumeRedisID(c, r, false, proto)
		return
	}
	if p.amqpPorts[dst] {
		p.consumeAMQPID(c, r, true)
		return
	}
	if p.amqpPorts[src] {
		p.consumeAMQPID(c, r, false)
		return
	}
	switch {
	case dst == pgPort || src == pgPort:
		p.consumePostgresID(c, r, dst == pgPort)
	case dst == mysqlPort || src == mysqlPort:
		p.consumeMySQLID(c, r, dst == mysqlPort)
	case dst == mongoPort || src == mongoPort:
		p.consumeMongoID(c, r, dst == mongoPort)
	case dst == kafkaPort || src == kafkaPort:
		p.consumeKafkaID(c, r, dst == kafkaPort)
	case dst == dnsPort || src == dnsPort:
		p.consumeDNSTCPID(c, r, dst == dnsPort)
	default:
		// No well-known port matched (Redis/Postgres/AMQP remapped onto a
		// non-standard port is common with k8s Services): content-sniff
		// instead of assuming HTTP, reusing the same sniffTLS-based dispatch
		// the eBPF TLS path uses (tls_pipeline.go) since it has no port to
		// key on either. dirHint follows newFlow's (dissect_l4.go)
		// "ephemeral/higher port is the client" heuristic; sniffTLS only
		// falls back to it for the few message types ambiguous from content
		// alone.
		p.consumeSniffedID(c, r, src > dst)
	}
}

// --- HTTP over TCP ----------------------------------------------------------

// consumeHTTP reads one direction of an AF_PACKET-discovered TCP connection
// and parses HTTP messages. Thin wrapper over consumeHTTPID (see conn.go).
func (p *pipeline) consumeHTTP(netFlow, transport gopacket.Flow, r io.Reader) {
	p.consumeHTTPID(connIDFromFlows(netFlow, transport), r)
}

// consumeHTTPID reads one direction of a TCP connection (identified by c) and
// parses HTTP messages. The direction (request vs response) is auto-detected
// from the first bytes. Fed by both AF_PACKET (via consumeHTTP) and eBPF TLS
// uprobes (via consumeTLS/tls_pipeline.go), which is the whole point of the
// hybrid capture layer: decrypted HTTPS lands in the exact same dissector as
// plaintext HTTP.
func (p *pipeline) consumeHTTPID(c connID, r io.Reader) {
	r, cr := p.capture(r)
	br := bufio.NewReader(r)
	peek, err := br.Peek(5)
	if err != nil {
		_, _ = io.Copy(io.Discard, br)
		return
	}
	key := c.key()

	if string(peek) == "HTTP/" {
		// Server -> client: a stream of responses.
		for {
			// Peek(1) blocks until the response's first byte is actually on
			// the wire without consuming it, so this timestamp reflects
			// first-byte arrival rather than whenever ReadResponse happens
			// to finish parsing headers.
			if _, err := br.Peek(1); err != nil {
				return
			}
			firstByte := time.Now()
			// The oldest pending request's method decides whether a body is
			// expected: net/http only skips a HEAD response's (possibly
			// non-zero) Content-Length when told the request method — a nil
			// req defaults to "a body may follow", which desyncs the rest of
			// the connection onto the wrong request/response pairs.
			method := p.peekPendingMethod(key)
			resp, err := http.ReadResponse(br, &http.Request{Method: method})
			if err != nil {
				return
			}
			if isInterimStatus(resp.StatusCode) {
				// 1xx informational responses (100 Continue, 103 Early
				// Hints, ...) precede the real response to the same
				// request; pairing them here would consume the pending
				// request early and shift every later response onto the
				// wrong request for the rest of the connection.
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				continue
			}
			if resp.StatusCode == http.StatusSwitchingProtocols && isWebSocketUpgradeResponse(resp) {
				// The server accepted an Upgrade: after a 101 the connection
				// stops speaking HTTP and carries RFC 6455 frames. Emit the
				// handshake as a normal HTTP entry (it pairs with the pending
				// GET). A 101 has no HTTP body (net/http leaves br positioned
				// right after the response headers, at the first frame), so we
				// hand that same br straight to the frame parser instead of
				// looping back into http.ReadResponse (which would misparse the
				// frames and abandon the connection — the bug this fixes).
				p.completeResponse(key, api.Payload{
					StatusCode: resp.StatusCode,
					Headers:    p.flattenHeaders(resp.Header),
					Raw:        rawOf(cr),
					HTTP:       &api.HTTPDetail{Version: resp.Proto},
					Summary:    "101 Switching Protocols",
				}, resp.StatusCode, classifyHTTP(resp.StatusCode), firstByte)
				// Both directions are WebSocket now; this goroutine owns the
				// server -> client direction (on the response flow Src is the
				// server).
				srv, cli := c.endpoints()
				p.consumeWSFrames(br, srv, cli)
				return
			}
			body, truncated, full := p.drainBody(resp.Body)
			body, truncated = decompressBody(body, truncated, resp.Header.Get("Content-Encoding"), p.bodyCap)
			ct := resp.Header.Get("Content-Type")
			p.completeResponse(key, api.Payload{
				StatusCode:  resp.StatusCode,
				Headers:     p.flattenHeaders(resp.Header),
				Body:        safeBody(body),
				Truncated:   truncated,
				Size:        full,
				ContentType: ct,
				Raw:         rawOf(cr),
				HTTP:        &api.HTTPDetail{Version: resp.Proto, ContentType: ct},
				Summary:     strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode),
			}, resp.StatusCode, classifyHTTP(resp.StatusCode), firstByte)
		}
	}
	// Client -> server: a stream of requests.
	src, dst := c.endpoints()
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, truncated, full := p.drainBody(req.Body)
		body, truncated = decompressBody(body, truncated, req.Header.Get("Content-Encoding"), p.bodyCap)
		ct := req.Header.Get("Content-Type")
		p.enqueueRequest(key, api.ProtocolHTTP, api.Payload{
			Method:      req.Method,
			Path:        redactedRequestURI(req.URL, p.redactHeaders),
			Host:        req.Host,
			Headers:     p.flattenHeaders(req.Header),
			Body:        safeBody(body),
			Truncated:   truncated,
			Size:        full,
			ContentType: ct,
			Raw:         rawOf(cr),
			HTTP:        &api.HTTPDetail{Version: req.Proto, ContentType: ct, Query: parseQuery(req.URL, p.redactHeaders)},
			Summary:     req.Method + " " + redactedRequestURI(req.URL, p.redactHeaders),
		}, src, dst)
		if isWebSocketUpgradeRequest(req) {
			// The client asked to switch protocols. Its half of the connection
			// carries WebSocket frames from here on (the server's 101 is seen
			// and paired on the response goroutine); switch this direction to
			// frame parsing. drainBody read nothing for the bodyless upgrade
			// GET, so br is positioned at the first client frame.
			p.consumeWSFrames(br, src, dst)
			return
		}
	}
}

// --- WebSocket (RFC 6455) ---------------------------------------------------

// isWebSocketUpgradeRequest reports whether req is an HTTP/1.1 Upgrade to
// WebSocket (Upgrade: websocket + a Connection token of "upgrade").
func isWebSocketUpgradeRequest(req *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") &&
		headerHasToken(req.Header.Get("Connection"), "upgrade")
}

// isWebSocketUpgradeResponse reports whether resp (already known to be a 101)
// completes a WebSocket upgrade (Upgrade: websocket).
func isWebSocketUpgradeResponse(resp *http.Response) bool {
	return strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "websocket")
}

// headerHasToken reports whether a comma-separated header value contains token
// (case-insensitive), e.g. Connection: "keep-alive, Upgrade".
func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// RFC 6455 frame opcodes.
const (
	wsOpcodeContinuation byte = 0x0
	wsOpcodeText         byte = 0x1
	wsOpcodeBinary       byte = 0x2
	wsOpcodeClose        byte = 0x8
	wsOpcodePing         byte = 0x9
	wsOpcodePong         byte = 0xA
)

const (
	// wsMaxPayload bounds a single frame's declared payload length. A frame
	// claiming more is treated as desynced/garbled framing (an attacker or a
	// misparse can put an arbitrary 64-bit length on the wire) and ends the
	// direction rather than trying to consume it — 8 MiB is far above any
	// realistic control/text frame while staying a safe ceiling.
	wsMaxPayload = 8 << 20
	// wsPreviewBytes bounds how many payload bytes are read into memory for the
	// frame preview; the remainder is discarded so the stream stays
	// frame-aligned regardless of frame size (cf. redisMaxValueDisplay).
	wsPreviewBytes = 256
	// wsSummaryPreview bounds the preview text embedded in an entry's summary.
	wsSummaryPreview = 120
)

// consumeWSFrames parses RFC 6455 frames from one direction of an
// already-upgraded WebSocket connection, emitting a standalone api.Entry per
// frame (the async, unpaired model dissect_redis.go's emitRedisPush uses). It
// is deliberately minimal: it decodes the FIN/opcode/mask bit and the 7/16/64-
// bit payload length, unmasks with the 4-byte key, and renders a bounded
// preview. It never panics on a short or garbled frame — any read error or
// oversize length ends the direction cleanly (discarding the rest so the
// stream advances), never a partial re-read that could desync further.
func (p *pipeline) consumeWSFrames(br *bufio.Reader, src, dst api.Endpoint) {
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			_, _ = io.Copy(io.Discard, br)
			return
		}
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		payloadLen := uint64(hdr[1] & 0x7f)
		switch payloadLen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				_, _ = io.Copy(io.Discard, br)
				return
			}
			payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				_, _ = io.Copy(io.Discard, br)
				return
			}
			payloadLen = binary.BigEndian.Uint64(ext[:])
		}
		if payloadLen > wsMaxPayload {
			_, _ = io.Copy(io.Discard, br) // desynced or absurd length — stop cleanly
			return
		}
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(br, maskKey[:]); err != nil {
				_, _ = io.Copy(io.Discard, br)
				return
			}
		}
		// Read only a bounded prefix for the preview; discard the remainder so
		// the reader stays aligned on the next frame boundary.
		previewN := payloadLen
		if previewN > wsPreviewBytes {
			previewN = wsPreviewBytes
		}
		preview := make([]byte, int(previewN))
		if _, err := io.ReadFull(br, preview); err != nil {
			_, _ = io.Copy(io.Discard, br) // truncated frame — stop, don't misparse
			return
		}
		if masked {
			for i := range preview {
				preview[i] ^= maskKey[i%4]
			}
		}
		if remaining := payloadLen - previewN; remaining > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(remaining)); err != nil {
				p.emitWSFrame(src, dst, opcode, preview, payloadLen)
				_, _ = io.Copy(io.Discard, br)
				return
			}
		}
		p.emitWSFrame(src, dst, opcode, preview, payloadLen)
		if opcode == wsOpcodeClose {
			_, _ = io.Copy(io.Discard, br) // no frames follow a close
			return
		}
	}
}

// emitWSFrame emits one WebSocket frame as a standalone entry.
func (p *pipeline) emitWSFrame(src, dst api.Endpoint, opcode byte, payload []byte, fullLen uint64) {
	name := wsOpcodeName(opcode)
	var summary, body string
	switch opcode {
	case wsOpcodeClose:
		if code, reason := wsCloseInfo(payload); code != 0 {
			summary = "close " + strconv.Itoa(code)
			if reason != "" {
				summary += " " + reason
			}
			body = summary
		} else {
			summary = "close"
		}
	case wsOpcodePing, wsOpcodePong:
		summary = name
		if len(payload) > 0 {
			body = safeBody(string(payload))
		}
	default: // text / binary / continuation — safeBody renders binary via binaryPreview
		body = safeBody(string(payload))
		if body != "" {
			summary = name + " " + truncate(body, wsSummaryPreview)
		} else {
			summary = name
		}
	}
	p.sink.emit(&api.Entry{
		ID:          p.node + "-ws-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    api.ProtocolWS,
		Timestamp:   time.Now(),
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      src,
		Destination: dst,
		Request: api.Payload{
			WSOpcode:  name,
			Summary:   summary,
			Body:      body,
			Size:      int(fullLen),
			Truncated: fullLen > uint64(len(payload)),
		},
		Status: "success",
	})
}

// wsCloseInfo decodes a close frame's payload: a 2-byte big-endian status code
// (RFC 6455 §7.4) optionally followed by a UTF-8 reason. Returns (0, "") when
// no code is present (an empty close payload is valid).
func wsCloseInfo(payload []byte) (code int, reason string) {
	if len(payload) < 2 {
		return 0, ""
	}
	code = int(binary.BigEndian.Uint16(payload[:2]))
	if len(payload) > 2 {
		reason = safeBody(string(payload[2:]))
	}
	return code, reason
}

// wsOpcodeName renders an RFC 6455 opcode as a short name (fed to the ws.opcode
// filter field and the UI).
func wsOpcodeName(op byte) string {
	switch op {
	case wsOpcodeContinuation:
		return "continuation"
	case wsOpcodeText:
		return "text"
	case wsOpcodeBinary:
		return "binary"
	case wsOpcodeClose:
		return "close"
	case wsOpcodePing:
		return "ping"
	case wsOpcodePong:
		return "pong"
	default:
		return "opcode-" + strconv.Itoa(int(op))
	}
}

// --- DNS over UDP -----------------------------------------------------------

type dnsPending struct {
	question  string
	questions []api.DNSQuestion
	id        int
	src, dst  api.Endpoint
	ts        time.Time
	raw       *api.RawView
}

// handleDNS processes a single UDP packet that carries a DNS layer. raw is
// the undecoded DNS message bytes (gopacket Layer.LayerContents()) for the
// Raw tab — DNS has no bufio.Reader-based capture path like the TCP
// dissectors, so it's captured directly from the packet layer instead.
func (p *pipeline) handleDNS(netFlow gopacket.Flow, udp *layers.UDP, dns *layers.DNS, raw []byte) {
	srcIP, dstIP := netFlow.Src().String(), netFlow.Dst().String()
	if !dns.QR {
		// Query: the sender is the client.
		p.dnsQuery(
			api.Endpoint{IP: srcIP, Port: int(udp.SrcPort)},
			api.Endpoint{IP: dstIP, Port: int(udp.DstPort), Name: "dns"},
			dns, raw)
		return
	}
	// Response: the client is now the destination.
	p.dnsResponse(dstIP, int(udp.DstPort), dns, raw)
}

// dnsQuery records a query awaiting its response, keyed by the client
// endpoint plus the message ID. Shared by the UDP packet path (handleDNS)
// and the TCP stream path (consumeDNSTCPID) so both transports pair through
// the same pending map.
func (p *pipeline) dnsQuery(client, server api.Endpoint, dns *layers.DNS, raw []byte) {
	q := ""
	if len(dns.Questions) > 0 {
		q = string(dns.Questions[0].Name)
	}
	p.mu.Lock()
	p.dns[dnsKey(client.IP, client.Port, dns.ID)] = &dnsPending{
		question:  q,
		questions: dnsQuestions(dns.Questions),
		id:        int(dns.ID),
		src:       client,
		dst:       server,
		ts:        time.Now(),
		raw:       rawViewFromBytes(raw, p.rawCap),
	}
	p.mu.Unlock()
}

// dnsResponse pairs a response with its pending query (looked up by the
// client endpoint the response is headed to, plus the message ID) and emits
// the finished entry.
func (p *pipeline) dnsResponse(clientIP string, clientPort int, dns *layers.DNS, raw []byte) {
	key := dnsKey(clientIP, clientPort, dns.ID)
	p.mu.Lock()
	pend := p.dns[key]
	delete(p.dns, key)
	p.mu.Unlock()
	if pend == nil {
		return
	}
	answer := ""
	for _, a := range dns.Answers {
		if a.IP != nil {
			answer = a.IP.String()
			break
		}
	}
	reqDetail := &api.DNSDetail{ID: pend.id, Questions: pend.questions}
	respDetail := &api.DNSDetail{
		ID:            int(dns.ID),
		Answers:       dnsRecords(dns.Answers),
		Authority:     dnsRecords(dns.Authorities),
		Additional:    dnsRecords(dns.Additionals),
		Rcode:         dnsRcodeName(dns.ResponseCode),
		Authoritative: dns.AA,
		RecursionAvl:  dns.RA,
	}
	now := time.Now()
	p.sink.emit(&api.Entry{
		ID:          p.node + "-dns-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    api.ProtocolDNS,
		Timestamp:   pend.ts,
		ElapsedMs:   now.Sub(pend.ts).Milliseconds(),
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      pend.src,
		Destination: pend.dst,
		Request:     api.Payload{Question: pend.question, Summary: "A? " + pend.question, DNS: reqDetail, Raw: pend.raw},
		Response:    api.Payload{Answer: answer, Summary: dnsRcode(dns.ResponseCode), DNS: respDetail, Raw: rawViewFromBytes(raw, p.rawCap)},
		Status:      dnsStatus(dns.ResponseCode),
	})
}

// --- DNS over TCP -----------------------------------------------------------

// consumeDNSTCPID dissects one direction of a TCP port-53 connection.
// Resolvers retry over TCP whenever a UDP answer is truncated (TC bit), which
// large records (SVCB/HTTPS, DNSSEC) make common. Framing (RFC 1035 §4.2.2)
// is a 2-byte big-endian length prefix per message — inherently bounded at
// 64KiB — each carrying a standard DNS payload. Decoded messages feed the
// same pending map as UDP (dnsQuery/dnsResponse), so TCP queries and answers
// pair, and entries are tagged, exactly like UDP ones. isRequest means
// client -> server (queries); the server -> client direction carries answers.
func (p *pipeline) consumeDNSTCPID(c connID, r io.Reader, isRequest bool) {
	// On the client -> server direction src is the client; flipped otherwise.
	cli, srv := c.endpoints()
	if !isRequest {
		srv, cli = cli, srv
	}
	srv.Name = "dns"

	marked := false
	var lenBuf [2]byte
	for {
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			_, _ = io.Copy(io.Discard, r)
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n == 0 {
			// A zero-length frame is never valid DNS; the framing is broken.
			_, _ = io.Copy(io.Discard, r)
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(r, msg); err != nil {
			return // stream ended mid-message
		}
		var dns layers.DNS
		if err := dns.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil {
			_, _ = io.Copy(io.Discard, r)
			return // not DNS after all — drop the rest of this direction
		}
		if !marked {
			// L7-dissected: don't also emit a generic L4 flow for this conn.
			p.markL7(c.key())
			marked = true
		}
		if !dns.QR {
			p.dnsQuery(cli, srv, &dns, msg)
			continue
		}
		p.dnsResponse(cli.IP, cli.Port, &dns, msg)
	}
}

// gc drops stale pending state so a lossy capture can't leak memory.
func (p *pipeline) gc() {
	cutoff := time.Now().Add(-30 * time.Second)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, d := range p.dns {
		if d.ts.Before(cutoff) {
			delete(p.dns, k)
		}
	}
	for k, m := range p.mongo {
		if m.ts.Before(cutoff) {
			delete(p.mongo, k)
		}
	}
	for k, m := range p.kafka {
		if m.ts.Before(cutoff) {
			delete(p.kafka, k)
		}
	}
	for k, cs := range p.conns {
		kept := cs.reqs[:0]
		for _, r := range cs.reqs {
			if !r.ts.Before(cutoff) {
				kept = append(kept, r)
			}
		}
		cs.reqs = kept
		if len(cs.reqs) == 0 {
			delete(p.conns, k)
		}
	}
	for k, r := range p.redisDB {
		if r.ts.Before(cutoff) {
			delete(p.redisDB, k)
		}
	}
}

// --- helpers ----------------------------------------------------------------

func connKey(netFlow, transport gopacket.Flow) string {
	a := netFlow.Src().String() + ":" + transport.Src().String()
	b := netFlow.Dst().String() + ":" + transport.Dst().String()
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}

func flowEndpoints(netFlow, transport gopacket.Flow) (src, dst api.Endpoint) {
	src = api.Endpoint{IP: netFlow.Src().String(), Port: portOf(transport.Src().String())}
	dst = api.Endpoint{IP: netFlow.Dst().String(), Port: portOf(transport.Dst().String())}
	return
}

// dnsKey keys a pending query by the client's source IP *and port* plus the
// message ID: on ID+IP alone, two concurrent queries from the same IP
// (hostNetwork pods, SNAT) with colliding IDs would mispair.
func dnsKey(clientIP string, clientPort int, id uint16) string {
	return clientIP + ":" + strconv.Itoa(clientPort) + "/" + strconv.Itoa(int(id))
}

func portOf(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// drainBody reads up to p.bodyCap bytes of a message body, always consuming the
// rest so the stream advances. It returns the snippet, whether it was cut, and
// the full body length. When capture is disabled the body is discarded.
//
// A one-byte probe gates buffer allocation so an empty body (a GET request, a
// 204/304 response) allocates nothing, and the snippet buffer then grows only
// with the bytes actually present rather than a fixed p.bodyCap scratch buffer.
func (p *pipeline) drainBody(rc io.ReadCloser) (body string, truncated bool, full int) {
	if rc == nil {
		return "", false, 0
	}
	defer rc.Close()
	if !p.captureBodies || p.bodyCap <= 0 {
		_, _ = io.Copy(io.Discard, rc)
		return "", false, 0
	}
	var first [1]byte
	if n, _ := io.ReadFull(rc, first[:]); n == 0 {
		return "", false, 0 // empty body — no allocation
	}
	var b bytes.Buffer
	b.WriteByte(first[0])
	n, _ := io.Copy(&b, io.LimitReader(rc, int64(p.bodyCap-1)))
	extra, _ := io.Copy(io.Discard, rc) // consume the rest so the stream advances
	return b.String(), extra > 0, 1 + int(n) + int(extra)
}

// decompressBody transparently inflates a gzip/deflate-encoded HTTP body so
// it's readable in the UI and matchable by request.body/response.body
// filters, which otherwise never see anything but opaque compressed bytes —
// the majority of real-world HTTP APIs respond compressed. body is the
// already bodyCap-bounded raw (compressed) bytes drainBody produced, so
// decompression only ever processes at most bodyCap input bytes; the output
// is separately capped at limit bytes as a zip-bomb guard, since a small
// compressed payload can still expand enormously. A body that was itself cut
// off mid-stream, or that isn't actually valid gzip/deflate despite the
// header, falls back to the original bytes unchanged rather than erroring.
func decompressBody(body string, truncated bool, contentEncoding string, limit int) (string, bool) {
	if body == "" || limit <= 0 {
		return body, truncated
	}
	var zr io.Reader
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "gzip":
		gr, err := gzip.NewReader(strings.NewReader(body))
		if err != nil {
			return body, truncated
		}
		defer gr.Close()
		zr = gr
	case "deflate":
		fr := flate.NewReader(strings.NewReader(body))
		defer fr.Close()
		zr = fr
	default:
		return body, truncated
	}

	var out bytes.Buffer
	n, err := io.CopyN(&out, zr, int64(limit)+1)
	if n == 0 && err != nil && err != io.EOF {
		return body, truncated // header claimed gzip/deflate but the body isn't
	}
	decompressed := out.String()
	if int64(len(decompressed)) > int64(limit) {
		decompressed = decompressed[:limit]
		truncated = true
	}
	return decompressed, truncated
}

// safeBody replaces a non-printable body with a bounded hex preview plus its
// true byte length, instead of storing raw bytes that would corrupt JSON/UI
// rendering. Printable UTF-8 passes through unchanged. Applies to HTTP and
// AMQP bodies, mirroring how dissect_redis.go's redisDisplay already renders
// binary Redis values.
func safeBody(s string) string {
	if isRedisPrintable(s) {
		return s
	}
	return binaryPreview(s)
}

// capReader tees up to max bytes into buf while passing every read through. It
// records the first "connection head" bytes of one direction for the Raw view.
type capReader struct {
	r     io.Reader
	buf   []byte
	total int
	max   int
}

func newCapReader(r io.Reader, max int) *capReader {
	return &capReader{r: r, max: max, buf: make([]byte, 0, max)}
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.total += n
		if room := c.max - len(c.buf); room > 0 {
			take := n
			if take > room {
				take = room
			}
			c.buf = append(c.buf, p[:take]...)
		}
	}
	return n, err
}

func (c *capReader) raw() *api.RawView {
	if len(c.buf) == 0 {
		return nil
	}
	return &api.RawView{
		Hex:       hexDump(c.buf, c.max),
		Bytes:     c.total,
		Truncated: c.total > len(c.buf),
	}
}

// capture wraps a stream reader with a bounded recording tee (for the Raw view)
// unless raw capture is disabled (rawCap < 0), in which case cr is nil.
func (p *pipeline) capture(r io.Reader) (io.Reader, *capReader) {
	if p.rawCap < 0 {
		return r, nil
	}
	cr := newCapReader(r, p.rawCap)
	return cr, cr
}

// rawOf returns the RawView for a capReader, or nil when raw capture is off.
func rawOf(cr *capReader) *api.RawView {
	if cr == nil {
		return nil
	}
	return cr.raw()
}

// rawViewFromBytes builds a RawView from a single already-available byte
// slice — for capture paths with no bufio.Reader to tee (DNS, generic L4/ICMP
// flows), unlike the streaming capReader above. Returns nil when raw capture
// is disabled (cap < 0) or b is empty.
func rawViewFromBytes(b []byte, cap int) *api.RawView {
	if cap < 0 || len(b) == 0 {
		return nil
	}
	limit := len(b)
	if limit > cap {
		limit = cap
	}
	return &api.RawView{
		Hex:       hexDump(b[:limit], limit),
		Bytes:     len(b),
		Truncated: len(b) > limit,
	}
}

// sensitiveQueryParams are credential-bearing URL query parameter names
// whose values are scrubbed when redaction is on (names are kept so a
// scrubbed param's presence stays observable) — reuses redactHeaders rather
// than a dedicated flag, since both are the same "don't leak HTTP
// credentials into the capture" concern with the same safe default (on).
var sensitiveQueryParams = map[string]bool{
	"access_token":  true,
	"api_key":       true,
	"apikey":        true,
	"auth":          true,
	"client_secret": true,
	"password":      true,
	"refresh_token": true,
	"secret":        true,
	"session_token": true,
	"sig":           true,
	"signature":     true,
	"token":         true,
}

// parseQuery renders a URL's query parameters as a flat map (nil if none),
// scrubbing sensitiveQueryParams values when redact is on.
func parseQuery(u *url.URL, redact bool) map[string]string {
	if u == nil || u.RawQuery == "" {
		return nil
	}
	q := u.Query()
	if len(q) == 0 {
		return nil
	}
	out := make(map[string]string, len(q))
	for k, v := range q {
		if redact && sensitiveQueryParams[strings.ToLower(k)] {
			out[k] = redactedValue
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// redactedRequestURI renders u's path+query the way url.URL.RequestURI()
// does, but with sensitiveQueryParams values scrubbed — used for Path and
// Summary, which otherwise embed the raw (unredacted) query string even
// when HTTP.Query itself is scrubbed via parseQuery. Falls back to the
// original RequestURI() when nothing needed scrubbing, since re-encoding an
// untouched query string (net/url.Values.Encode sorts keys and re-escapes)
// would otherwise change formatting for no reason.
func redactedRequestURI(u *url.URL, redact bool) string {
	if !redact || u.RawQuery == "" {
		return u.RequestURI()
	}
	q := u.Query()
	changed := false
	for k := range q {
		if sensitiveQueryParams[strings.ToLower(k)] {
			q[k] = []string{redactedValue}
			changed = true
		}
	}
	if !changed {
		return u.RequestURI()
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return path + "?" + q.Encode()
}

// sensitiveHeaders are credential-bearing headers whose values are scrubbed
// when redaction is on (keys are kept so their presence stays observable).
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
}

const redactedValue = "[REDACTED]"

func (p *pipeline) flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		if p.redactHeaders && sensitiveHeaders[lk] {
			out[lk] = redactedValue
			continue
		}
		out[lk] = strings.Join(v, ", ")
	}
	return out
}

// correlationID extracts an end-to-end trace/request id from an HTTP request's
// headers (EXT-3), which flattenHeaders has already lowercased the keys of.
// Precedence: the W3C traceparent trace-id, else x-request-id, else
// x-correlation-id. Returns "" when none is present — the id is never
// fabricated. A traceparent that doesn't yield a valid trace-id falls through
// to the x-request-id/x-correlation-id headers rather than being surfaced raw.
func correlationID(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	if id := traceparentTraceID(headers["traceparent"]); id != "" {
		return id
	}
	if id := headers["x-request-id"]; id != "" {
		return id
	}
	return headers["x-correlation-id"]
}

// traceparentTraceID returns the 32-hex trace-id from a W3C traceparent value,
// which is the second hyphen-delimited field of
// "00-<32hextrace>-<16hexspan>-<flags>". Returns "" when the value doesn't have
// that shape (so the caller can fall back to another correlation header).
func traceparentTraceID(tp string) string {
	if tp == "" {
		return ""
	}
	parts := strings.Split(tp, "-")
	if len(parts) < 2 {
		return ""
	}
	id := parts[1]
	if len(id) != 32 || !isHexString(id) {
		return ""
	}
	return id
}

// isHexString reports whether s is entirely hex digits (either case).
func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func dnsRcode(c layers.DNSResponseCode) string {
	if c == layers.DNSResponseCodeNoErr {
		return "NOERROR"
	}
	return c.String()
}

// dnsRcodeName renders a response code with the canonical short DNS name (e.g.
// "NXDOMAIN"), used for the DNSDetail.Rcode field and the dns.rcode filter.
func dnsRcodeName(c layers.DNSResponseCode) string {
	switch c {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	default:
		return c.String()
	}
}

// dnsQuestions renders the question section into wire DNSQuestion values.
func dnsQuestions(qs []layers.DNSQuestion) []api.DNSQuestion {
	if len(qs) == 0 {
		return nil
	}
	out := make([]api.DNSQuestion, 0, len(qs))
	for _, q := range qs {
		out = append(out, api.DNSQuestion{
			Name:  string(q.Name),
			Type:  q.Type.String(),
			Class: q.Class.String(),
		})
	}
	return out
}

// dnsRecords renders a resource-record section into wire DNSRecord values.
func dnsRecords(rrs []layers.DNSResourceRecord) []api.DNSRecord {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]api.DNSRecord, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, api.DNSRecord{
			Name: string(rr.Name),
			Type: rr.Type.String(),
			TTL:  rr.TTL,
			Data: dnsRecordData(rr),
		})
	}
	return out
}

// dnsRecordData renders the rdata of a resource record to a printable string.
func dnsRecordData(rr layers.DNSResourceRecord) string {
	switch {
	case rr.IP != nil:
		return rr.IP.String()
	case len(rr.CNAME) > 0:
		return string(rr.CNAME)
	case len(rr.NS) > 0:
		return string(rr.NS)
	case len(rr.PTR) > 0:
		return string(rr.PTR)
	case len(rr.TXTs) > 0:
		parts := make([]string, len(rr.TXTs))
		for i, t := range rr.TXTs {
			parts[i] = string(t)
		}
		return strings.Join(parts, " ")
	case rr.SOA.MName != nil:
		return string(rr.SOA.MName) + " " + string(rr.SOA.RName)
	case rr.SRV.Name != nil:
		return string(rr.SRV.Name)
	default:
		return ""
	}
}

func dnsStatus(c layers.DNSResponseCode) string {
	if c == layers.DNSResponseCodeNoErr {
		return "success"
	}
	return "error"
}
