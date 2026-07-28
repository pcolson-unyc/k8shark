package worker

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/pablocolson/k8shark/pkg/api"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// flows builds matching request/response gopacket flows for a client on
// clientPort talking to a server on serverPort.
func flows(clientPort, serverPort int) (reqNet, reqTr, respNet, respTr gopacket.Flow) {
	ipA := layers.NewIPEndpoint(net.IP{10, 0, 0, 1})
	ipB := layers.NewIPEndpoint(net.IP{10, 0, 0, 2})
	c := layers.NewTCPPortEndpoint(layers.TCPPort(clientPort))
	s := layers.NewTCPPortEndpoint(layers.TCPPort(serverPort))
	reqNet, _ = gopacket.FlowFromEndpoints(ipA, ipB)
	reqTr, _ = gopacket.FlowFromEndpoints(c, s)
	respNet, _ = gopacket.FlowFromEndpoints(ipB, ipA)
	respTr, _ = gopacket.FlowFromEndpoints(s, c)
	return
}

// drain collects all entries currently buffered on the sink.
func drain(s *sink) []*api.Entry {
	var out []*api.Entry
	for {
		select {
		case e := <-s.ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

// --- Redis ------------------------------------------------------------------

func TestRedisBinaryValueRendering(t *testing.T) {
	// A SET of a gzip-compressed value: the command must render safely (key
	// stays readable, the binary value becomes a bounded hex preview) rather
	// than dumping raw bytes.
	gz := "\x1f\x8b\x08\x00" + strings.Repeat("\x00\xff\xfe", 40) // clearly non-printable, >32 bytes
	req := "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$" + strconv.Itoa(len(gz)) + "\r\n" + gz + "\r\n"
	v, err := parseRESP(bufio.NewReader(strings.NewReader(req)))
	if err != nil {
		t.Fatal(err)
	}
	got := renderRedisCommand(v)
	if !strings.HasPrefix(got, "SET key \\x1f8b0800") {
		t.Errorf("command = %q, want it to start with the SET key + hex preview", got)
	}
	if strings.ContainsRune(got, 0x00) || strings.Contains(got, "\xff") {
		t.Errorf("command still contains raw binary bytes: %q", got)
	}
	if !strings.Contains(got, "bytes)") {
		t.Errorf("command %q should note the true byte length", got)
	}

	// A printable value passes through untouched.
	if d := redisDisplay("hello world"); d != "hello world" {
		t.Errorf("redisDisplay(printable) = %q, want unchanged", d)
	}
}

func TestRedisRESPRendering(t *testing.T) {
	cmd, err := parseRESP(bufio.NewReader(strings.NewReader("*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := renderRedisCommand(cmd); got != "GET mykey" {
		t.Errorf("command = %q, want %q", got, "GET mykey")
	}

	cases := []struct {
		in      string
		summary string
		isErr   bool
	}{
		{"+OK\r\n", "OK", false},
		{"-ERR bad command\r\n", "ERR bad command", true},
		{":42\r\n", "(integer) 42", false},
		{"$3\r\nabc\r\n", "abc", false},
		{"$-1\r\n", "(nil)", false},
	}
	for _, c := range cases {
		v, err := parseRESP(bufio.NewReader(strings.NewReader(c.in)))
		if err != nil {
			t.Fatalf("parse %q: %v", c.in, err)
		}
		summary, _, isErr := renderRedisReply(v)
		if summary != c.summary || isErr != c.isErr {
			t.Errorf("reply %q = (%q,%v), want (%q,%v)", c.in, summary, isErr, c.summary, c.isErr)
		}
	}
}

func TestRedisPairingEndToEnd(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40000, redisPort)

	req := "*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n" + "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
	resp := "$5\r\nvalue\r\n" + "+OK\r\n"

	p.consumeRedis(rNet, rTr, strings.NewReader(req), true, api.ProtocolRedis)
	p.consumeRedis(sNet, sTr, strings.NewReader(resp), false, api.ProtocolRedis)

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Protocol != api.ProtocolRedis || got[0].Request.Command != "GET mykey" || got[0].Response.Summary != "value" {
		t.Errorf("entry0 = %+v", got[0])
	}
	if got[1].Request.Command != "SET foo bar" || got[1].Response.Summary != "OK" {
		t.Errorf("entry1 = %+v", got[1])
	}
}

// --- Valkey / RESP port labelling ---------------------------------------------

// Default configuration (no RedisPorts/ValkeyPorts overrides) must keep
// emitting ProtocolRedis on port 6379, proving the Valkey feature is
// backward-compatible and opt-in only.
func TestConsumeStreamDefaultPortIsRedis(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40020, redisPort)

	req := "*1\r\n$4\r\nPING\r\n"
	resp := "+PONG\r\n"

	p.consumeStream(rNet, rTr, strings.NewReader(req))
	p.consumeStream(sNet, sTr, strings.NewReader(resp))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Protocol != api.ProtocolRedis {
		t.Errorf("protocol = %q, want %q (default port 6379 must stay redis)", got[0].Protocol, api.ProtocolRedis)
	}
}

// A port configured (via respPorts, as buildRespPorts would populate it from
// --valkey-ports) as Valkey must emit ProtocolValkey entries, even though the
// bytes on the wire are indistinguishable from Redis.
func TestConsumeStreamConfiguredPortIsValkey(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	const valkeyPort = 16379
	p.respPorts = buildRespPorts(nil, []int{valkeyPort})
	rNet, rTr, sNet, sTr := flows(40021, valkeyPort)

	req := "*1\r\n$4\r\nPING\r\n"
	resp := "+PONG\r\n"

	p.consumeStream(rNet, rTr, strings.NewReader(req))
	p.consumeStream(sNet, sTr, strings.NewReader(resp))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Protocol != api.ProtocolValkey {
		t.Errorf("protocol = %q, want %q", got[0].Protocol, api.ProtocolValkey)
	}
}

// buildRespPorts: Valkey wins when a port is listed in both RedisPorts and
// ValkeyPorts, and the 6379 default stays redis unless overridden.
func TestBuildRespPorts(t *testing.T) {
	rp := buildRespPorts(nil, nil)
	if rp[redisPort] != api.ProtocolRedis {
		t.Errorf("default respPorts[%d] = %q, want redis", redisPort, rp[redisPort])
	}

	rp = buildRespPorts([]int{7000}, []int{7000, 7001})
	if rp[7000] != api.ProtocolValkey {
		t.Errorf("overlapping port 7000 = %q, want valkey to win", rp[7000])
	}
	if rp[7001] != api.ProtocolValkey {
		t.Errorf("port 7001 = %q, want valkey", rp[7001])
	}
	if rp[redisPort] != api.ProtocolRedis {
		t.Errorf("default port %d = %q, want redis to remain unaffected", redisPort, rp[redisPort])
	}
}

// --- non-standard ports (DIS-5 content-sniff fallback) ----------------------

// A well-known protocol (Redis here) exposed on a port none of the
// respPorts/amqpPorts/pgPort rules recognize must still be detected by
// content-sniffing the stream (consumeSniffedID), instead of silently
// falling into the HTTP sniff and being lost as a bare TCP flow.
func TestConsumeStreamNonStandardPortSniffsRedis(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	const oddPort = 16380 // not 6379, not configured, not pg/amqp
	rNet, rTr, sNet, sTr := flows(40022, oddPort)

	req := "*1\r\n$4\r\nPING\r\n"
	resp := "+PONG\r\n"

	p.consumeStream(rNet, rTr, strings.NewReader(req))
	p.consumeStream(sNet, sTr, strings.NewReader(resp))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Protocol != api.ProtocolRedis {
		t.Errorf("protocol = %q, want %q (content-sniff fallback should still recognize RESP)", got[0].Protocol, api.ProtocolRedis)
	}
}

// Plain HTTP on a port matching none of the well-known dissectors must keep
// working through the new content-sniff fallback (sniffTLS's default case is
// HTTP) — a regression guard for the common case.
func TestConsumeStreamNonStandardPortFallsBackToHTTP(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	const oddPort = 18080
	rNet, rTr, sNet, sTr := flows(40023, oddPort)

	req := "GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

	p.consumeStream(rNet, rTr, strings.NewReader(req))
	p.consumeStream(sNet, sTr, strings.NewReader(resp))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Protocol != api.ProtocolHTTP {
		t.Errorf("protocol = %q, want %q", got[0].Protocol, api.ProtocolHTTP)
	}
	if got[0].StatusCode != 200 {
		t.Errorf("statusCode = %d, want 200", got[0].StatusCode)
	}
}

// --- Postgres ---------------------------------------------------------------

func pgMsg(typ byte, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:], uint32(4+len(payload)))
	copy(buf[5:], payload)
	return buf
}

func pgStartup() []byte { // SSLRequest: len=8, code=80877103
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:], 8)
	binary.BigEndian.PutUint32(b[4:], 80877103)
	return b
}

func TestPostgresPairingEndToEnd(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40001, pgPort)

	// Requests: startup (skipped) + Simple Query + extended Parse/Execute.
	var req []byte
	req = append(req, pgStartup()...)
	req = append(req, pgMsg('Q', []byte("SELECT id FROM t\x00"))...)
	// Parse: stmt "s1", query, then int16 numParams(0).
	req = append(req, pgMsg('P', []byte("s1\x00UPDATE t SET x=1\x00\x00\x00"))...)
	// Execute: empty portal cstr + int32 maxRows(0).
	req = append(req, pgMsg('E', []byte("\x00\x00\x00\x00\x00"))...)

	// Responses: two DataRows + CommandComplete for the SELECT, then a
	// CommandComplete for the UPDATE.
	var resp []byte
	resp = append(resp, pgMsg('D', []byte{0, 1})...)
	resp = append(resp, pgMsg('D', []byte{0, 1})...)
	resp = append(resp, pgMsg('C', []byte("SELECT 2\x00"))...)
	resp = append(resp, pgMsg('C', []byte("UPDATE 3\x00"))...)

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Protocol != api.ProtocolPostgres || got[0].Request.Query != "SELECT id FROM t" {
		t.Errorf("entry0 request = %+v", got[0].Request)
	}
	if got[0].Response.Summary != "SELECT 2 (2 rows)" || got[0].Response.RowCount != 2 {
		t.Errorf("entry0 response = %+v", got[0].Response)
	}
	if got[1].Request.Query != "UPDATE t SET x=1" || got[1].Response.Summary != "UPDATE 3" {
		t.Errorf("entry1 = req %q resp %q", got[1].Request.Query, got[1].Response.Summary)
	}
}

func TestPostgresError(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40002, pgPort)

	req := pgMsg('Q', []byte("SELECT * FROM nope\x00"))
	// ErrorResponse: S=ERROR, C=42P01, M=relation "nope" does not exist, then 0.
	errPayload := []byte("SERROR\x00C42P01\x00Mrelation \"nope\" does not exist\x00\x00")
	resp := pgMsg('E', errPayload)

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Status != "error" {
		t.Errorf("status = %q, want error", got[0].Status)
	}
	if !strings.Contains(got[0].Response.Summary, "does not exist") || !strings.Contains(got[0].Response.Summary, "42P01") {
		t.Errorf("summary = %q", got[0].Response.Summary)
	}
}

// --- regression tests for issues found by the adversarial review ------------

// Deeply nested RESP arrays must be rejected, not overflow the stack.
func TestRESPDepthGuard(t *testing.T) {
	in := strings.Repeat("*1\r\n", 100000) + "+OK\r\n"
	if _, err := parseRESP(bufio.NewReader(strings.NewReader(in))); err == nil {
		t.Fatal("expected error for over-deep RESP nesting, got nil")
	}
}

// A RESP3 map is ONE reply value, not several — otherwise it desyncs pairing.
func TestRESP3MapSingleReply(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("%1\r\n$6\r\nserver\r\n$5\r\nredis\r\n"))
	n := 0
	for {
		if _, err := parseRESP(br); err != nil {
			break
		}
		n++
	}
	if n != 1 {
		t.Fatalf("RESP3 map parsed as %d values, want 1", n)
	}
}

// An unsolicited pub/sub message must not steal a pending request's response.
func TestRedisPubSubNotMispaired(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40010, redisPort)

	req := "*2\r\n$9\r\nSUBSCRIBE\r\n$4\r\nnews\r\n" + "*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"
	resp := "*3\r\n$9\r\nsubscribe\r\n$4\r\nnews\r\n:1\r\n" + // reply to SUBSCRIBE
		"*3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n" + // unsolicited push
		"$3\r\nbar\r\n" // reply to GET

	p.consumeRedis(rNet, rTr, strings.NewReader(req), true, api.ProtocolRedis)
	p.consumeRedis(sNet, sTr, strings.NewReader(resp), false, api.ProtocolRedis)

	var getEntry *api.Entry
	for _, e := range drain(s) {
		if e.Request.Command == "GET foo" {
			getEntry = e
		}
	}
	if getEntry == nil {
		t.Fatal("GET foo entry missing")
	}
	if getEntry.Response.Summary != "bar" {
		t.Errorf("GET foo paired with %q, want \"bar\" (pub/sub push mispaired it)", getEntry.Response.Summary)
	}
}

// startupMessage builds a plaintext libpq StartupMessage (protocol 3.0).
func startupMessage() []byte {
	params := []byte("user\x00postgres\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:], 0x00030000)
	copy(body[4:], params)
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[0:], uint32(4+len(body)))
	copy(out[4:], body)
	return out
}

// --- WS3 richer extraction: sub-object population ---------------------------

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

type pgCol struct {
	name string
	oid  uint32
}

// pgBindPayload builds a Bind message payload with text-format params.
func pgBindPayload(portal, stmt string, params []string) []byte {
	var b []byte
	b = append(append(b, []byte(portal)...), 0)
	b = append(append(b, []byte(stmt)...), 0)
	b = appendU16(b, 1) // one param format code
	b = appendU16(b, 0) // text
	b = appendU16(b, uint16(len(params)))
	for _, pv := range params {
		b = appendU32(b, uint32(len(pv)))
		b = append(b, []byte(pv)...)
	}
	return appendU16(b, 0) // no result format codes
}

// pgRowDesc builds a RowDescription payload for the given columns.
func pgRowDesc(cols ...pgCol) []byte {
	b := appendU16(nil, uint16(len(cols)))
	for _, c := range cols {
		b = append(append(b, []byte(c.name)...), 0)
		b = appendU32(b, 0)          // tableOID
		b = appendU16(b, 0)          // colAttr
		b = appendU32(b, c.oid)      // typeOID
		b = appendU16(b, 0xffff)     // typeSize (-1)
		b = appendU32(b, 0xffffffff) // typeMod (-1)
		b = appendU16(b, 0)          // format
	}
	return b
}

// Extended-query Parse+Bind+Execute -> typed params/columns/tag on the entry.
func TestPostgresExtendedDetail(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40030, pgPort)

	var req []byte
	req = append(req, pgStartup()...)
	req = append(req, pgMsg('P', []byte("s1\x00SELECT id,email FROM users WHERE id=$1 AND name=$2\x00\x00\x00"))...)
	req = append(req, pgMsg('B', pgBindPayload("", "s1", []string{"42", "bob"}))...)
	req = append(req, pgMsg('E', []byte("\x00\x00\x00\x00\x00"))...)

	var resp []byte
	resp = append(resp, pgMsg('T', pgRowDesc(pgCol{"id", 23}, pgCol{"email", 1043}))...)
	resp = append(resp, pgMsg('D', []byte{0, 2})...)
	resp = append(resp, pgMsg('C', []byte("SELECT 1\x00"))...)

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Request.Postgres == nil || e.Request.Postgres.StatementName != "s1" {
		t.Fatalf("statement name = %+v", e.Request.Postgres)
	}
	if got := e.Request.Postgres.Params; len(got) != 2 || got[0] != "42" || got[1] != "bob" {
		t.Errorf("params = %v, want [42 bob]", got)
	}
	if e.Response.Postgres == nil || e.Response.Postgres.Tag != "SELECT 1" {
		t.Fatalf("tag = %+v", e.Response.Postgres)
	}
	cols := e.Response.Postgres.Columns
	if len(cols) != 2 || cols[0].Name != "id" || cols[0].Type != "int4" || cols[1].Type != "varchar" {
		t.Errorf("columns = %+v", cols)
	}
}

// ErrorResponse -> typed PGError fields.
func TestPostgresErrorDetail(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40031, pgPort)

	req := pgMsg('Q', []byte("SELECT * FROM nope\x00"))
	errPayload := []byte("SERROR\x00VERROR\x00C42P01\x00Mrelation \"nope\" does not exist\x00Htry again\x00\x00")
	resp := pgMsg('E', errPayload)

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	pe := got[0].Response.Postgres
	if pe == nil || pe.Error == nil {
		t.Fatalf("no PGError: %+v", got[0].Response.Postgres)
	}
	if pe.Error.Code != "42P01" || pe.Error.Severity != "ERROR" || pe.Error.Hint != "try again" {
		t.Errorf("error = %+v", pe.Error)
	}
	if !strings.Contains(pe.Error.Message, "does not exist") {
		t.Errorf("message = %q", pe.Error.Message)
	}
}

// SELECT n + pipelined GET + RESP3 attribute reply -> DBIndex/PipelineDepth/
// ReplyType/Attributes.
func TestRedisDetail(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40040, redisPort)

	req := "*2\r\n$6\r\nSELECT\r\n$1\r\n2\r\n" + "*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"
	resp := "+OK\r\n" + "|1\r\n$3\r\nttl\r\n:60\r\n$3\r\nbar\r\n"

	p.consumeRedis(rNet, rTr, strings.NewReader(req), true, api.ProtocolRedis)
	p.consumeRedis(sNet, sTr, strings.NewReader(resp), false, api.ProtocolRedis)

	var get *api.Entry
	for _, e := range drain(s) {
		if e.Request.Command == "GET foo" {
			get = e
		}
	}
	if get == nil {
		t.Fatal("GET foo entry missing")
	}
	if get.Request.Redis == nil || get.Request.Redis.DBIndex != 2 {
		t.Errorf("DBIndex = %+v, want 2", get.Request.Redis)
	}
	if get.Request.Redis.PipelineDepth != 1 {
		t.Errorf("PipelineDepth = %d, want 1", get.Request.Redis.PipelineDepth)
	}
	if get.Response.Redis == nil || get.Response.Redis.Reply != "bar" || get.Response.Redis.ReplyType != "string" {
		t.Errorf("reply = %+v", get.Response.Redis)
	}
	if get.Response.Redis.Attributes["ttl"] != "60" {
		t.Errorf("attributes = %+v, want ttl=60", get.Response.Redis.Attributes)
	}
}

func TestRESP3MapReplyType(t *testing.T) {
	v, err := parseRESP(bufio.NewReader(strings.NewReader("%1\r\n$1\r\na\r\n$1\r\nb\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := respTypeName(v.typ); got != "map" {
		t.Errorf("replyType = %q, want map", got)
	}
}

// A NOERROR response with multiple A answers -> DNSDetail.Answers/Rcode.
func TestDNSAnswerDetail(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, _, respNet, _ := flows(50000, 53)

	q := &layers.DNS{ID: 7, Questions: []layers.DNSQuestion{{Name: []byte("svc.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	p.handleDNS(reqNet, &layers.UDP{SrcPort: 50000, DstPort: 53}, q, []byte("raw-query-bytes"))

	resp := &layers.DNS{
		ID: 7, QR: true, AA: true, RA: true, ResponseCode: layers.DNSResponseCodeNoErr,
		Answers: []layers.DNSResourceRecord{
			{Name: []byte("svc.local"), Type: layers.DNSTypeA, TTL: 30, IP: net.IP{1, 2, 3, 4}},
			{Name: []byte("svc.local"), Type: layers.DNSTypeA, TTL: 30, IP: net.IP{5, 6, 7, 8}},
		},
	}
	p.handleDNS(respNet, &layers.UDP{SrcPort: 53, DstPort: 50000}, resp, []byte("raw-response-bytes"))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Request.DNS == nil || len(e.Request.DNS.Questions) != 1 || e.Request.DNS.Questions[0].Type != "A" {
		t.Errorf("question detail = %+v", e.Request.DNS)
	}
	if e.Response.DNS == nil || e.Response.DNS.Rcode != "NOERROR" || !e.Response.DNS.Authoritative {
		t.Fatalf("response detail = %+v", e.Response.DNS)
	}
	if a := e.Response.DNS.Answers; len(a) != 2 || a[0].Data != "1.2.3.4" || a[1].Data != "5.6.7.8" {
		t.Errorf("answers = %+v", e.Response.DNS.Answers)
	}
	// Raw tab coverage (previously DNS never populated Raw at all).
	if e.Request.Raw == nil || e.Request.Raw.Bytes != len("raw-query-bytes") {
		t.Errorf("request raw = %+v, want a populated RawView over the query bytes", e.Request.Raw)
	}
	if e.Response.Raw == nil || e.Response.Raw.Bytes != len("raw-response-bytes") {
		t.Errorf("response raw = %+v, want a populated RawView over the response bytes", e.Response.Raw)
	}
}

func TestDNSNXDomainDetail(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, _, respNet, _ := flows(50001, 53)

	q := &layers.DNS{ID: 8, Questions: []layers.DNSQuestion{{Name: []byte("nope.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	p.handleDNS(reqNet, &layers.UDP{SrcPort: 50001, DstPort: 53}, q, nil)

	resp := &layers.DNS{
		ID: 8, QR: true, RA: true, ResponseCode: layers.DNSResponseCodeNXDomain,
		Authorities: []layers.DNSResourceRecord{
			{Name: []byte("local"), Type: layers.DNSTypeSOA, TTL: 30, SOA: layers.DNSSOA{MName: []byte("ns.local"), RName: []byte("hostmaster.local")}},
		},
	}
	p.handleDNS(respNet, &layers.UDP{SrcPort: 53, DstPort: 50001}, resp, nil)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Response.DNS == nil || e.Response.DNS.Rcode != "NXDOMAIN" {
		t.Errorf("rcode = %+v, want NXDOMAIN", e.Response.DNS)
	}
	if len(e.Response.DNS.Authority) != 1 {
		t.Errorf("authority = %+v", e.Response.DNS.Authority)
	}
	if e.Status != "error" {
		t.Errorf("status = %q, want error", e.Status)
	}
}

// dnsWire serializes a DNS message to real wire bytes via gopacket.
func dnsWire(t *testing.T, msg *layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := msg.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dnsTCPFrame wraps a DNS message in RFC 1035 §4.2.2 TCP framing (2-byte
// big-endian length prefix).
func dnsTCPFrame(payload []byte) []byte {
	b := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(b, uint16(len(payload)))
	copy(b[2:], payload)
	return b
}

// Two length-prefixed queries on the client direction plus their answers on
// the server direction -> two correctly-paired entries, dispatched by the
// port-53 case in consumeStreamID.
func TestDNSOverTCPPairing(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	cli := connID{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 40200, dstPort: 53}
	srv := connID{srcIP: "10.0.0.2", dstIP: "10.0.0.1", srcPort: 53, dstPort: 40200}

	q1 := dnsWire(t, &layers.DNS{ID: 21, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("a.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}})
	q2 := dnsWire(t, &layers.DNS{ID: 22, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("b.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}})
	p.consumeStreamID(cli, bytes.NewReader(append(dnsTCPFrame(q1), dnsTCPFrame(q2)...)))

	a1 := dnsWire(t, &layers.DNS{
		ID: 21, QR: true, ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{{Name: []byte("a.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers:   []layers.DNSResourceRecord{{Name: []byte("a.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 30, IP: net.IP{1, 2, 3, 4}}},
	})
	a2 := dnsWire(t, &layers.DNS{
		ID: 22, QR: true, ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{{Name: []byte("b.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers:   []layers.DNSResourceRecord{{Name: []byte("b.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 30, IP: net.IP{5, 6, 7, 8}}},
	})
	p.consumeStreamID(srv, bytes.NewReader(append(dnsTCPFrame(a1), dnsTCPFrame(a2)...)))

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	answers := map[string]string{}
	for _, e := range got {
		if e.Protocol != api.ProtocolDNS {
			t.Errorf("protocol = %q, want dns", e.Protocol)
		}
		if e.Source.Port != 40200 || e.Destination.Port != 53 || e.Destination.Name != "dns" {
			t.Errorf("endpoints = %+v -> %+v, want client:40200 -> dns:53", e.Source, e.Destination)
		}
		answers[e.Request.Question] = e.Response.Answer
	}
	if answers["a.local"] != "1.2.3.4" || answers["b.local"] != "5.6.7.8" {
		t.Errorf("pairing = %v, want a.local->1.2.3.4 b.local->5.6.7.8", answers)
	}
}

// Regression: two in-flight queries from the same IP with the same message ID
// but different source ports must pair independently (hostNetwork pods and
// SNAT make same-IP colliding IDs realistic) — the pending key includes the
// client port, not just IP+ID.
func TestDNSSameIDDistinctSourcePorts(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, _, respNet, _ := flows(50002, 53)

	mkQ := func(name string) *layers.DNS {
		return &layers.DNS{ID: 99, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	}
	p.handleDNS(reqNet, &layers.UDP{SrcPort: 50002, DstPort: 53}, mkQ("one.local"), nil)
	p.handleDNS(reqNet, &layers.UDP{SrcPort: 50003, DstPort: 53}, mkQ("two.local"), nil)

	mkA := func(name string, ip net.IP) *layers.DNS {
		return &layers.DNS{
			ID: 99, QR: true, ResponseCode: layers.DNSResponseCodeNoErr,
			Answers: []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, TTL: 30, IP: ip}},
		}
	}
	p.handleDNS(respNet, &layers.UDP{SrcPort: 53, DstPort: 50002}, mkA("one.local", net.IP{1, 1, 1, 1}), nil)
	p.handleDNS(respNet, &layers.UDP{SrcPort: 53, DstPort: 50003}, mkA("two.local", net.IP{2, 2, 2, 2}), nil)

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (same-ID queries must not collide)", len(got))
	}
	for _, e := range got {
		want := map[string]string{"one.local": "1.1.1.1", "two.local": "2.2.2.2"}[e.Request.Question]
		if e.Response.Answer != want {
			t.Errorf("question %q paired with answer %q, want %q", e.Request.Question, e.Response.Answer, want)
		}
	}
}

// Broken TCP framing (short prefix, zero-length frame, prefix promising more
// bytes than the stream holds) must not panic and must emit nothing.
func TestDNSOverTCPTruncatedFrame(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	cli := connID{srcIP: "10.0.0.1", dstIP: "10.0.0.2", srcPort: 40201, dstPort: 53}

	for _, stream := range [][]byte{
		{0x01},                         // can't even read the length prefix
		{0x00, 0x00, 0xde, 0xad},       // zero-length frame
		{0x01, 0x2c, 0x00, 0x01, 0x02}, // prefix says 300 bytes, only 3 present
	} {
		p.consumeStreamID(cli, bytes.NewReader(stream))
	}
	if got := drain(s); len(got) != 0 {
		t.Errorf("got %d entries from broken framing, want 0", len(got))
	}
}

// --- WS5: AMQP (RabbitMQ 0-9-1) ---------------------------------------------

func amqpFrame(ftype byte, channel uint16, payload []byte) []byte {
	b := make([]byte, 7+len(payload)+1)
	b[0] = ftype
	binary.BigEndian.PutUint16(b[1:], channel)
	binary.BigEndian.PutUint32(b[3:], uint32(len(payload)))
	copy(b[7:], payload)
	b[7+len(payload)] = 0xCE
	return b
}

func amqpMethod(class, method uint16, args []byte) []byte {
	p := make([]byte, 4+len(args))
	binary.BigEndian.PutUint16(p[0:], class)
	binary.BigEndian.PutUint16(p[2:], method)
	copy(p[4:], args)
	return p
}

func amqpShortStrBytes(s string) []byte { return append([]byte{byte(len(s))}, s...) }

const amqpHeader = "AMQP\x00\x00\x09\x01"

// Basic.Publish + content header + body -> one entry with exchange/rk/body.
func TestAMQPBasicPublish(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40100, amqpPort)

	// Basic.Publish args: reserved short(0) + exchange + routing-key + bits(1).
	var args []byte
	args = appendU16(args, 0)
	args = append(args, amqpShortStrBytes("orders")...)
	args = append(args, amqpShortStrBytes("new")...)
	args = append(args, 0x00) // mandatory/immediate bits
	publish := amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassBasic, 40, args))

	// Content header: class(2) weight(2) body-size(8)=5 flags(2).
	var hdr []byte
	hdr = appendU16(hdr, amqpClassBasic)
	hdr = appendU16(hdr, 0)
	hdr = append(hdr, 0, 0, 0, 0, 0, 0, 0, 5) // body-size = 5
	hdr = appendU16(hdr, 0)
	header := amqpFrame(amqpFrameHeader, 1, hdr)
	body := amqpFrame(amqpFrameBody, 1, []byte("hello"))

	stream := amqpHeader + string(publish) + string(header) + string(body)
	p.consumeStream(rNet, rTr, strings.NewReader(stream))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Protocol != api.ProtocolAMQP {
		t.Errorf("protocol = %q, want amqp", e.Protocol)
	}
	if e.Request.Exchange != "orders" || e.Request.RoutingKey != "new" {
		t.Errorf("exchange/rk = %q/%q, want orders/new", e.Request.Exchange, e.Request.RoutingKey)
	}
	if e.Request.Body != "hello" {
		t.Errorf("body = %q, want hello", e.Request.Body)
	}
	if !strings.Contains(e.Request.Summary, "PUBLISH orders/new") {
		t.Errorf("summary = %q", e.Request.Summary)
	}
}

// TestAMQPBasicProperties (DIS-9): a Publish whose content header carries
// content-type + a headers field-table (which must be SKIPPED to reach later
// properties) + correlation-id + reply-to + message-id must surface those
// three IDs and the content-type, proving the property list is walked in flag
// order past the field-table.
func TestAMQPBasicProperties(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40120, amqpPort)

	var args []byte
	args = appendU16(args, 0)
	args = append(args, amqpShortStrBytes("orders")...)
	args = append(args, amqpShortStrBytes("new")...)
	args = append(args, 0x00)
	publish := amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassBasic, 40, args))

	// property flags: content-type|headers|correlation-id|reply-to|message-id
	const flags = 0x8000 | 0x2000 | 0x0400 | 0x0200 | 0x0080
	var props []byte
	props = appendU16(props, flags)
	props = append(props, amqpShortStrBytes("application/json")...) // content-type
	// headers field table: one entry key="x" value shortstr("y"), must be skipped.
	var table []byte
	table = append(table, amqpShortStrBytes("x")...)
	table = append(table, 'S')  // field type: long string
	table = appendU32(table, 1) // string length
	table = append(table, 'y')
	props = appendU32(props, uint32(len(table)))
	props = append(props, table...)
	props = append(props, amqpShortStrBytes("corr-99")...)      // correlation-id
	props = append(props, amqpShortStrBytes("amq.reply-to")...) // reply-to
	props = append(props, amqpShortStrBytes("msg-7")...)        // message-id

	var hdr []byte
	hdr = appendU16(hdr, amqpClassBasic)
	hdr = appendU16(hdr, 0)
	hdr = append(hdr, 0, 0, 0, 0, 0, 0, 0, 2) // body-size = 2
	hdr = append(hdr, props...)
	header := amqpFrame(amqpFrameHeader, 1, hdr)
	body := amqpFrame(amqpFrameBody, 1, []byte("hi"))

	stream := amqpHeader + string(publish) + string(header) + string(body)
	p.consumeStream(rNet, rTr, strings.NewReader(stream))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	r := got[0].Request
	if r.ContentType != "application/json" {
		t.Errorf("contentType = %q, want application/json", r.ContentType)
	}
	if r.CorrelationID != "corr-99" {
		t.Errorf("correlationId = %q, want corr-99 (field table must be skipped)", r.CorrelationID)
	}
	if r.ReplyTo != "amq.reply-to" {
		t.Errorf("replyTo = %q, want amq.reply-to", r.ReplyTo)
	}
	if r.MessageID != "msg-7" {
		t.Errorf("messageId = %q, want msg-7", r.MessageID)
	}
}

// A garbled/truncated property list must not panic and must still emit the
// content entry (bodySize=0 here, so it completes on the header alone).
func TestAMQPBasicPropertiesTruncated(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40121, amqpPort)

	var args []byte
	args = appendU16(args, 0)
	args = append(args, amqpShortStrBytes("orders")...)
	args = append(args, amqpShortStrBytes("new")...)
	args = append(args, 0x00)
	publish := amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassBasic, 40, args))

	// flags claim content-type + correlation-id but the payload ends mid-string.
	var hdr []byte
	hdr = appendU16(hdr, amqpClassBasic)
	hdr = appendU16(hdr, 0)
	hdr = append(hdr, 0, 0, 0, 0, 0, 0, 0, 0) // body-size = 0
	hdr = appendU16(hdr, 0x8000|0x0400)       // content-type|correlation-id
	hdr = append(hdr, 20, 'a', 'b')           // shortstr claims len 20, only 2 bytes present
	header := amqpFrame(amqpFrameHeader, 1, hdr)

	stream := amqpHeader + string(publish) + string(header)
	p.consumeStream(rNet, rTr, strings.NewReader(stream)) // must not panic

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (truncated props must still emit)", len(got))
	}
}

// Queue.Declare surfaces without any content frames.
func TestAMQPQueueDeclare(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40101, amqpPort)

	var args []byte
	args = appendU16(args, 0) // reserved
	args = append(args, amqpShortStrBytes("payments")...)
	frame := amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassQueue, 10, args))

	p.consumeStream(rNet, rTr, strings.NewReader(amqpHeader+string(frame)))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Request.Queue != "payments" {
		t.Errorf("queue = %q, want payments", got[0].Request.Queue)
	}
	if !strings.Contains(got[0].Request.Summary, "QUEUE.DECLARE payments") {
		t.Errorf("summary = %q", got[0].Request.Summary)
	}
}

// Connection.Close with a >=400 reply-code is an error entry.
func TestAMQPConnectionCloseIsError(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40102, amqpPort)

	var args []byte
	args = appendU16(args, 320) // reply-code CONNECTION_FORCED
	args = append(args, amqpShortStrBytes("CONNECTION_FORCED")...)
	args = appendU16(args, 0) // class
	args = appendU16(args, 0) // method
	frame := amqpFrame(amqpFrameMethod, 0, amqpMethod(amqpClassConnection, 50, args))

	p.consumeStream(rNet, rTr, strings.NewReader(amqpHeader+string(frame)))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Status != "error" {
		t.Errorf("status = %q, want error", got[0].Status)
	}
}

// A frame whose frame-end byte != 0xCE (garbled/TLS) must bail without emitting.
func TestAMQPFramingGuard(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40103, amqpPort)

	frame := amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassQueue, 10, append(appendU16(nil, 0), amqpShortStrBytes("q")...)))
	frame[len(frame)-1] = 0x00 // corrupt the frame-end sentinel

	p.consumeStream(rNet, rTr, strings.NewReader(amqpHeader+string(frame)))

	if got := drain(s); len(got) != 0 {
		t.Fatalf("got %d entries, want 0 on framing error", len(got))
	}
}

// An AMQP 1.0 protocol header must be detected and skipped (no entries, no panic).
func TestAMQP10Skipped(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40104, amqpPort)

	stream := "AMQP\x00\x01\x00\x00" + "some 1.0 performative junk that must not parse"
	p.consumeStream(rNet, rTr, strings.NewReader(stream))

	if got := drain(s); len(got) != 0 {
		t.Fatalf("got %d entries, want 0 for AMQP 1.0", len(got))
	}
}

// A port configured as Valkey emits ProtocolValkey entries (label-only relabel).
func TestValkeyLabel(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	p.respPorts = buildRespPorts(nil, []int{6380})
	rNet, rTr, sNet, sTr := flows(40105, 6380)

	p.consumeStream(rNet, rTr, strings.NewReader("*1\r\n$4\r\nPING\r\n"))
	p.consumeStream(sNet, sTr, strings.NewReader("+PONG\r\n"))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Protocol != api.ProtocolValkey || got[0].Request.Command != "PING" {
		t.Errorf("entry = %q %q, want valkey PING", got[0].Protocol, got[0].Request.Command)
	}
}

// sslmode=prefer against a non-TLS server sends SSLRequest THEN a plaintext
// StartupMessage — two consecutive untyped messages. Both must be skipped.
func TestPostgresSSLPreferDoubleUntyped(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40011, pgPort)

	var req []byte
	req = append(req, pgStartup()...)      // untyped #1: SSLRequest
	req = append(req, startupMessage()...) // untyped #2: plaintext StartupMessage
	req = append(req, pgMsg('Q', []byte("SELECT 1\x00"))...)
	resp := pgMsg('C', []byte("SELECT 1\x00"))

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 || got[0].Request.Query != "SELECT 1" {
		t.Fatalf("expected 1 paired SELECT after skipping both untyped msgs, got %d: %+v", len(got), got)
	}
}

// --- HTTP ---------------------------------------------------------------

// TTFBMs must measure request-sent -> response-first-byte, distinct from (and
// smaller than) the total ElapsedMs — a real gap between the two consumeHTTP
// calls proves it's an actual duration, not a dead always-zero field.
func TestHTTPTTFB(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40200, 80)

	p.consumeHTTP(rNet, rTr, strings.NewReader("GET /x HTTP/1.1\r\nHost: h\r\n\r\n"))
	time.Sleep(10 * time.Millisecond)
	p.consumeHTTP(sNet, sTr, strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Response.HTTP == nil {
		t.Fatalf("entry has no Response.HTTP")
	}
	if got[0].Response.HTTP.TTFBMs <= 0 {
		t.Errorf("TTFBMs = %d, want > 0 given a real gap between request and response", got[0].Response.HTTP.TTFBMs)
	}
	if got[0].Response.HTTP.TTFBMs > got[0].ElapsedMs {
		t.Errorf("TTFBMs (%d) should not exceed total ElapsedMs (%d)", got[0].Response.HTTP.TTFBMs, got[0].ElapsedMs)
	}
}

// TestHTTPHeadResponseNotDesynced guards against a HEAD response's declared
// Content-Length being read as an actual body: per RFC 7230 a HEAD response
// never has one, but net/http only knows that when told the request method.
func TestHTTPHeadResponseNotDesynced(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40300, 80)

	p.consumeHTTP(rNet, rTr, strings.NewReader(
		"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n"+
			"GET /y HTTP/1.1\r\nHost: h\r\n\r\n"))
	// The HEAD response claims Content-Length: 5 but carries no body; naively
	// honoring that would eat the next response's bytes as "body".
	p.consumeHTTP(sNet, sTr, strings.NewReader(
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"+
			"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"))

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (a desynced HEAD response swallowed the next one)", len(got))
	}
	if got[0].Request.Method != "HEAD" || got[0].Response.StatusCode != 200 {
		t.Errorf("entry 0 = %s -> %d, want HEAD -> 200", got[0].Request.Method, got[0].Response.StatusCode)
	}
	if got[1].Request.Method != "GET" || got[1].Response.StatusCode != 201 {
		t.Errorf("entry 1 = %s -> %d, want GET -> 201", got[1].Request.Method, got[1].Response.StatusCode)
	}
}

// TestHTTPInterimResponseNotPaired guards against a 1xx informational
// response (100 Continue, 103 Early Hints, ...) being paired as if it were
// the final response, which would shift every later response on the
// connection onto the wrong request.
func TestHTTPInterimResponseNotPaired(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40301, 80)

	p.consumeHTTP(rNet, rTr, strings.NewReader(
		"POST /upload HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok"))
	p.consumeHTTP(sNet, sTr, strings.NewReader(
		"HTTP/1.1 100 Continue\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (100 Continue must not consume the pairing)", len(got))
	}
	if got[0].Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200 (the real response, not the 100 Continue)", got[0].Response.StatusCode)
	}
}

// TestHTTPTraceIDExtraction (EXT-3) checks that an end-to-end correlation id is
// surfaced on the top-level Entry from the request headers, with the W3C
// traceparent 32-hex trace-id taking precedence over x-request-id, then
// x-correlation-id, and empty when no correlation header is present.
func TestHTTPTraceIDExtraction(t *testing.T) {
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736" // 32-hex W3C trace-id
	cases := []struct {
		name    string
		headers string // extra request header lines, each already CRLF-terminated
		want    string
	}{
		{
			name:    "traceparent trace-id",
			headers: "traceparent: 00-" + traceID + "-00f067aa0ba902b7-01\r\n",
			want:    traceID,
		},
		{
			name:    "traceparent wins over x-request-id",
			headers: "traceparent: 00-" + traceID + "-00f067aa0ba902b7-01\r\nX-Request-Id: req-abc-123\r\n",
			want:    traceID,
		},
		{
			name:    "x-request-id only",
			headers: "X-Request-Id: req-abc-123\r\n",
			want:    "req-abc-123",
		},
		{
			name:    "x-correlation-id fallback",
			headers: "X-Correlation-Id: corr-xyz-789\r\n",
			want:    "corr-xyz-789",
		},
		{
			name:    "no correlation header",
			headers: "",
			want:    "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSink("", "", "n", discardLogger())
			p := newPipeline(s, "n", "1.2.3.4", discardLogger())
			rNet, rTr, sNet, sTr := flows(40800, 80)

			req := "GET /x HTTP/1.1\r\nHost: h\r\n" + c.headers + "\r\n"
			p.consumeHTTP(rNet, rTr, strings.NewReader(req))
			p.consumeHTTP(sNet, sTr, strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))

			got := drain(s)
			if len(got) != 1 {
				t.Fatalf("got %d entries, want 1", len(got))
			}
			if got[0].TraceID != c.want {
				t.Errorf("TraceID = %q, want %q", got[0].TraceID, c.want)
			}
		})
	}
}

// --- SEC-8: allocation bounds — oversized payloads are discarded, not buffered

// A DataRow bigger than pgMaxPayload (a large resultset column, e.g. bytea)
// must be skipped without killing the stream: framing must stay intact so the
// following CommandComplete still pairs with the query.
func TestPostgresHugeDataRowSkipped(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40401, pgPort)

	req := pgMsg('Q', []byte("SELECT blob FROM t\x00"))

	var resp []byte
	resp = append(resp, pgMsg('D', make([]byte, pgMaxPayload+512))...) // > materialization cap
	resp = append(resp, pgMsg('C', []byte("SELECT 1\x00"))...)

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (huge DataRow must not desync the stream)", len(got))
	}
	if got[0].Response.Summary != "SELECT 1 (1 rows)" || got[0].Response.RowCount != 1 {
		t.Errorf("response = %+v", got[0].Response)
	}
}

// A huge client-side CopyData ('d') message — a COPY upload — must be
// discarded without allocating or desyncing: the query after it still parses.
func TestPostgresHugeCopyDataSkipped(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40402, pgPort)

	var req []byte
	req = append(req, pgMsg('d', make([]byte, pgMaxPayload+512))...)
	req = append(req, pgMsg('Q', []byte("SELECT 1\x00"))...)
	resp := pgMsg('C', []byte("SELECT 1\x00"))

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (huge CopyData must not desync the stream)", len(got))
	}
	if got[0].Request.Query != "SELECT 1" {
		t.Errorf("query = %q, want SELECT 1", got[0].Request.Query)
	}
}

// A bulk string above maxRESPCapture is truncated in memory but fully consumed
// on the wire: the next command on the connection must still parse.
func TestRedisOversizedBulkTruncatedNotDesynced(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40403, redisPort)

	big := strings.Repeat("a", maxRESPCapture+3)
	req := "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$" + strconv.Itoa(len(big)) + "\r\n" + big + "\r\n" +
		"*1\r\n$4\r\nPING\r\n"
	resp := "+OK\r\n+PONG\r\n"

	p.consumeRedis(rNet, rTr, strings.NewReader(req), true, api.ProtocolRedis)
	p.consumeRedis(sNet, sTr, strings.NewReader(resp), false, api.ProtocolRedis)

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (oversized bulk must not desync the stream)", len(got))
	}
	if !strings.HasPrefix(got[0].Request.Command, "SET key") {
		t.Errorf("entry0 command = %q", truncate(got[0].Request.Command, 80))
	}
	if got[1].Request.Command != "PING" || got[1].Response.Summary != "PONG" {
		t.Errorf("entry1 = %q / %q", got[1].Request.Command, got[1].Response.Summary)
	}
}

// A body frame above amqpMaxCapture keeps exact size accounting (the entry is
// emitted, with the true body size) and the next frame still parses.
func TestAMQPOversizedBodyFrame(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40404, amqpPort)

	bodySize := amqpMaxCapture + 5

	var args []byte
	args = appendU16(args, 0)
	args = append(args, amqpShortStrBytes("orders")...)
	args = append(args, amqpShortStrBytes("new")...)
	args = append(args, 0x00)
	publish := amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassBasic, 40, args))

	var hdr []byte
	hdr = appendU16(hdr, amqpClassBasic)
	hdr = appendU16(hdr, 0)
	hdr = append(hdr, 0, 0, 0, 0, byte(bodySize>>24), byte(bodySize>>16), byte(bodySize>>8), byte(bodySize))
	hdr = appendU16(hdr, 0)
	header := amqpFrame(amqpFrameHeader, 1, hdr)
	body := amqpFrame(amqpFrameBody, 1, make([]byte, bodySize))

	var declArgs []byte
	declArgs = appendU16(declArgs, 0)
	declArgs = append(declArgs, amqpShortStrBytes("after")...)
	declare := amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassQueue, 10, declArgs))

	stream := amqpHeader + string(publish) + string(header) + string(body) + string(declare)
	p.consumeStream(rNet, rTr, strings.NewReader(stream))

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (truncated body frame must still complete + not desync)", len(got))
	}
	if got[0].Request.Size != bodySize {
		t.Errorf("body size = %d, want %d (true on-wire size despite truncated capture)", got[0].Request.Size, bodySize)
	}
	if got[1].Request.Queue != "after" {
		t.Errorf("entry1 queue = %q, want after (framing after oversized frame)", got[1].Request.Queue)
	}
}

// --- WebSocket (DIS-6) ------------------------------------------------------

const (
	wsUpgradeReq = "GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	wsUpgradeResp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
)

// wsFrame builds a single RFC 6455 frame (FIN set). When maskKey is non-nil the
// payload is masked with it (client -> server frames MUST be masked; server ->
// client MUST NOT). It uses the 7-bit length form, which is all these tests
// need (payloads < 126 bytes).
func wsFrame(opcode byte, payload, maskKey []byte) []byte {
	if len(payload) >= 126 {
		panic("wsFrame helper only supports <126-byte payloads")
	}
	out := []byte{0x80 | opcode} // FIN + opcode
	b1 := byte(len(payload))
	body := append([]byte(nil), payload...)
	if maskKey != nil {
		b1 |= 0x80
		for i := range body {
			body[i] ^= maskKey[i%4]
		}
	}
	out = append(out, b1)
	if maskKey != nil {
		out = append(out, maskKey...)
	}
	return append(out, body...)
}

// wsEntriesBySide splits ws entries into the client->server and server->client
// directions by source port (client on clientPort, server on serverPort).
func wsEntriesBySide(entries []*api.Entry, clientPort int) (client, server []*api.Entry) {
	for _, e := range entries {
		if e.Protocol != api.ProtocolWS {
			continue
		}
		if e.Source.Port == clientPort {
			client = append(client, e)
		} else {
			server = append(server, e)
		}
	}
	return
}

// A real GET+Upgrade -> 101 handshake followed by a masked client text frame
// and an unmasked server text frame must yield the HTTP handshake entry plus
// two standalone ws entries (one per direction) with correctly unmasked
// previews — instead of the response loop misparsing frames as HTTP and
// abandoning the whole connection (the DIS-6 bug).
func TestWebSocketUpgradeAndTextFrames(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	const clientPort = 40500
	rNet, rTr, sNet, sTr := flows(clientPort, 80)

	clientFrame := wsFrame(wsOpcodeText, []byte("ping from client"), []byte{0x37, 0xfa, 0x21, 0x3d})
	serverFrame := wsFrame(wsOpcodeText, []byte("pong from server"), nil)

	p.consumeHTTP(rNet, rTr, strings.NewReader(wsUpgradeReq+string(clientFrame)))
	p.consumeHTTP(sNet, sTr, strings.NewReader(wsUpgradeResp+string(serverFrame)))

	got := drain(s)

	var httpN int
	for _, e := range got {
		if e.Protocol == api.ProtocolHTTP {
			httpN++
			if e.StatusCode != 101 {
				t.Errorf("http handshake statusCode = %d, want 101", e.StatusCode)
			}
		}
	}
	if httpN != 1 {
		t.Fatalf("got %d http entries, want 1 (the 101 handshake)", httpN)
	}

	client, server := wsEntriesBySide(got, clientPort)
	if len(client) != 1 || len(server) != 1 {
		t.Fatalf("got %d client + %d server ws frames, want 1 + 1 (entries: %+v)", len(client), len(server), got)
	}
	if client[0].Request.WSOpcode != "text" || !strings.Contains(client[0].Request.Body, "ping from client") {
		t.Errorf("client frame = opcode %q body %q, want text 'ping from client' (unmasked)",
			client[0].Request.WSOpcode, client[0].Request.Body)
	}
	if server[0].Request.WSOpcode != "text" || !strings.Contains(server[0].Request.Body, "pong from server") {
		t.Errorf("server frame = opcode %q body %q, want text 'pong from server'",
			server[0].Request.WSOpcode, server[0].Request.Body)
	}
}

// A close frame must be surfaced as a ws entry noting its RFC 6455 close code.
func TestWebSocketCloseFrame(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	const clientPort = 40600
	rNet, rTr, sNet, sTr := flows(clientPort, 80)

	closePayload := append([]byte{0x03, 0xe8}, []byte("bye")...) // code 1000 + reason
	serverClose := wsFrame(wsOpcodeClose, closePayload, nil)

	p.consumeHTTP(rNet, rTr, strings.NewReader(wsUpgradeReq)) // client sends no frames
	p.consumeHTTP(sNet, sTr, strings.NewReader(wsUpgradeResp+string(serverClose)))

	got := drain(s)
	_, server := wsEntriesBySide(got, clientPort)
	if len(server) != 1 {
		t.Fatalf("got %d server ws frames, want 1 (the close) (entries: %+v)", len(server), got)
	}
	if server[0].Request.WSOpcode != "close" {
		t.Errorf("opcode = %q, want close", server[0].Request.WSOpcode)
	}
	if !strings.Contains(server[0].Request.Summary, "1000") {
		t.Errorf("summary = %q, want it to note close code 1000", server[0].Request.Summary)
	}
	if !strings.Contains(server[0].Request.Summary, "bye") {
		t.Errorf("summary = %q, want it to include the close reason", server[0].Request.Summary)
	}
}

// Truncated and garbled frames must never panic and must never desync into a
// runaway allocation: the parser stops the direction cleanly, and the HTTP
// handshake entry is still emitted in every case.
func TestWebSocketGarbledFrameNoPanic(t *testing.T) {
	cases := map[string][]byte{
		"lone header byte":        {0x88},
		"truncated 16-bit length": {0x81, 0x7e, 0x00},                                           // len=126, only 1 of 2 ext bytes
		"truncated 64-bit length": {0x82, 0x7f, 0xff, 0xff},                                     // len=127, partial ext
		"absurd 64-bit length":    {0x82, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // > wsMaxPayload
		"masked but no key":       {0x81, 0x85, 0x01},                                           // masked text len=5, key cut off
		"len exceeds payload":     {0x81, 0x0a, 'h', 'i'},                                       // claims 10, only 2 present
	}
	for name, garbled := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSink("", "", "n", discardLogger())
			p := newPipeline(s, "n", "1.2.3.4", discardLogger())
			rNet, rTr, sNet, sTr := flows(40700, 80)

			p.consumeHTTP(rNet, rTr, strings.NewReader(wsUpgradeReq))
			p.consumeHTTP(sNet, sTr, strings.NewReader(wsUpgradeResp+string(garbled))) // must not panic

			var httpN int
			for _, e := range drain(s) {
				if e.Protocol == api.ProtocolHTTP {
					httpN++
				}
			}
			if httpN != 1 {
				t.Errorf("got %d http handshake entries, want 1 (a garbled frame must not lose the handshake)", httpN)
			}
		})
	}
}

// --- TCP segment-loss resilience (DIS-10) -----------------------------------

// lossChunk is one segment served by lossyReader: data bytes, or (with empty
// data) a single terminal error to return once.
type lossChunk struct {
	data []byte
	err  error
}

// lossyReader mimics a tcpreader.ReaderStream with LossErrors enabled: it serves
// its chunks' bytes in order, returns each chunk's error once (tcpreader reports
// DataLost as (0, DataLost), i.e. an empty-data chunk carrying DataLost), and
// finally io.EOF. It lets the DIS-10 tests inject a lost segment without having
// to drive a real tcpassembly.Assembler with Skip!=0 reassemblies.
type lossyReader struct {
	chunks []lossChunk
}

func (r *lossyReader) Read(p []byte) (int, error) {
	for len(r.chunks) > 0 {
		c := &r.chunks[0]
		if len(c.data) > 0 {
			n := copy(p, c.data)
			c.data = c.data[n:]
			if len(c.data) == 0 && c.err == nil {
				r.chunks = r.chunks[1:]
			}
			return n, nil
		}
		err := c.err
		r.chunks = r.chunks[1:]
		if err != nil {
			return 0, err
		}
	}
	return 0, io.EOF
}

func (r *lossyReader) chunkExhausted() bool { return len(r.chunks) == 0 }

// A lossReader must fire onLoss exactly once on a DataLost, drain everything
// past the gap (so tcpassembly is never left blocked on an unread stream), and
// then report io.EOF — never surfacing the post-gap bytes to the dissector.
func TestLossReaderTruncatesDrainsAndCounts(t *testing.T) {
	var losses int
	inner := &lossyReader{chunks: []lossChunk{
		{data: []byte("before")},
		{err: tcpreader.DataLost},
		{data: []byte("after-the-gap")}, // must be drained, never delivered
	}}
	lr := &lossReader{r: inner, onLoss: func() { losses++ }}

	got, err := io.ReadAll(lr) // io.ReadAll stops at the io.EOF lossReader returns
	if err != nil {
		t.Fatalf("ReadAll err = %v, want nil (EOF is normal termination)", err)
	}
	if string(got) != "before" {
		t.Errorf("delivered %q, want only the pre-gap %q (post-gap bytes must be dropped)", got, "before")
	}
	if losses != 1 {
		t.Errorf("onLoss fired %d times, want exactly 1", losses)
	}
	if !inner.chunkExhausted() {
		t.Error("underlying stream was not drained to EOF — tcpassembly could block")
	}
}

// End to end: a lost segment in the response direction must purge the
// connection's pending requests and truncate the direction, so a valid pre-gap
// reply still pairs but no post-gap reply is emitted against the wrong request —
// and the loss is counted for /api/workers + /metrics.
func TestTCPLossPurgesPendingAndCounts(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40000, redisPort)

	// Two requests, both fully sent before any loss (request direction is clean).
	req := "*2\r\n$3\r\nGET\r\n$1\r\na\r\n" + "*2\r\n$3\r\nGET\r\n$1\r\nb\r\n"
	p.consumeStream(rNet, rTr, strings.NewReader(req))

	key := connKey(rNet, rTr)
	if got := pendingCount(p, key); got != 2 {
		t.Fatalf("pending requests = %d, want 2 before the response direction runs", got)
	}

	// Response direction: the reply to GET a, then a lost segment, then a stray
	// reply that (post-gap) can no longer be trusted to belong to GET b.
	resp := &lossyReader{chunks: []lossChunk{
		{data: []byte("$1\r\nX\r\n")},
		{err: tcpreader.DataLost},
		{data: []byte("$1\r\nY\r\n")},
	}}
	p.consumeStream(sNet, sTr, resp)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (only the pre-gap GET a/X pair; the gap must drop the rest)", len(got))
	}
	if got[0].Request.Command != "GET a" || got[0].Response.Summary != "X" {
		t.Errorf("entry = %q -> %q, want GET a -> X", got[0].Request.Command, got[0].Response.Summary)
	}
	if n := pendingCount(p, key); n != 0 {
		t.Errorf("pending requests = %d after loss, want 0 (GET b must be purged, not mispaired)", n)
	}
	if got := s.tcpLossEvents.Load(); got != 1 {
		t.Errorf("tcpLossEvents = %d, want 1", got)
	}
}

// pendingCount reports how many requests are still awaiting a response on key.
func pendingCount(p *pipeline, key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cs := p.conns[key]; cs != nil {
		return len(cs.reqs)
	}
	return 0
}

// --- DIS-11: MySQL ----------------------------------------------------------

// appendU32LE / appendU64LE append little-endian integers (MySQL and BSON are
// both little-endian, unlike the big-endian appendU16/appendU32 above).
func appendU32LE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
func appendU64LE(b []byte, v uint64) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

// mysqlPacket frames a payload with the 3-byte little-endian length + 1-byte
// sequence id MySQL header.
func mysqlPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

func comQueryPacket(sql string) []byte {
	return mysqlPacket(0, append([]byte{comQuery}, sql...))
}

// A full MySQL flow — server greeting + auth OK skipped, then COM_QUERY paired
// with a result set, an OK (affected rows), and an ERR — pairs correctly and
// surfaces the SQL text, row count and error.
func TestMySQLPairingEndToEnd(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40400, mysqlPort)

	// Request direction: a (skipped) handshake response at seq 1, then three
	// command-phase COM_QUERY packets at seq 0.
	var req []byte
	req = append(req, mysqlPacket(1, make([]byte, 40))...) // HandshakeResponse (skipped)
	req = append(req, comQueryPacket("SELECT id FROM t")...)
	req = append(req, comQueryPacket("UPDATE t SET x=1")...)
	req = append(req, comQueryPacket("SELECT * FROM nope")...)

	// Response direction: greeting + auth OK (both skipped), then the three
	// command responses in order.
	var resp []byte
	resp = append(resp, mysqlPacket(0, append([]byte{0x0a}, "8.0.32\x00rest"...))...)        // greeting
	resp = append(resp, mysqlPacket(2, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})...) // auth OK
	// Result set for SELECT id FROM t: 1 column, 2 rows (DEPRECATE_EOF dialect).
	resp = append(resp, mysqlPacket(1, []byte{0x01})...)                                     // column count = 1
	resp = append(resp, mysqlPacket(2, []byte{0x03, 'i', 'd', 'x'})...)                      // column definition
	resp = append(resp, mysqlPacket(3, []byte{0x02, '4', '2'})...)                           // row 1
	resp = append(resp, mysqlPacket(4, []byte{0x02, '4', '3'})...)                           // row 2
	resp = append(resp, mysqlPacket(5, []byte{0xfe, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})...) // OK terminator (7 bytes)
	// OK for the UPDATE: affected rows = 3.
	resp = append(resp, mysqlPacket(1, []byte{0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00})...)
	// ERR for SELECT * FROM nope: code 1146, SQL state 42S02.
	errPayload := append([]byte{0xff, 0x7a, 0x04, '#'}, "42S02Table 'shop.nope' doesn't exist"...)
	resp = append(resp, mysqlPacket(1, errPayload)...)

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))
	p.consumeStream(sNet, sTr, strings.NewReader(string(resp)))

	got := drain(s)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	if got[0].Protocol != api.ProtocolMySQL || got[0].Request.Query != "SELECT id FROM t" {
		t.Errorf("entry0 request = %+v", got[0].Request)
	}
	if got[0].Response.RowCount != 2 || got[0].Response.Summary != "2 rows" {
		t.Errorf("entry0 response = %+v, want 2 rows", got[0].Response)
	}
	if got[1].Request.Query != "UPDATE t SET x=1" || got[1].Response.RowCount != 3 {
		t.Errorf("entry1 = req %q resp %+v", got[1].Request.Query, got[1].Response)
	}
	if got[2].Status != "error" {
		t.Errorf("entry2 status = %q, want error", got[2].Status)
	}
	if got[2].Response.MySQL == nil || got[2].Response.MySQL.ErrorCode != 1146 {
		t.Fatalf("entry2 error detail = %+v", got[2].Response.MySQL)
	}
	if !strings.Contains(got[2].Response.MySQL.ErrorMessage, "doesn't exist") {
		t.Errorf("entry2 error message = %q", got[2].Response.MySQL.ErrorMessage)
	}
}

// A CLIENT_SSL request (short handshake packet with the SSL capability bit) is
// detected and the direction stopped cleanly rather than framing the following
// TLS ciphertext as MySQL packets.
func TestMySQLSSLUpgradeStopsCleanly(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, _, _ := flows(40404, mysqlPort)

	var req []byte
	// SSL request: seq 1, capability flags with CLIENT_SSL (0x0800) set, short.
	sslCaps := appendU32LE(nil, clientSSLCapability)
	sslReq := append(sslCaps, make([]byte, 28)...) // 32-byte SSL request, no username
	req = append(req, mysqlPacket(1, sslReq)...)
	// TLS ClientHello ciphertext follows — must NOT be emitted as anything.
	req = append(req, 0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28)

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))

	if got := drain(s); len(got) != 0 {
		t.Fatalf("got %d entries, want 0 after a TLS upgrade", len(got))
	}
}

// Truncated / garbled MySQL streams must not panic and must emit nothing.
func TestMySQLTruncatedNoPanic(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40405, mysqlPort)

	for _, stream := range [][]byte{
		{0x01},                              // can't even read the header
		{0x10, 0x00, 0x00, 0x00, 0x03, 'S'}, // header claims 16 bytes, only 2 present
		{0xff, 0xff, 0xff, 0x00, 0x03, 'x'}, // 16 MiB claim, truncated
	} {
		p.consumeStream(rNet, rTr, bytes.NewReader(stream)) // request side
		p.consumeStream(sNet, sTr, bytes.NewReader(stream)) // response side
	}
	if got := drain(s); len(got) != 0 {
		t.Errorf("got %d entries from garbled MySQL, want 0", len(got))
	}
}

// --- DIS-11: MongoDB --------------------------------------------------------

// bsonStrElem / bsonDblElem build single BSON string / double elements; bsonDoc
// wraps elements into a length-prefixed, NUL-terminated document.
func bsonStrElem(key, val string) []byte {
	e := append([]byte{0x02}, key...)
	e = append(e, 0x00)
	e = appendU32LE(e, uint32(len(val)+1))
	e = append(e, val...)
	return append(e, 0x00)
}
func bsonDblElem(key string, v float64) []byte {
	e := append([]byte{0x01}, key...)
	e = append(e, 0x00)
	return appendU64LE(e, math.Float64bits(v))
}
func bsonDoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	total := 4 + len(body) + 1
	out := appendU32LE(nil, uint32(total))
	out = append(out, body...)
	return append(out, 0x00)
}

// mongoMsg frames a MsgHeader + body; opMsgMsg builds an OP_MSG carrying a
// single section-0 command document.
func mongoMsg(requestID, responseTo, opCode int32, body []byte) []byte {
	total := 16 + len(body)
	out := appendU32LE(nil, uint32(total))
	out = appendU32LE(out, uint32(requestID))
	out = appendU32LE(out, uint32(responseTo))
	out = appendU32LE(out, uint32(opCode))
	return append(out, body...)
}
func opMsgMsg(requestID, responseTo int32, doc []byte) []byte {
	body := appendU32LE(nil, 0) // flagBits
	body = append(body, 0x00)   // section kind 0 (body)
	body = append(body, doc...)
	return mongoMsg(requestID, responseTo, opMsg, body)
}

// OP_MSG find + insert requests pair by requestID/responseTo with an ok:1 reply
// and an ok:0 + errmsg reply, surfacing collection/command and the error.
func TestMongoOpMsgPairing(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40500, mongoPort)

	req := opMsgMsg(100, 0, bsonDoc(bsonStrElem("find", "users"), bsonStrElem("$db", "shop")))
	req = append(req, opMsgMsg(101, 0, bsonDoc(bsonStrElem("insert", "carts"), bsonStrElem("$db", "shop")))...)

	resp := opMsgMsg(200, 100, bsonDoc(bsonDblElem("ok", 1.0)))
	resp = append(resp, opMsgMsg(201, 101, bsonDoc(bsonDblElem("ok", 0.0), bsonStrElem("errmsg", "not authorized on shop")))...)

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))
	p.consumeStream(sNet, sTr, strings.NewReader(string(resp)))

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	byColl := map[string]*api.Entry{}
	for _, e := range got {
		if e.Protocol != api.ProtocolMongo {
			t.Errorf("protocol = %q, want mongodb", e.Protocol)
		}
		if e.Request.Mongo == nil {
			t.Fatalf("entry has no request Mongo detail: %+v", e.Request)
		}
		byColl[e.Request.Mongo.Collection] = e
	}
	find := byColl["users"]
	if find == nil || find.Request.Mongo.Command != "find" || find.Status != "success" {
		t.Errorf("find entry = %+v", find)
	}
	ins := byColl["carts"]
	if ins == nil || ins.Request.Mongo.Command != "insert" || ins.Status != "error" {
		t.Fatalf("insert entry = %+v", ins)
	}
	if ins.Response.Mongo == nil || ins.Response.Mongo.ErrMsg != "not authorized on shop" {
		t.Errorf("insert error = %+v", ins.Response.Mongo)
	}
}

// Truncated / garbled MongoDB streams (short header, absurd message length,
// truncated BSON) must not panic and must emit nothing.
func TestMongoTruncatedNoPanic(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40501, mongoPort)

	// A BSON doc whose string value claims far more bytes than are present.
	badDoc := appendU32LE(nil, 40)
	badDoc = append(badDoc, 0x02)
	badDoc = append(badDoc, "find\x00"...)
	badDoc = appendU32LE(badDoc, 99) // string claims 99 bytes
	badDoc = append(badDoc, "us"...) // only 2 present
	badDoc = append(badDoc, 0x00)

	streams := [][]byte{
		{0x05, 0x00},                            // can't read the 16-byte header
		mongoMsg(1<<20, 0, opMsg, []byte{0x00}), // absurd message length
		mongoMsg(16, 0, opMsg, nil),             // header only, empty body
		opMsgMsg(7, 0, badDoc),                  // truncated BSON string
	}
	for _, stream := range streams {
		p.consumeStream(rNet, rTr, bytes.NewReader(stream)) // request side
		p.consumeStream(sNet, sTr, bytes.NewReader(stream)) // response side
	}
	if got := drain(s); len(got) != 0 {
		t.Errorf("got %d entries from garbled MongoDB, want 0", len(got))
	}
}

// --- DIS-8: Kafka -----------------------------------------------------------

// kafkaFrame prepends the 4-byte big-endian size prefix Kafka frames every
// request/response with. kafkaString appends a Kafka STRING (INT16 length +
// bytes). Kafka is big-endian, so appendU16/appendU32 (not the *LE helpers).
func kafkaFrame(payload []byte) []byte {
	return append(appendU32(nil, uint32(len(payload))), payload...)
}
func kafkaString(b []byte, s string) []byte {
	b = appendU16(b, uint16(len(s)))
	return append(b, s...)
}

// kafkaReqHeaderBytes builds a request header: api_key, api_version,
// correlation_id, client_id (nullable string, always present here).
func kafkaReqHeaderBytes(apiKey, apiVersion int16, corrID int32, clientID string) []byte {
	b := appendU16(nil, uint16(apiKey))
	b = appendU16(b, uint16(apiVersion))
	b = appendU32(b, uint32(corrID))
	return kafkaString(b, clientID)
}

// kafkaProduceReqBody builds a non-flexible (v3-v8) Produce request body up to
// the first topic name (the dissector reads no further).
func kafkaProduceReqBody(topic string) []byte {
	b := appendU16(nil, 0xffff)  // transactional_id = null (v3+)
	b = appendU16(b, 1)          // acks
	b = appendU32(b, 30000)      // timeout_ms
	b = appendU32(b, 1)          // topics count
	return kafkaString(b, topic) // first topic name
}

// kafkaProduceRespPayload builds a non-flexible Produce response payload
// (response header v0 = just correlation_id, then the body up to the first
// partition's error_code).
func kafkaProduceRespPayload(corrID int32, topic string, errCode int16) []byte {
	b := appendU32(nil, uint32(corrID)) // response header: correlation_id
	b = appendU32(b, 1)                 // responses count
	b = kafkaString(b, topic)           // topic name
	b = appendU32(b, 1)                 // partition_responses count
	b = appendU32(b, 0)                 // partition index
	return appendU16(b, uint16(errCode))
}

// A Produce request pairs with its response by correlation_id, surfacing the
// api_key name, version, topic and client id.
func TestKafkaProducePairing(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40600, kafkaPort)

	req := kafkaFrame(append(kafkaReqHeaderBytes(0, 7, 42, "producer-1"), kafkaProduceReqBody("orders")...))
	resp := kafkaFrame(kafkaProduceRespPayload(42, "orders", 0))

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))
	p.consumeStream(sNet, sTr, strings.NewReader(string(resp)))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Protocol != api.ProtocolKafka {
		t.Fatalf("protocol = %q, want kafka", e.Protocol)
	}
	k := e.Request.Kafka
	if k == nil {
		t.Fatalf("no request Kafka detail: %+v", e.Request)
	}
	if k.APIKey != "Produce" || k.APIVersion != 7 || k.Topic != "orders" {
		t.Errorf("request kafka = %+v, want Produce/v7/orders", k)
	}
	if k.CorrelationID != 42 {
		t.Errorf("correlation id = %d, want 42", k.CorrelationID)
	}
	if k.ClientID != "producer-1" {
		t.Errorf("client id = %q, want producer-1", k.ClientID)
	}
	if e.Request.Summary != "PRODUCE topic=orders (v7)" {
		t.Errorf("summary = %q", e.Request.Summary)
	}
	if e.Status != "success" {
		t.Errorf("status = %q, want success", e.Status)
	}
}

// Two requests on one connection whose responses arrive in the opposite order
// still pair correctly, because pairing is by correlation_id (not FIFO). The
// swapped Produce response also carries an error_code, exercising the response
// error path.
func TestKafkaOutOfOrderCorrelation(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40601, kafkaPort)

	// Metadata(corr=1, topic=events) then Produce(corr=2, topic=orders).
	metaBody := kafkaString(appendU32(nil, 1), "events") // topics count=1 + name
	var req []byte
	req = append(req, kafkaFrame(append(kafkaReqHeaderBytes(3, 8, 1, "c"), metaBody...))...)
	req = append(req, kafkaFrame(append(kafkaReqHeaderBytes(0, 7, 2, "c"), kafkaProduceReqBody("orders")...))...)

	// Responses swapped: Produce (corr=2, error 3) first, then Metadata (corr=1).
	metaResp := appendU32(appendU32(nil, 1), 0) // correlation_id=1 + a body we don't parse
	var resp []byte
	resp = append(resp, kafkaFrame(kafkaProduceRespPayload(2, "orders", 3))...)
	resp = append(resp, kafkaFrame(metaResp)...)

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))
	p.consumeStream(sNet, sTr, strings.NewReader(string(resp)))

	got := drain(s)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	byTopic := map[string]*api.Entry{}
	for _, e := range got {
		if e.Request.Kafka == nil {
			t.Fatalf("entry has no request Kafka detail: %+v", e.Request)
		}
		byTopic[e.Request.Kafka.Topic] = e
	}
	meta := byTopic["events"]
	if meta == nil || meta.Request.Kafka.APIKey != "Metadata" || meta.Request.Kafka.CorrelationID != 1 {
		t.Fatalf("metadata entry = %+v", meta)
	}
	prod := byTopic["orders"]
	if prod == nil || prod.Request.Kafka.APIKey != "Produce" || prod.Request.Kafka.CorrelationID != 2 {
		t.Fatalf("produce entry = %+v", prod)
	}
	if prod.Status != "error" || prod.Response.Kafka == nil || prod.Response.Kafka.ErrorCode != 3 {
		t.Errorf("produce error = status %q resp %+v", prod.Status, prod.Response.Kafka)
	}
}

// Truncated / garbled Kafka streams (short size prefix, negative/oversized size,
// truncated body) must not panic and must emit nothing.
func TestKafkaTruncatedNoPanic(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40602, kafkaPort)

	streams := [][]byte{
		{0x00, 0x00},                                                // can't read the 4-byte size
		{0x00, 0x00, 0x00, 0x10, 0x00, 0x03},                        // size claims 16, only 2 present
		{0xff, 0xff, 0xff, 0xff, 0x00},                              // negative size
		{0x00, 0x00, 0x00, 0x02, 0x00},                              // size=2, only 1 byte present
		kafkaFrame([]byte{0x00, 0x00, 0x00}),                        // valid frame, payload too short for a header
		kafkaFrame(append(kafkaReqHeaderBytes(0, 7, 5, "c"), 0xff)), // header ok, body truncated
	}
	for _, stream := range streams {
		p.consumeStream(rNet, rTr, bytes.NewReader(stream)) // request side
		p.consumeStream(sNet, sTr, bytes.NewReader(stream)) // response side
	}
	if got := drain(s); len(got) != 0 {
		t.Errorf("got %d entries from garbled Kafka, want 0", len(got))
	}
}

// A flexible-version request (Produce v9) is still paired and surfaces its
// api_key/version/client_id, but its compact-encoded body is NOT deep-parsed for
// a topic — and neither side panics.
func TestKafkaFlexibleVersionSurfaced(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40603, kafkaPort)

	// Header fields stay fixed-position (incl. the non-compact client_id); the
	// trailing bytes stand in for tagged fields + compact body.
	req := kafkaFrame(append(kafkaReqHeaderBytes(0, 9, 7, "producer"), 0x00, 0x0a, 0x03, 0x01))
	// Flexible response header: correlation_id + tagged fields + compact body,
	// none of which we touch beyond the correlation_id.
	resp := kafkaFrame(append(appendU32(nil, 7), 0x00, 0x00, 0x01))

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))
	p.consumeStream(sNet, sTr, strings.NewReader(string(resp)))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	k := got[0].Request.Kafka
	if k == nil || k.APIKey != "Produce" || k.APIVersion != 9 {
		t.Fatalf("request kafka = %+v, want Produce/v9", k)
	}
	if k.Topic != "" {
		t.Errorf("topic = %q, want empty (flexible version must not be deep-parsed)", k.Topic)
	}
	if k.ClientID != "producer" {
		t.Errorf("client id = %q, want producer", k.ClientID)
	}
	if got[0].Status != "success" {
		t.Errorf("status = %q, want success", got[0].Status)
	}
}

// --- retention caps: queryCap / redisMaxArgs (caps.go) ----------------------

// A machine-generated statement far past queryCap must be retained as a
// bounded prefix and flagged Truncated — the hub keeps every entry alive for
// the whole ring buffer, so an unbounded Query is unbounded resident memory.
func TestPostgresQueryCappedAtQueryCap(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40700, pgPort)

	sql := "SELECT * FROM t WHERE id IN (" + strings.Repeat("1,", 40000) + "1)"
	if len(sql) <= queryCap {
		t.Fatalf("test statement is only %d bytes, must exceed queryCap (%d)", len(sql), queryCap)
	}
	req := append(pgStartup(), pgMsg('Q', append([]byte(sql), 0))...)
	resp := pgMsg('C', []byte("SELECT 1\x00"))

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	q := got[0].Request.Query
	if len(q) > queryCap+len("…") {
		t.Errorf("retained query is %d bytes, want <= queryCap (%d)", len(q), queryCap)
	}
	if !strings.HasPrefix(q, "SELECT * FROM t WHERE id IN (1,1,") {
		t.Errorf("query prefix = %.40q, want the head of the statement", q)
	}
	if !strings.HasSuffix(q, "…") {
		t.Errorf("cut query %.20q… must end with the ellipsis marker", q)
	}
	if !got[0].Request.Truncated {
		t.Error("Request.Truncated = false, want true for a query cut at queryCap")
	}
	if len(got[0].Request.Summary) > 160+len("…") {
		t.Errorf("summary is %d bytes, want <= 160", len(got[0].Request.Summary))
	}

	// A statement under the cap is kept verbatim and NOT flagged.
	if pl := pgQueryPayload("SELECT 1", nil); pl.Query != "SELECT 1" || pl.Truncated {
		t.Errorf("short query payload = %+v, want untouched and unflagged", pl)
	}
}

// Same contract on the MySQL side (COM_QUERY payloads are materialized up to
// mysqlMaxPayload before the cap applies).
func TestMySQLQueryCappedAtQueryCap(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40701, mysqlPort)

	sql := "INSERT INTO t VALUES " + strings.Repeat("(1),", 20000) + "(1)"
	if len(sql) <= queryCap {
		t.Fatalf("test statement is only %d bytes, must exceed queryCap (%d)", len(sql), queryCap)
	}
	req := comQueryPacket(sql)
	// OK reply at seq 1 (no greeting: capture started mid-connection).
	resp := mysqlPacket(1, []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00})

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))
	p.consumeStream(sNet, sTr, strings.NewReader(string(resp)))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	q := got[0].Request.Query
	if len(q) > queryCap+len("…") {
		t.Errorf("retained query is %d bytes, want <= queryCap (%d)", len(q), queryCap)
	}
	if !strings.HasPrefix(q, "INSERT INTO t VALUES (1),") || !strings.HasSuffix(q, "…") {
		t.Errorf("query = %.40q…, want the cut head of the statement", q)
	}
	if !got[0].Request.Truncated {
		t.Error("Request.Truncated = false, want true for a query cut at queryCap")
	}
	if pl := mysqlQueryPayload([]byte("SELECT 1"), "COM_QUERY", nil); pl.Query != "SELECT 1" || pl.Truncated {
		t.Errorf("short query payload = %+v, want untouched and unflagged", pl)
	}
}

// A pipelined MSET with far more arguments than redisMaxArgs keeps a bounded
// argument list plus a synthetic "… (N more)" tail, so the drop is visible.
// Element VALUES are already bounded (redisMaxValueDisplay); this is the
// element COUNT bound.
func TestRedisArgsCappedAtRedisMaxArgs(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40702, redisPort)

	const pairs = 200
	nargs := 1 + 2*pairs
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(nargs) + "\r\n$4\r\nMSET\r\n")
	for i := 0; i < pairs; i++ {
		k, v := "k"+strconv.Itoa(i), "v"+strconv.Itoa(i)
		b.WriteString("$" + strconv.Itoa(len(k)) + "\r\n" + k + "\r\n")
		b.WriteString("$" + strconv.Itoa(len(v)) + "\r\n" + v + "\r\n")
	}

	p.consumeRedis(rNet, rTr, strings.NewReader(b.String()), true, api.ProtocolRedis)
	p.consumeRedis(sNet, sTr, strings.NewReader("+OK\r\n"), false, api.ProtocolRedis)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	rd := got[0].Request.Redis
	if rd == nil {
		t.Fatalf("no Redis detail: %+v", got[0].Request)
	}
	if len(rd.Args) != redisMaxArgs+1 {
		t.Fatalf("kept %d args, want redisMaxArgs+1 (%d)", len(rd.Args), redisMaxArgs+1)
	}
	if rd.Args[0] != "MSET" || rd.Args[1] != "k0" {
		t.Errorf("args head = %v, want the start of the command", rd.Args[:2])
	}
	if want := "… (" + strconv.Itoa(nargs-redisMaxArgs) + " more)"; rd.Args[redisMaxArgs] != want {
		t.Errorf("tail element = %q, want %q", rd.Args[redisMaxArgs], want)
	}
	if !got[0].Request.Truncated {
		t.Error("Request.Truncated = false, want true when arguments were dropped")
	}
	if !strings.HasPrefix(got[0].Request.Command, "MSET k0 v0 ") || strings.Contains(got[0].Request.Command, "k199") {
		t.Errorf("command = %.40q, want the capped argument list", got[0].Request.Command)
	}

	// A command within the cap keeps every argument and stays unflagged.
	small, err := parseRESP(bufio.NewReader(strings.NewReader("*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\nb\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if args, cut := redisArgs(small); cut || len(args) != 3 {
		t.Errorf("redisArgs(SET a b) = %v, cut=%v, want 3 args uncut", args, cut)
	}
}

// A command document larger than mongoScanBytes is materialized only as a
// prefix; the message must still be identified by its first key (the command
// name) instead of being dropped wholesale.
func TestMongoOversizedCommandDocKeepsCommand(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40703, mongoPort)

	// find + a filter value that pushes the document past mongoScanBytes, with
	// $db deliberately last (as the drivers emit it) so it falls off the cut.
	huge := strings.Repeat("x", mongoScanBytes+4096)
	doc := bsonDoc(bsonStrElem("find", "users"), bsonStrElem("filter", huge), bsonStrElem("$db", "shop"))
	req := opMsgMsg(300, 0, doc)
	resp := opMsgMsg(301, 300, bsonDoc(bsonDblElem("ok", 1.0)))

	p.consumeStream(rNet, rTr, strings.NewReader(string(req)))
	p.consumeStream(sNet, sTr, strings.NewReader(string(resp)))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	m := got[0].Request.Mongo
	if m == nil || m.Command != "find" || m.Collection != "users" {
		t.Fatalf("request mongo = %+v, want find/users from the truncated prefix", m)
	}
}
