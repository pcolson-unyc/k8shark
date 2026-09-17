package worker

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pablocolson/k8shark/internal/worker/ebpf"
	"github.com/pablocolson/k8shark/pkg/api"
)

// fakeTLSSource is a canned ebpf.Source: the test pushes TLSRecords directly
// on ch instead of a real eBPF ring buffer.
type fakeTLSSource struct {
	ch     chan ebpf.TLSRecord
	closed chan struct{}
}

func newFakeTLSSource() *fakeTLSSource {
	return &fakeTLSSource{ch: make(chan ebpf.TLSRecord, 8), closed: make(chan struct{})}
}

func TestTLSBudgetAdmissionAndCleanup(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "", discardLogger())
	src := newFakeTLSSource()
	b := newTLSByteBudget(32)
	src.ch <- ebpf.TLSRecord{ConnID: 1, Direction: ebpf.TLSDirWrite, Data: []byte("G")}
	src.ch <- ebpf.TLSRecord{ConnID: 2, Direction: ebpf.TLSDirWrite, Data: []byte("G")}
	close(src.ch)
	p.consumeTLSBounded(context.Background(), src, 1, b)
	if s.tlsBudgetDrops.Load() != 1 {
		t.Fatal("stream admission drop not counted")
	}
	deadline := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		used := b.used
		b.mu.Unlock()
		if used == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("parser exit retained %d bytes", used)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTLSBudgetDiscardRejectsFurtherData(t *testing.T) {
	b := newTLSByteBudget(20)
	c := newChanPipe(2, b)
	c.push([]byte("abcdef"))
	if _, err := c.Read(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	c.push([]byte("queued"))
	c.discard()
	c.discard()
	c.push([]byte("late"))
	if b.used != 0 || len(c.ch) != 0 || c.buf != nil {
		t.Fatal("discard retained payload or admitted new data")
	}
}

func TestTLSBudgetOverflowUnblocksWaitingReader(t *testing.T) {
	b := newTLSByteBudget(1)
	c := newChanPipe(1, b)
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	c.push([]byte("too big"))
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("got %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("budget overflow left reader blocked")
	}
}

func TestTLSBudgetPipeLifecycle(t *testing.T) {
	b := newTLSByteBudget(5)
	c := newChanPipe(4, b)
	c.push([]byte("hello"))
	out := make([]byte, 2)
	if n, _ := c.Read(out); n != 2 {
		t.Fatal(n)
	}
	b.mu.Lock()
	used := b.used
	b.mu.Unlock()
	if used != 5 {
		t.Fatalf("partial read released budget: %d", used)
	}
	if _, err := c.Read(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	used = b.used
	b.mu.Unlock()
	if used != 0 {
		t.Fatalf("fully consumed chunk retained budget: %d", used)
	}

	c.push([]byte("prefix")) // over budget: marks EOF, but retains no new bytes
	c.Close()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("overflow read err=%v", err)
	}
	c.discard()
	b.mu.Lock()
	used = b.used
	b.mu.Unlock()
	if used != 0 {
		t.Fatalf("discard retained budget: %d", used)
	}
}

func TestTLSBudgetClosePreservesPrefixAndOverflowWakes(t *testing.T) {
	b := newTLSByteBudget(100)
	c := newChanPipe(2, b)
	c.push([]byte("prefix"))
	c.Close()
	out := make([]byte, 6)
	if n, err := c.Read(out); n != 6 || err != nil {
		t.Fatalf("prefix n=%d err=%v", n, err)
	}
	if _, err := c.Read(out); err != io.EOF {
		t.Fatal(err)
	}

	b = newTLSByteBudget(2)
	c = newChanPipe(1, b)
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	time.Sleep(time.Millisecond)
	c.push([]byte("too big"))
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("overflow did not wake reader")
	}
	if b.drops.Load() != 1 {
		t.Fatalf("drops=%d", b.drops.Load())
	}
}

func (f *fakeTLSSource) Records() <-chan ebpf.TLSRecord { return f.ch }
func (f *fakeTLSSource) Attach() error                  { return nil }
func (f *fakeTLSSource) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
		close(f.ch)
	}
	return nil
}

// TestConsumeTLSPairsDecryptedHTTP is the core acceptance case for the eBPF
// TLS layer: a fake Source streams canned HTTP (one SSL_write
// carrying the request, one SSL_read carrying the response, same ConnID) and
// consumeTLS must produce exactly one paired api.Entry — proving decrypted
// TLS records reach the same dissector plaintext AF_PACKET traffic uses.
func TestConsumeTLSPairsDecryptedHTTP(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	src := newFakeTLSSource()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.consumeTLS(ctx, src)

	req := "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"

	src.ch <- ebpf.TLSRecord{PID: 1, TID: 7, ConnID: 42, Direction: ebpf.TLSDirWrite, Data: []byte(req)}
	src.ch <- ebpf.TLSRecord{PID: 1, TID: 7, ConnID: 42, Direction: ebpf.TLSDirRead, Data: []byte(resp)}

	var entries []*api.Entry
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries = drain(s)
		if len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (entries=%+v)", len(entries), entries)
	}

	e := entries[0]
	if e.Protocol != api.ProtocolHTTP {
		t.Errorf("protocol = %q, want %q", e.Protocol, api.ProtocolHTTP)
	}
	if e.Request.Path != "/hello" {
		t.Errorf("request path = %q, want /hello", e.Request.Path)
	}
	if e.Response.StatusCode != 200 {
		t.Errorf("response status = %d, want 200", e.Response.StatusCode)
	}
	if e.Response.Body != "hi" {
		t.Errorf("response body = %q, want %q", e.Response.Body, "hi")
	}
}

// TestConsumeTLSDispatchesDecryptedPostgres proves the content-sniff dispatch
// (Phase 2a.1): a decrypted Postgres exchange with the synthetic port-less
// eBPF connID must reach the Postgres dissector (not the HTTP default) and
// produce a paired protocol=postgres entry.
func TestConsumeTLSDispatchesDecryptedPostgres(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	src := newFakeTLSSource()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.consumeTLS(ctx, src)

	// Request side (SSL_write): StartupMessage (skipped) + Simple Query.
	req := append([]byte{}, startupMessage()...)
	req = append(req, pgMsg('Q', []byte("SELECT id FROM t\x00"))...)
	// Response side (SSL_read): CommandComplete pairs with the query.
	resp := pgMsg('C', []byte("SELECT 1\x00"))

	src.ch <- ebpf.TLSRecord{PID: 5, TID: 9, ConnID: 77, Direction: ebpf.TLSDirWrite, Data: req}
	src.ch <- ebpf.TLSRecord{PID: 5, TID: 9, ConnID: 77, Direction: ebpf.TLSDirRead, Data: resp}

	var entries []*api.Entry
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries = drain(s)
		if len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (%+v)", len(entries), entries)
	}
	if entries[0].Protocol != api.ProtocolPostgres {
		t.Errorf("protocol = %q, want postgres (sniff dispatched to the wrong dissector)", entries[0].Protocol)
	}
	if entries[0].Request.Query != "SELECT id FROM t" {
		t.Errorf("query = %q, want %q", entries[0].Request.Query, "SELECT id FROM t")
	}
}

// TestConsumeTLSRealTupleEndpoints: when the eBPF record carries a resolved
// 4-tuple (Phase 2b kprobe), the emitted entry shows the real IPs/ports, not
// the synthetic pid:<n> endpoint.
func TestConsumeTLSRealTupleEndpoints(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	src := newFakeTLSSource()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.consumeTLS(ctx, src)

	req := "GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	tuple := ebpf.TLSRecord{PID: 1, TID: 2, ConnID: 9, SrcIP: "10.1.2.3", DstIP: "10.4.5.6", SrcPort: 44000, DstPort: 8443}

	w := tuple
	w.Direction, w.Data = ebpf.TLSDirWrite, []byte(req)
	r := tuple
	r.Direction, r.Data = ebpf.TLSDirRead, []byte(resp)
	src.ch <- w
	src.ch <- r

	var entries []*api.Entry
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if entries = drain(s); len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Source.IP != "10.1.2.3" || e.Destination.IP != "10.4.5.6" {
		t.Errorf("endpoints = %s -> %s, want 10.1.2.3 -> 10.4.5.6 (real tuple, not pid:)", e.Source.IP, e.Destination.IP)
	}
	if e.Destination.Port != 8443 {
		t.Errorf("dst port = %d, want 8443", e.Destination.Port)
	}
}

// TestConsumeTLSServerSidePostgres proves capture works when the traced
// process is the SERVER (e.g. a CNPG Postgres pod's OpenSSL): the eBPF write
// direction then carries backend messages (responses) and read carries the
// client's queries (requests) — inverted from the client case. Content-based
// role detection must still produce a correct protocol=postgres entry.
func TestConsumeTLSServerSidePostgres(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	src := newFakeTLSSource()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.consumeTLS(ctx, src)

	// SSL_read on the server = what the client sent = requests.
	readReq := append([]byte{}, startupMessage()...)
	readReq = append(readReq, pgMsg('Q', []byte("SELECT email FROM users\x00"))...)
	// SSL_write on the server = what the server sent = responses. Starts with
	// AuthenticationOk ('R'), the unambiguous backend opener, then the result.
	writeResp := append([]byte{}, pgMsg('R', []byte{0, 0, 0, 0})...)
	writeResp = append(writeResp, pgMsg('C', []byte("SELECT 1\x00"))...)

	src.ch <- ebpf.TLSRecord{PID: 8, TID: 3, ConnID: 55, Direction: ebpf.TLSDirWrite, Data: writeResp}
	src.ch <- ebpf.TLSRecord{PID: 8, TID: 3, ConnID: 55, Direction: ebpf.TLSDirRead, Data: readReq}

	var entries []*api.Entry
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries = drain(s)
		if len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (%+v)", len(entries), entries)
	}
	if entries[0].Protocol != api.ProtocolPostgres {
		t.Errorf("protocol = %q, want postgres", entries[0].Protocol)
	}
	if entries[0].Request.Query != "SELECT email FROM users" {
		t.Errorf("query = %q, want %q", entries[0].Request.Query, "SELECT email FROM users")
	}
}

// TestSniffTLS covers the protocol/role detection directly.
func TestSniffTLS(t *testing.T) {
	pgStart := startupMessage()
	cases := []struct {
		name    string
		head    []byte
		dirHint bool
		wantP   api.Protocol
		wantReq bool
	}{
		{"pg-startup", pgStart, false, api.ProtocolPostgres, true}, // client marker overrides hint
		{"pg-backend", pgMsg('T', []byte{0, 1}), false, api.ProtocolPostgres, false},
		{"pg-query-wrong-hint", pgMsg('Q', []byte("SELECT 1\x00")), false, api.ProtocolPostgres, true}, // 'Q' frontend overrides read hint (server-side)
		{"pg-auth-wrong-hint", pgMsg('R', []byte{0, 0, 0, 0}), true, api.ProtocolPostgres, false},      // 'R' backend overrides write hint (server-side)
		{"redis-cmd", []byte("*1\r\n$4\r\nPING\r\n"), false, api.ProtocolRedis, true},                  // '*' = command, overrides hint
		{"redis-reply", []byte("+OK\r\n"), true, api.ProtocolRedis, false},                             // '+' = reply, overrides hint
		{"amqp", []byte("AMQP\x00\x00\x09\x01"), false, api.ProtocolAMQP, true},
		{"http-req", []byte("GET / HTTP/1.1\r\n"), true, api.ProtocolHTTP, true},
		{"http-resp", []byte("HTTP/1.1 200 OK\r\n"), false, api.ProtocolHTTP, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotP, gotReq := sniffTLS(bufio.NewReader(strings.NewReader(string(c.head))), c.dirHint)
			if gotP != c.wantP || gotReq != c.wantReq {
				t.Errorf("sniffTLS = (%q,%v), want (%q,%v)", gotP, gotReq, c.wantP, c.wantReq)
			}
		})
	}
}

// TestChanPipeTruncatesOnLag exercises chanPipe's backpressure policy directly:
// push must never block, and once the buffer overflows the pipe delivers the
// already-buffered prefix in order and then EOF (a clean truncation) rather than
// dropping an interior chunk and desyncing the stream parser.
func TestChanPipeTruncatesOnLag(t *testing.T) {
	c := newChanPipe(2)
	c.push([]byte("a"))
	c.push([]byte("b"))
	c.push([]byte("c")) // buffer full: "c" is not enqueued; pipe marks itself lagged

	var got []byte
	buf := make([]byte, 1)
	for {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if string(got) != "ab" {
		t.Errorf("got %q, want %q (buffered prefix then clean EOF on lag, no interior drop)", got, "ab")
	}
}

func TestChanPipeCloseUnblocksRead(t *testing.T) {
	c := newChanPipe(2)
	c.Close()
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Error("Read after Close() should return an error (io.EOF)")
	}
}

// TestConsumeTLSLaggedTombstone: a Lagged record (backpressure dropped one of
// the connection's interior chunks upstream — see the ebpf loader's
// drainLoop) must close the stream with a clean truncation and count the
// drop, and a fresh record for the same ConnID afterward must start a NEW
// stream rather than resume the truncated one past a hole.
func TestConsumeTLSLaggedTombstone(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	src := newFakeTLSSource()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.consumeTLS(ctx, src)

	// Half a request, then the tombstone: no entry may be emitted from the
	// truncated stream, and the lag counter must tick.
	src.ch <- ebpf.TLSRecord{PID: 1, TID: 7, ConnID: 42, Direction: ebpf.TLSDirWrite,
		Data: []byte("GET /partial HTTP/1.1\r\nHost: e")}
	src.ch <- ebpf.TLSRecord{ConnID: 42, Lagged: true}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.tlsLagDrops.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.tlsLagDrops.Load(); got != 1 {
		t.Fatalf("tlsLagDrops = %d, want 1", got)
	}
	if got := drain(s); len(got) != 0 {
		t.Fatalf("truncated stream emitted %d entries, want 0", len(got))
	}

	// Same ConnID again: a complete exchange must pair normally on a new stream.
	src.ch <- ebpf.TLSRecord{PID: 1, TID: 7, ConnID: 42, Direction: ebpf.TLSDirWrite,
		Data: []byte("GET /fresh HTTP/1.1\r\nHost: example.com\r\n\r\n")}
	src.ch <- ebpf.TLSRecord{PID: 1, TID: 7, ConnID: 42, Direction: ebpf.TLSDirRead,
		Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")}

	var entries []*api.Entry
	for time.Now().Before(deadline) {
		entries = drain(s)
		if len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 || entries[0].Request.Path != "/fresh" {
		t.Fatalf("post-tombstone entries = %+v, want one /fresh pairing", entries)
	}
}
