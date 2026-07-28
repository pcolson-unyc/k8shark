package worker

// TST-7: benchmarks for the per-connection dissection hot path — the work done
// for every reassembled request/response pair the node captures. b.ReportAllocs
// tracks per-entry allocations. Run with `make bench`. One pipeline is reused
// across iterations (as a real long-lived connection would be), draining the
// sink each round so its buffer never fills.

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

// BenchmarkHexDump / BenchmarkHexDumpReference bracket the renderer rewrite.
// hexDump is the worker's hottest formatting site — it runs for every request,
// response and generic L4 flow, and its output is ~75% of the bytes shipped to
// the hub — so the reference (the original one-fmt.Fprintf-per-byte version,
// kept in hexdump_test.go as the correctness oracle) is benchmarked alongside
// it to keep the gap visible.
func BenchmarkHexDump(b *testing.B) {
	buf := make([]byte, 2048)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hexDump(buf, len(buf))
	}
}

func BenchmarkHexDumpReference(b *testing.B) {
	buf := make([]byte, 2048)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = referenceHexDump(buf, len(buf))
	}
}

// BenchmarkFlagSetString covers the [64]string lookup table; buildL4Info calls
// this twice for every emitted entry.
func BenchmarkFlagSetString(b *testing.B) {
	f := flagSYN | flagACK | flagPSH
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.String()
	}
}

// BenchmarkTrackTCPPacket measures the per-packet L4 accounting path — the work
// done for every single captured TCP packet, dissected or not. It is driven
// with a real serialised packet so extractL4Meta sees genuine decoded layers,
// and the flow is established before the timer starts so the benchmark
// measures the steady state (header metadata already captured once).
func BenchmarkTrackTCPPacket(b *testing.B) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	p.rawCap = 0 // raw sampling is a separate concern; keep this to the L4 path
	reqNet, reqTr, _, _ := flows(40010, 80)
	pkt, meta := mkPacketMeta(b, "02:00:00:00:00:41", "02:00:00:00:00:42", 64, true)
	base := time.Unix(1_700_000_000, 0)

	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 64240, 0), 60, base, meta)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := extractL4Meta(pkt)
		// Distinct seq per iteration so the CAP-8 dedup gate doesn't short-
		// circuit the accounting we are trying to measure.
		p.trackTCP(reqNet, reqTr, mkTCP(uint32(i)*100+2, false, true, false, 64240, 100), 154,
			base.Add(time.Duration(i)*time.Second), m)
	}
}

// BenchmarkCapReaderRaw measures rawOf()/raw() on a keep-alive connection whose
// captured head has already frozen — i.e. every entry after the first on a
// long-lived connection.
func BenchmarkCapReaderRaw(b *testing.B) {
	cr := newCapReader(strings.NewReader(strings.Repeat("x", 1<<16)), 512)
	buf := make([]byte, 1024)
	for i := 0; i < 8; i++ {
		_, _ = cr.Read(buf)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cr.raw()
	}
}

// BenchmarkDecompressBody covers the gzip/deflate reader pooling. Most
// real-world HTTP APIs respond compressed, so this runs for the majority of
// captured responses, and an unpooled gzip.Reader drags a ~32 KiB window plus
// Huffman tables in with it every time.
func BenchmarkDecompressBody(b *testing.B) {
	payload := strings.Repeat(`{"id":1,"name":"row"},`, 200)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(payload))
	_ = zw.Close()
	body := gz.String()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out, _ := decompressBody(body, false, "gzip", 1<<20); len(out) != len(payload) {
			b.Fatalf("decompressed %d bytes, want %d", len(out), len(payload))
		}
	}
}

func BenchmarkConsumeHTTP(b *testing.B) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40000, 80)
	const req = "GET /api/v1/users?page=2 HTTP/1.1\r\nHost: api\r\nUser-Agent: bench\r\n\r\n"
	const resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.consumeHTTP(rNet, rTr, strings.NewReader(req))
		p.consumeHTTP(sNet, sTr, strings.NewReader(resp))
		drain(s)
	}
}

func BenchmarkConsumeRedis(b *testing.B) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40001, redisPort)
	const req = "*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n"
	const resp = "$5\r\nvalue\r\n"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.consumeRedis(rNet, rTr, strings.NewReader(req), true, api.ProtocolRedis)
		p.consumeRedis(sNet, sTr, strings.NewReader(resp), false, api.ProtocolRedis)
		drain(s)
	}
}

func BenchmarkConsumePostgres(b *testing.B) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40002, pgPort)
	req := string(pgMsg('Q', []byte("SELECT id FROM t WHERE k = 1\x00")))
	resp := string(pgMsg('C', []byte("SELECT 1\x00")))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.consumePostgres(rNet, rTr, strings.NewReader(req), true)
		p.consumePostgres(sNet, sTr, strings.NewReader(resp), false)
		drain(s)
	}
}
