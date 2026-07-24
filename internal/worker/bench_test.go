package worker

// TST-7: benchmarks for the per-connection dissection hot path — the work done
// for every reassembled request/response pair the node captures. b.ReportAllocs
// tracks per-entry allocations. Run with `make bench`. One pipeline is reused
// across iterations (as a real long-lived connection would be), draining the
// sink each round so its buffer never fills.

import (
	"strings"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

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
