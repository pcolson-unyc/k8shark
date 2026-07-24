package worker

// TST-3: the dissectors consume arbitrary bytes off the wire (RESP is
// recursive, AMQP/Postgres are length-framed, HTTP is sniffed) — a panic in
// any of them takes down the node's whole capture. These fuzz targets assert
// "never panics on hostile input"; their seed corpora (the real protocol bytes
// the unit tests already use) run on every `go test`, and `go test -fuzz`
// (see `make fuzz`) explores further. Each iteration uses a fresh sink whose
// emit() is non-blocking, so a pathological input that produces a flood of
// entries can't deadlock the target.

import (
	"bytes"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

// fuzzPipeline builds a throwaway sink+pipeline for one fuzz iteration.
func fuzzPipeline() (*pipeline, *sink) {
	s := newSink("", "", "n", discardLogger())
	return newPipeline(s, "n", "1.2.3.4", discardLogger()), s
}

func FuzzConsumeRedis(f *testing.F) {
	f.Add([]byte("*1\r\n$4\r\nPING\r\n"))
	f.Add([]byte("*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"))
	f.Add([]byte("$5\r\nvalue\r\n"))
	f.Add([]byte("-ERR nope\r\n"))
	f.Add([]byte("*-1\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, s := fuzzPipeline()
		rNet, rTr, _, _ := flows(40000, redisPort)
		p.consumeRedis(rNet, rTr, bytes.NewReader(data), true, api.ProtocolRedis)
		drain(s)
	})
}

func FuzzConsumePostgres(f *testing.F) {
	f.Add(append(pgStartup(), pgMsg('Q', []byte("SELECT 1\x00"))...))
	f.Add(pgMsg('P', []byte("s1\x00UPDATE t\x00\x00\x00")))
	f.Add(pgMsg('E', []byte("SERROR\x00C42P01\x00Mboom\x00\x00")))
	f.Add(pgMsg('D', []byte{0, 1}))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, s := fuzzPipeline()
		rNet, rTr, _, _ := flows(40001, pgPort)
		p.consumePostgres(rNet, rTr, bytes.NewReader(data), true)
		drain(s)
	})
}

func FuzzConsumeAMQP(f *testing.F) {
	f.Add(amqpFrame(amqpFrameMethod, 1, amqpMethod(amqpClassQueue, 10,
		append(appendU16(nil, 0), amqpShortStrBytes("q")...))))
	f.Add(amqpFrame(amqpFrameHeader, 1, []byte{0, 0, 0, 0, 0, 0, 0, 5, 0, 0}))
	f.Add(amqpFrame(amqpFrameBody, 1, []byte("hello")))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, s := fuzzPipeline()
		rNet, rTr, _, _ := flows(40002, amqpPort)
		p.consumeAMQP(rNet, rTr, bytes.NewReader(data), true)
		drain(s)
	})
}

// FuzzConsumeStream exercises the full port-based dispatch plus the HTTP sniff
// on the default branch (server port 80): arbitrary bytes that don't look like
// any known protocol must degrade cleanly, not panic.
func FuzzConsumeStream(f *testing.F) {
	f.Add([]byte("GET /health HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	f.Add([]byte("not a protocol at all"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, s := fuzzPipeline()
		rNet, rTr, _, _ := flows(40003, 80)
		p.consumeStream(rNet, rTr, bytes.NewReader(data))
		drain(s)
	})
}
