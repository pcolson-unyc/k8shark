package worker

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func assembleTestTCP(a *tcpassembly.Assembler, netFlow, transport gopacket.Flow, src, dst layers.TCPPort, seq uint32, syn, fin bool, payload string, ts time.Time) {
	raw := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(raw[0:2], uint16(src))
	binary.BigEndian.PutUint16(raw[2:4], uint16(dst))
	binary.BigEndian.PutUint32(raw[4:8], seq)
	raw[12] = 5 << 4
	if syn {
		raw[13] |= 0x02
	}
	if fin {
		raw[13] |= 0x01
	}
	copy(raw[20:], payload)
	t := &layers.TCP{}
	if err := t.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
		panic(err)
	}
	a.AssembleWithTimestamp(netFlow, t, ts)
}

func TestAssemblerLifecycleActualPackets(t *testing.T) {
	p := newPipeline(newSink("", "", "", slog.Default()), "", "", slog.Default())
	var live atomic.Int64
	var creates atomic.Uint64
	a := newWorkerAssembler(p, &live, &creates)
	baseline := creates.Load()
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2))
	transport := gopacket.NewFlow(layers.EndpointTCPPort, layers.NewTCPPortEndpoint(1234).Raw(), layers.NewTCPPortEndpoint(80).Raw())
	now := time.Now()
	assembleTestTCP(a, netFlow, transport, 1234, 80, 1, true, false, "", now)
	assembleTestTCP(a, netFlow, transport, 1234, 80, 2, false, false, "GET / HTTP/1.0\r\n\r\n", now.Add(time.Millisecond))
	assembleTestTCP(a, netFlow, transport, 1234, 80, 21, false, true, "", now.Add(2*time.Millisecond))
	if live.Load() != 1 {
		t.Fatalf("after SYN/data/FIN, live streams=%d, want 1 before flush", live.Load())
	}
	a.FlushOlderThan(now.Add(time.Hour))
	deadline := time.Now().Add(time.Second)
	for live.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if live.Load() != 0 {
		t.Fatalf("stream completion did not decrement live count: %d", live.Load())
	}
	if got := reclaimWorkerAssembler(a, p, &live, &creates, &baseline); got == a {
		t.Fatal("idle assembler was not retired after actual packet lifecycle")
	}

	// A current stream must prevent rotation and continue accepting bytes.
	b := newWorkerAssembler(p, &live, &creates)
	baseline = creates.Load()
	netFlow = gopacket.NewFlow(layers.EndpointIPv4, net.IPv4(10, 0, 0, 3), net.IPv4(10, 0, 0, 4))
	transport = gopacket.NewFlow(layers.EndpointTCPPort, layers.NewTCPPortEndpoint(1235).Raw(), layers.NewTCPPortEndpoint(80).Raw())
	assembleTestTCP(b, netFlow, transport, 1235, 80, 1, true, false, "", now)
	assembleTestTCP(b, netFlow, transport, 1235, 80, 2, false, false, "GET / HTTP/1.0\r\n", now.Add(time.Millisecond))
	if live.Load() == 0 {
		t.Fatal("actual SYN did not create a live stream")
	}
	if got := reclaimWorkerAssembler(b, p, &live, &creates, &baseline); got != b {
		t.Fatal("reclaimed assembler while actual stream was active")
	}
	assembleTestTCP(b, netFlow, transport, 1235, 80, 2+uint32(len("GET / HTTP/1.0\r\n")), false, false, "\r\n", now.Add(2*time.Millisecond))
	b.FlushAll()
}

func TestReclaimWorkerAssemblerPreservesActiveStreams(t *testing.T) {
	p := newPipeline(nil, "", "", slog.Default())
	var live atomic.Int64
	var creates atomic.Uint64
	a := newWorkerAssembler(p, &live, &creates)
	baseline := creates.Load()
	live.Store(1)
	if got := reclaimWorkerAssembler(a, p, &live, &creates, &baseline); got != a {
		t.Fatal("reclaimed assembler while a stream was active")
	}
}

func TestReclaimWorkerAssemblerRotatesWhenIdle(t *testing.T) {
	p := newPipeline(nil, "", "", slog.Default())
	var live atomic.Int64
	var creates atomic.Uint64
	a := newWorkerAssembler(p, &live, &creates)
	creates.Add(1) // represent a burst that created a stream, now idle
	baseline := uint64(0)
	if got := reclaimWorkerAssembler(a, p, &live, &creates, &baseline); got == a {
		t.Fatal("idle assembler was not retired")
	}
}

func TestNewWorkerAssemblerKeepsReassemblyBounds(t *testing.T) {
	p := newPipeline(nil, "", "", slog.Default())
	var live atomic.Int64
	var creates atomic.Uint64
	a := newWorkerAssembler(p, &live, &creates)
	if a.MaxBufferedPagesTotal != maxBufferedPagesTotal || a.MaxBufferedPagesPerConnection != maxBufferedPagesPerConnection {
		t.Fatalf("assembler bounds changed: total=%d/conn=%d", a.MaxBufferedPagesTotal, a.MaxBufferedPagesPerConnection)
	}
}
