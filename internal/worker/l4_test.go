package worker

import (
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pablocolson/k8shark/pkg/api"
)

// mkPacketMeta serialises a real Ethernet+IPv4+TCP packet, decodes it and runs
// it through extractL4Meta. Tests need a genuine packet (not a hand-filled
// struct) because l4meta now carries the decoded layers themselves and renders
// the MAC strings / fragment flags / header hexdump lazily from their real
// LayerContents — see the l4meta doc comment in worker.go.
func mkPacketMeta(t testing.TB, srcMAC, dstMAC string, ttl uint8, df bool) (gopacket.Packet, l4meta) {
	t.Helper()
	sm, err := net.ParseMAC(srcMAC)
	if err != nil {
		t.Fatalf("bad src MAC %q: %v", srcMAC, err)
	}
	dm, err := net.ParseMAC(dstMAC)
	if err != nil {
		t.Fatalf("bad dst MAC %q: %v", dstMAC, err)
	}
	eth := &layers.Ethernet{SrcMAC: sm, DstMAC: dm, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: ttl, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
	}
	if df {
		ip.Flags = layers.IPv4DontFragment
	}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 80, SYN: true, Window: 64240, DataOffset: 5}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return pkt, extractL4Meta(pkt)
}

// mkTCP builds a *layers.TCP with the given flags/seq/window/payload for driving
// trackTCP directly.
func mkTCP(seq uint32, syn, ack, fin bool, window uint16, payload int, opts ...layers.TCPOption) *layers.TCP {
	t := &layers.TCP{Seq: seq, SYN: syn, ACK: ack, FIN: fin, Window: window, Options: opts}
	if payload > 0 {
		t.Payload = make([]byte, payload)
	}
	return t
}

func TestTrackTCPSnapshotL4(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	// client 40000 -> server 80
	reqNet, reqTr, respNet, respTr := flows(40000, 80)

	mss := layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}} // 1460
	base := time.Unix(1_700_000_000, 0)
	pkt, meta := mkPacketMeta(t, "02:00:00:00:00:01", "02:00:00:00:00:02", 64, true)
	empty := l4meta{}

	// SYN (client) — carries the L3 meta, MSS and window.
	p.trackTCP(reqNet, reqTr, mkTCP(1000, true, false, false, 64240, 0, mss), 60, base, meta)
	// SYN-ACK (server), +10ms.
	p.trackTCP(respNet, respTr, mkTCP(5000, true, true, false, 64240, 0), 60, base.Add(10*time.Millisecond), empty)
	// Client data (100B payload), +11ms.
	p.trackTCP(reqNet, reqTr, mkTCP(1001, false, true, false, 64240, 100), 154, base.Add(11*time.Millisecond), empty)
	// Client retransmit — same seq, non-empty payload => retransmit++. +211ms
	// (200ms after the original, past Linux's minimum RTO) so it lands well
	// outside CAP-8's dedupWindow and is unambiguously a real retransmit, not
	// a same-packet-via-another-interface duplicate.
	p.trackTCP(reqNet, reqTr, mkTCP(1001, false, true, false, 64240, 100), 154, base.Add(211*time.Millisecond), empty)
	// Server data (200B payload), +212ms.
	p.trackTCP(respNet, respTr, mkTCP(5001, false, true, false, 64240, 200), 254, base.Add(212*time.Millisecond), empty)

	info := p.snapshotL4(connKey(reqNet, reqTr))
	if info == nil {
		t.Fatal("snapshotL4 returned nil")
	}
	if info.RTTMs <= 0 {
		t.Errorf("RTTMs = %v, want > 0", info.RTTMs)
	}
	if info.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460", info.MSS)
	}
	if info.SeqStart != 1000 || info.AckStart != 5000 {
		t.Errorf("SeqStart/AckStart = %d/%d, want 1000/5000", info.SeqStart, info.AckStart)
	}
	if info.Retransmits != 1 {
		t.Errorf("Retransmits = %d, want 1", info.Retransmits)
	}
	if info.ClientTCPFlags != "SYN,ACK" {
		t.Errorf("ClientTCPFlags = %q, want SYN,ACK", info.ClientTCPFlags)
	}
	// SYN + data + retransmit = 3 client packets; SYN-ACK + data = 2 server packets.
	if info.ClientPackets != 3 || info.ServerPackets != 2 {
		t.Errorf("packets client/server = %d/%d, want 3/2", info.ClientPackets, info.ServerPackets)
	}
	if info.ClientBytes != 60+154+154 || info.ServerBytes != 60+254 {
		t.Errorf("bytes client/server = %d/%d, want 368/314", info.ClientBytes, info.ServerBytes)
	}
	if info.SrcMAC != "02:00:00:00:00:01" || info.DstMAC != "02:00:00:00:00:02" || info.TTL != 64 || info.IPFlags != "DF" {
		t.Errorf("L3 meta not copied: %+v", info)
	}
	// The header hexdump is now rendered inside trackTCP (once per flow) rather
	// than in extractL4Meta (once per packet); it must still be the dump of the
	// packet's real eth+ip+tcp header bytes.
	if want := hexDump(pkt.Data()[:14+20+20], p.headerHexCap); info.HeaderHex != want {
		t.Errorf("HeaderHex = %q, want %q", info.HeaderHex, want)
	}
	if info.Window != 64240 {
		t.Errorf("Window = %d, want 64240", info.Window)
	}
}

// A FIN closes the flow and emits a generic L4 entry carrying L4Info.
func TestTrackTCPCloseEmitsL4(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, reqTr, _, _ := flows(41000, 443)
	base := time.Unix(1_700_000_000, 0)
	_, meta := mkPacketMeta(t, "02:00:00:00:00:0a", "02:00:00:00:00:0b", 128, false)

	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base, meta)
	p.trackTCP(reqNet, reqTr, mkTCP(2, false, true, true, 1000, 0), 60, base.Add(time.Millisecond), l4meta{})

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].L4 == nil {
		t.Fatal("emitted L4 flow has no L4Info")
	}
	if got[0].L4.TTL != 128 {
		t.Errorf("L4.TTL = %d, want 128", got[0].L4.TTL)
	}
}

// A generic (undissected) TCP flow now samples its payload into Request.Raw,
// same as the L7 dissectors already did — previously only HTTP/Redis/
// Postgres/AMQP populated Raw at all.
func TestTrackTCPCapturesRawPayload(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, reqTr, _, _ := flows(41001, 443)
	base := time.Unix(1_700_000_001, 0)

	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base, l4meta{})

	data := mkTCP(2, false, true, false, 1000, 0)
	data.Payload = []byte("hello from the client")
	p.trackTCP(reqNet, reqTr, data, 60+len(data.Payload), base.Add(time.Millisecond), l4meta{})

	fin := mkTCP(2+uint32(len(data.Payload)), false, true, true, 1000, 0)
	p.trackTCP(reqNet, reqTr, fin, 60, base.Add(2*time.Millisecond), l4meta{})

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	raw := got[0].Request.Raw
	if raw == nil {
		t.Fatal("generic L4 flow has no Raw view (payload was seen but not captured)")
	}
	if raw.Bytes != len(data.Payload) {
		t.Errorf("raw.Bytes = %d, want %d", raw.Bytes, len(data.Payload))
	}
	if !strings.Contains(string(raw.Data), "hello") {
		t.Errorf("raw.Data = %q, want it to contain the captured payload text", raw.Data)
	}
}

// TestSegFingerprintSeenRecently exercises the CAP-8 dedup primitive in
// isolation: same seq/len within dedupWindow is a dup, the recorded
// fingerprint stays pinned to the original sighting (so a third delivery
// still compares against it, not the second), and anything outside the
// window or with a different seq is never a dup.
func TestSegFingerprintSeenRecently(t *testing.T) {
	var fp segFingerprint
	base := time.Unix(1_700_000_005, 0)

	if fp.seenRecently(100, 50, base) {
		t.Error("first sighting must never be a dup")
	}
	if !fp.seenRecently(100, 50, base.Add(time.Millisecond)) {
		t.Error("same seq/len within dedupWindow must be a dup")
	}
	if !fp.seenRecently(100, 50, base.Add(2*time.Millisecond)) {
		t.Error("a third delivery within the window of the ORIGINAL sighting must also be a dup")
	}
	if fp.seenRecently(100, 50, base.Add(10*time.Millisecond)) {
		t.Error("same seq/len outside dedupWindow must not be treated as a dup")
	}
	if fp.seenRecently(200, 50, base.Add(10*time.Millisecond+time.Microsecond)) {
		t.Error("a different seq must never be a dup")
	}
}

// TestTrackTCPDedupsSamePacketAcrossInterfaces is the CAP-8 regression test:
// AF_PACKET on the "any" interface can see one physical packet more than once
// on a CNI-overlay node (the physical NIC, the CNI's vxlan/overlay interface,
// and the destination pod's veth all hand the same packet to the capture
// socket). Before the dedup gate, each extra delivery double/triple-counted
// bytes/packets and — worse — read as a spurious retransmit.
func TestTrackTCPDedupsSamePacketAcrossInterfaces(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, reqTr, _, _ := flows(43000, 80)
	base := time.Unix(1_700_000_003, 0)

	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base, l4meta{})

	// The same 100-byte data segment delivered 3 times, microseconds apart —
	// as if captured on eth0, the CNI overlay interface and the pod veth.
	data := mkTCP(2, false, true, false, 1000, 100)
	p.trackTCP(reqNet, reqTr, data, 154, base.Add(1*time.Millisecond), l4meta{})
	p.trackTCP(reqNet, reqTr, data, 154, base.Add(2*time.Millisecond), l4meta{})
	p.trackTCP(reqNet, reqTr, data, 154, base.Add(3*time.Millisecond), l4meta{})

	fin := mkTCP(102, false, true, true, 1000, 0)
	p.trackTCP(reqNet, reqTr, fin, 60, base.Add(4*time.Millisecond), l4meta{})

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	info := got[0].L4
	if info == nil {
		t.Fatal("emitted L4 flow has no L4Info")
	}
	if info.Retransmits != 0 {
		t.Errorf("Retransmits = %d, want 0 (duplicate deliveries, not real retransmits)", info.Retransmits)
	}
	// SYN + one (deduped) data segment + FIN = 3, not 5.
	if info.ClientPackets != 3 {
		t.Errorf("ClientPackets = %d, want 3 (2 duplicate deliveries dropped)", info.ClientPackets)
	}
	if want := int64(60 + 154 + 60); info.ClientBytes != want {
		t.Errorf("ClientBytes = %d, want %d", info.ClientBytes, want)
	}
	if raw := got[0].Request.Raw; raw == nil || raw.Bytes != 100 {
		t.Errorf("Request.Raw.Bytes = %+v, want 100 (not tripled by the duplicate deliveries)", raw)
	}
}

// TestTrackTCPCountsRealRetransmitOutsideDedupWindow guards the other side of
// CAP-8: a genuine retransmission of the same byte range, arriving well after
// dedupWindow, must still be counted — the dedup gate must not swallow real
// network problems along with the same-host duplicate deliveries it targets.
func TestTrackTCPCountsRealRetransmitOutsideDedupWindow(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, reqTr, _, _ := flows(43001, 80)
	base := time.Unix(1_700_000_004, 0)

	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base, l4meta{})

	data := mkTCP(2, false, true, false, 1000, 100)
	p.trackTCP(reqNet, reqTr, data, 154, base.Add(1*time.Millisecond), l4meta{})
	// Same seq/len as above, but 200ms later (Linux's minimum RTO) — well
	// outside dedupWindow, so this is a real retransmit, not a duplicate
	// delivery, and must still be counted as one.
	p.trackTCP(reqNet, reqTr, data, 154, base.Add(200*time.Millisecond), l4meta{})

	fin := mkTCP(102, false, true, true, 1000, 0)
	p.trackTCP(reqNet, reqTr, fin, 60, base.Add(201*time.Millisecond), l4meta{})

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if info := got[0].L4; info == nil || info.Retransmits != 1 {
		t.Errorf("Retransmits = %+v, want 1 (a real retransmit outside the dedup window)", info)
	}
}

// TestMaxFlowsCapEvicts guards against p.flows growing without bound when a
// burst of connections (SYN flood/scan) arrives faster than flushFlows'
// idle-based reaping runs.
func TestMaxFlowsCapEvicts(t *testing.T) {
	orig := maxFlows
	maxFlows = 3
	defer func() { maxFlows = orig }()

	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	base := time.Unix(1_700_000_002, 0)

	// 5 distinct connections, each just a SYN (no FIN/RST, so trackTCP itself
	// never removes one) — enough to push well past the shrunk cap.
	for i := 0; i < 5; i++ {
		reqNet, reqTr, _, _ := flows(42000+i, 80)
		p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base, l4meta{})
	}

	p.flowMu.Lock()
	n := len(p.flows)
	p.flowMu.Unlock()
	if n > maxFlows {
		t.Errorf("len(p.flows) = %d, want <= maxFlows (%d)", n, maxFlows)
	}
	if got := s.flowsEvicted.Load(); got == 0 {
		t.Error("flowsEvicted = 0, want > 0 after exceeding maxFlows")
	}
}

// TestSnapshotL4HeaderHexForL7Flow guards the non-obvious half of moving the
// header hexdump out of the per-packet path: headerHex is NOT dead for
// L7-dissected connections. They never emit a generic L4 entry, but every
// paired L7 entry carries snapshotL4 -> buildL4Info -> HeaderHex, so the dump
// must still be rendered exactly once per flow even when the flow is flagged
// l7 before any packet arrives.
func TestSnapshotL4HeaderHexForL7Flow(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, reqTr, respNet, respTr := flows(44000, 80)
	key := connKey(reqNet, reqTr)
	base := time.Unix(1_700_000_006, 0)
	pkt, meta := mkPacketMeta(t, "02:00:00:00:00:11", "02:00:00:00:00:12", 63, true)

	// markL7 first (as a dissector does on the first parsed request), so the
	// flow exists as a placeholder before trackTCP ever sees a packet.
	p.markL7(key)
	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base, meta)

	info := p.snapshotL4(key)
	if info == nil {
		t.Fatal("snapshotL4 returned nil for an L7-flagged flow")
	}
	want := hexDump(pkt.Data()[:14+20+20], p.headerHexCap)
	if info.HeaderHex != want {
		t.Errorf("HeaderHex = %q, want %q", info.HeaderHex, want)
	}
	if info.SrcMAC != "02:00:00:00:00:11" || info.IPFlags != "DF" || info.TTL != 63 {
		t.Errorf("L3 meta not filled for an L7 flow: %+v", info)
	}

	// The orientation of a markL7 placeholder is back-filled from the first
	// packet, so the server direction must still be accounted as server->client.
	p.trackTCP(respNet, respTr, mkTCP(9, true, true, false, 1000, 0), 60, base.Add(time.Millisecond), l4meta{})
	info = p.snapshotL4(key)
	if info.ClientPackets != 1 || info.ServerPackets != 1 {
		t.Errorf("packets client/server = %d/%d, want 1/1", info.ClientPackets, info.ServerPackets)
	}

	// A second packet must not re-render (or change) the header dump.
	p.trackTCP(reqNet, reqTr, mkTCP(2, false, true, false, 1000, 0), 60, base.Add(2*time.Millisecond),
		mustMeta(t, "02:00:00:00:00:99", "02:00:00:00:00:98", 1, false))
	if got := p.snapshotL4(key).HeaderHex; got != want {
		t.Errorf("HeaderHex changed on a later packet: %q, want %q (first packet wins)", got, want)
	}
}

// mustMeta is mkPacketMeta without the packet, for call sites that only need
// the metadata.
func mustMeta(t testing.TB, srcMAC, dstMAC string, ttl uint8, df bool) l4meta {
	t.Helper()
	_, m := mkPacketMeta(t, srcMAC, dstMAC, ttl, df)
	return m
}

// TestHeaderHexDisabledByCap: headerHexCap <= 0 must skip the dump entirely
// (the render is now gated inside trackTCP rather than in extractL4Meta).
func TestHeaderHexDisabledByCap(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	p.headerHexCap = 0
	reqNet, reqTr, _, _ := flows(44001, 80)
	base := time.Unix(1_700_000_007, 0)

	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base,
		mustMeta(t, "02:00:00:00:00:21", "02:00:00:00:00:22", 64, false))

	if got := p.snapshotL4(connKey(reqNet, reqTr)).HeaderHex; got != "" {
		t.Errorf("HeaderHex = %q, want empty with headerHexCap = 0", got)
	}
}

// TestCompleteResponsePairWaitSwitch pins which capture path pays the
// pending-request retry budget. The eBPF TLS path genuinely races (both
// direction goroutines are fed back-to-back from memory) and must keep
// waiting; an AF_PACKET connection with nothing pending is simply unpairable,
// and sleeping on it stalls the goroutine draining tcpassembly.
func TestCompleteResponsePairWaitSwitch(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	const key = "10.0.0.1:1234|10.0.0.2:80"
	budget := time.Duration(completeResponsePairRetries) * completeResponsePairDelay

	// Not registered as AF_PACKET-fed => the conservative default is kept.
	start := time.Now()
	p.completeResponse(key, api.Payload{}, 200, "success", time.Time{})
	if el := time.Since(start); el < budget {
		t.Errorf("unregistered conn gave up after %v, want it to spend the ~%v TLS-race budget", el, budget)
	}

	// Registered => no wait at all.
	p.addAFPacketStream(key)
	start = time.Now()
	p.completeResponse(key, api.Payload{}, 200, "success", time.Time{})
	if el := time.Since(start); el > completeResponsePairDelay {
		t.Errorf("AF_PACKET conn slept %v on an unpairable response, want no wait", el)
	}
	if got := drain(s); len(got) != 0 {
		t.Fatalf("unpairable responses emitted %d entries, want 0", len(got))
	}

	// Pairing itself is untouched by the switch.
	p.enqueueRequest(key, api.ProtocolHTTP, api.Payload{Summary: "GET /x"},
		api.Endpoint{IP: "10.0.0.1", Port: 1234}, api.Endpoint{IP: "10.0.0.2", Port: 80})
	p.completeResponse(key, api.Payload{Summary: "200 OK"}, 200, "success", time.Time{})
	got := drain(s)
	if len(got) != 1 || got[0].Request.Summary != "GET /x" || got[0].Response.Summary != "200 OK" {
		t.Fatalf("paired emit = %+v, want a single GET /x <-> 200 OK entry", got)
	}

	// Both directions register under the same key, so the refcount must
	// outlive the first direction's exit and clean up after the last.
	p.addAFPacketStream(key)
	p.removeAFPacketStream(key)
	p.mu.Lock()
	n, present := p.afPacketStreams[key]
	p.mu.Unlock()
	if !present || n != 1 {
		t.Errorf("afPacketStreams[key] = %d (present=%v), want 1 — refcount dropped a live direction", n, present)
	}
	p.removeAFPacketStream(key)
	p.mu.Lock()
	_, present = p.afPacketStreams[key]
	p.mu.Unlock()
	if present {
		t.Error("afPacketStreams entry leaked after the last direction exited")
	}
}

// TestConsumeHTTPMarksL7Once: a dissected HTTP connection must be flagged
// L7 — otherwise it would also emit a duplicate generic L4 flow entry on close.
func TestConsumeHTTPMarksL7Once(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, reqTr, _, _ := flows(45000, 80)
	key := connKey(reqNet, reqTr)

	// Two pipelined requests on one connection.
	p.consumeHTTP(reqNet, reqTr, strings.NewReader(
		"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n"))

	p.flowMu.Lock()
	f := p.flows[key]
	l7 := f != nil && f.l7
	p.flowMu.Unlock()
	if !l7 {
		t.Fatal("HTTP request direction did not flag the connection as L7-dissected")
	}

	// ...so closing the connection must not also emit a generic L4 flow.
	base := time.Unix(1_700_000_008, 0)
	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, base, l4meta{})
	p.trackTCP(reqNet, reqTr, mkTCP(2, false, true, true, 1000, 0), 60, base.Add(time.Millisecond), l4meta{})
	if got := drain(s); len(got) != 0 {
		t.Errorf("got %d generic L4 entries for an L7-dissected connection, want 0", len(got))
	}
}

// stepReader hands out its chunks one Read at a time, running between() at
// every chunk boundary after the first. It is how these tests get *inside* a
// dissector goroutine that is parked waiting for more bytes: everything a
// single consumeHTTP call latches or reserves per connection is invisible to a
// test that just calls consumeHTTP twice (each call starts with fresh locals),
// yet on a real keep-alive connection one call spans minutes and many requests.
type stepReader struct {
	chunks  []string
	between func()
	reads   int
}

func (r *stepReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	if r.reads > 0 && r.between != nil {
		r.between()
	}
	r.reads++
	n := copy(p, r.chunks[0])
	if n < len(r.chunks[0]) {
		r.chunks[0] = r.chunks[0][n:]
	} else {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

// TestConsumeHTTPReMarksL7AfterIdleFlowReap is the regression test for the
// markL7 latch: flushFlows *deletes* an idle flow whatever its l7 flag (the
// !f.l7 test there only suppresses the emit), and HTTP keep-alive connections
// routinely idle past the 20s timeout — Go's IdleConnTimeout is 90s, nginx's
// keepalive_timeout 75s. If the flag were latched per stream, the request
// arriving after that reap would recreate the flowState unflagged and never
// re-flag it, and every later idle period plus the FIN would emit a generic
// TCP entry duplicating traffic already reported as HTTP entries.
func TestConsumeHTTPReMarksL7AfterIdleFlowReap(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	reqNet, reqTr, _, _ := flows(45002, 80)
	key := connKey(reqNet, reqTr)

	// A keep-alive connection whose last packet is a minute old — exactly what
	// the 20s idle sweep reaps.
	old := time.Now().Add(-time.Minute)
	p.trackTCP(reqNet, reqTr, mkTCP(1, true, false, false, 1000, 0), 60, old, l4meta{})

	var reaped bool
	p.consumeHTTP(reqNet, reqTr, &stepReader{
		chunks: []string{
			"GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
			"GET /b HTTP/1.1\r\nHost: h\r\n\r\n",
		},
		between: func() {
			p.flushFlows(20 * time.Second)
			p.flowMu.Lock()
			reaped = p.flows[key] == nil
			p.flowMu.Unlock()
		},
	})

	if !reaped {
		t.Fatal("precondition: flushFlows must reap the idle flow of an L7 connection (the l7 flag only suppresses the emit)")
	}
	p.flowMu.Lock()
	f := p.flows[key]
	l7 := f != nil && f.l7
	p.flowMu.Unlock()
	if !l7 {
		t.Fatal("the request after the idle reap did not re-flag the connection as L7-dissected")
	}

	// ...so the connection closing must still not emit a generic L4 entry.
	now := time.Now()
	p.trackTCP(reqNet, reqTr, mkTCP(2, false, true, false, 1000, 0), 60, now, l4meta{})
	p.trackTCP(reqNet, reqTr, mkTCP(3, false, true, true, 1000, 0), 60, now.Add(time.Millisecond), l4meta{})
	if got := drain(s); len(got) != 0 {
		t.Errorf("got %d generic L4 entries on an L7 connection whose flow was reaped mid-life, want 0: %+v", len(got), got)
	}
}

// TestConsumeHTTPPairsResponseOvertakingRequestBody is the regression test for
// the pairing window closed by reserveRequest. A tcpreader.ReaderStream
// releases the assembler as soon as its reader asks for bytes it doesn't have,
// so once a request body spans more than one reassembly the response direction
// gets its data — and reaches completeResponse — while the request goroutine
// is still parked inside drainBody. Enqueueing the request only after its body
// was read dropped that response outright on AF_PACKET (which does not wait for
// a pending request), and no amount of waiting there could have fixed it: the
// request direction cannot advance until this very goroutine returns to the
// reassembler.
func TestConsumeHTTPPairsResponseOvertakingRequestBody(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(45003, 80)
	key := connKey(rNet, rTr)
	// AF_PACKET-fed, so completeResponse spends no retry budget: the pairing
	// has to be right on the first look.
	p.addAFPacketStream(key)
	defer p.removeAFPacketStream(key)

	p.consumeHTTP(rNet, rTr, &stepReader{
		chunks: []string{
			"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n",
			"hello",
		},
		// The whole response direction runs while the request goroutine is
		// parked waiting for its body — the interleaving described above.
		between: func() {
			p.consumeHTTP(sNet, sTr, strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		},
	})

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 — the response that overtook the request body was dropped", len(got))
	}
	e := got[0]
	if e.Request.Method != "POST" || e.Request.Path != "/x" {
		t.Errorf("request = %s %s, want POST /x", e.Request.Method, e.Request.Path)
	}
	// The body must be the *filled-in* one, not the empty payload the slot was
	// reserved with.
	if e.Request.Body != "hello" || e.Request.Size != 5 || e.Request.Truncated {
		t.Errorf("request body = %q (size %d, truncated %v), want %q (size 5)", e.Request.Body, e.Request.Size, e.Request.Truncated, "hello")
	}
	if e.StatusCode != 200 || e.Response.Body != "ok" {
		t.Errorf("response = %q (status %d), want %q with status 200", e.Response.Body, e.StatusCode, "ok")
	}
}

// TestGCSweepsStaleAndKeepsFresh guards the batched (lock-releasing) rewrite of
// gc: releasing p.mu between delete batches must not reap anything fresh, and
// must still reap everything stale.
func TestGCSweepsStaleAndKeepsFresh(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	old := time.Now().Add(-time.Hour)

	// Enough entries to span several gcDeleteBatch batches.
	const n = 3 * gcDeleteBatch
	p.mu.Lock()
	for i := 0; i < n; i++ {
		k := "stale-" + strconv.Itoa(i)
		p.dns[k] = &dnsPending{ts: old}
		p.conns[k] = &connState{reqs: []*pendingReq{{ts: old}}}
		p.kafka[k] = &kafkaPending{ts: old}
	}
	p.dns["fresh"] = &dnsPending{ts: time.Now()}
	p.conns["fresh"] = &connState{reqs: []*pendingReq{{ts: time.Now()}}}
	p.kafka["fresh"] = &kafkaPending{ts: time.Now()}
	// A connection whose oldest request is stale but which also holds a fresh
	// one must be pruned, not deleted.
	p.conns["mixed"] = &connState{reqs: []*pendingReq{{ts: old}, {ts: time.Now()}}}
	p.mu.Unlock()

	p.gc()

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.dns) != 1 || p.dns["fresh"] == nil {
		t.Errorf("p.dns = %d entries, want just the fresh one", len(p.dns))
	}
	if len(p.kafka) != 1 || p.kafka["fresh"] == nil {
		t.Errorf("p.kafka = %d entries, want just the fresh one", len(p.kafka))
	}
	if len(p.conns) != 2 || p.conns["fresh"] == nil {
		t.Errorf("p.conns = %d entries, want fresh + mixed", len(p.conns))
	}
	if cs := p.conns["mixed"]; cs == nil || len(cs.reqs) != 1 {
		t.Errorf("mixed conn = %+v, want its one fresh request kept", cs)
	}
}

// TestMaxPendingCapEvicts is the p.conns/p.dns analogue of
// TestMaxFlowsCapEvicts: a capture that only ever sees requests (or queries)
// must not grow the pairing maps without bound between gc cycles.
func TestMaxPendingCapEvicts(t *testing.T) {
	orig := maxPending
	maxPending = 4
	defer func() { maxPending = orig }()

	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	for i := 0; i < 20; i++ {
		p.enqueueRequestOnly("c"+strconv.Itoa(i), api.ProtocolHTTP, api.Payload{}, api.Endpoint{}, api.Endpoint{})
	}
	p.mu.Lock()
	nConns := len(p.conns)
	// p.mongo/p.kafka are only inserted into from dissectors this file doesn't
	// own, so their ceiling is enforced by gc's trim rather than at insert.
	for i := 0; i < 20; i++ {
		p.mongo["m"+strconv.Itoa(i)] = &mongoPending{ts: time.Now()}
		p.kafka["k"+strconv.Itoa(i)] = &kafkaPending{ts: time.Now()}
	}
	p.mu.Unlock()
	if nConns > maxPending {
		t.Errorf("len(p.conns) = %d, want <= maxPending (%d)", nConns, maxPending)
	}

	p.gc()

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.mongo) > maxPending || len(p.kafka) > maxPending {
		t.Errorf("after gc: mongo=%d kafka=%d, want both <= %d", len(p.mongo), len(p.kafka), maxPending)
	}
}

// TestFlushFlowsBatchedReap covers the batched flushFlows rewrite across more
// flows than one gcDeleteBatch: every idle flow is emitted exactly once and
// removed, and a flow that is still active is left alone.
func TestFlushFlowsBatchedReap(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	idleTS := time.Now().Add(-time.Minute)

	const n = gcDeleteBatch + 17
	p.flowMu.Lock()
	for i := 0; i < n; i++ {
		reqNet, reqTr, _, _ := flows(46000+i, 80)
		f := newFlow(api.ProtocolTCP, reqNet, reqTr, idleTS)
		p.flows[connKey(reqNet, reqTr)] = f
	}
	activeNet, activeTr, _, _ := flows(47000, 80)
	activeKey := connKey(activeNet, activeTr)
	p.flows[activeKey] = newFlow(api.ProtocolTCP, activeNet, activeTr, time.Now())
	p.flowMu.Unlock()

	p.flushFlows(20 * time.Second)

	got := drain(s)
	if len(got) != n {
		t.Errorf("emitted %d idle flows, want %d", len(got), n)
	}
	p.flowMu.Lock()
	defer p.flowMu.Unlock()
	if len(p.flows) != 1 || p.flows[activeKey] == nil {
		t.Errorf("p.flows = %d entries, want only the still-active flow", len(p.flows))
	}
}

// TestExtractL4MetaIsAllocationFree pins the point of the restructure: the
// function that runs for every single captured TCP packet must not build any
// strings — no MAC formatting, no fragment-flag join, and above all no
// hexdump. All of those are per-flow values rendered later, in trackTCP.
func TestExtractL4MetaIsAllocationFree(t *testing.T) {
	pkt, _ := mkPacketMeta(t, "02:00:00:00:00:31", "02:00:00:00:00:32", 64, true)
	var m l4meta
	if n := testing.AllocsPerRun(200, func() { m = extractL4Meta(pkt) }); n != 0 {
		t.Errorf("extractL4Meta allocated %v times per packet, want 0", n)
	}
	if m.eth == nil || m.ip4 == nil || m.tcp == nil || m.ipVersion != 4 || m.ttl != 64 {
		t.Errorf("extractL4Meta returned %+v, want the decoded eth/ip4/tcp layers plus v4/ttl 64", m)
	}
}
