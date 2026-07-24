package worker

import (
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

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
	meta := l4meta{srcMAC: "02:00:00:00:00:01", dstMAC: "02:00:00:00:00:02", ipVersion: 4, ttl: 64, ipFlags: "DF", headerHex: "hdr"}
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
	if info.SrcMAC != "02:00:00:00:00:01" || info.TTL != 64 || info.IPFlags != "DF" || info.HeaderHex != "hdr" {
		t.Errorf("L3 meta not copied: %+v", info)
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
	meta := l4meta{srcMAC: "02:00:00:00:00:0a", ipVersion: 4, ttl: 128}

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
	if !strings.Contains(raw.Hex, "hello") {
		t.Errorf("raw.Hex = %q, want it to contain the captured payload text", raw.Hex)
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
