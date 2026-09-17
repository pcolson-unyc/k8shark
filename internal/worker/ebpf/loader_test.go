//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestDecodeEventWithTuple verifies decodeEvent's hand-computed offsets against
// a crafted struct event, including the Phase 2b 4-tuple fields. The offsets
// must match bpf/tls.bpf.c's struct event layout exactly.
func TestDecodeEventWithTuple(t *testing.T) {
	data := []byte("hello")
	raw := make([]byte, eventOffData+len(data))
	binary.LittleEndian.PutUint32(raw[eventOffPID:], 100)
	binary.LittleEndian.PutUint32(raw[eventOffTID:], 7)
	binary.LittleEndian.PutUint64(raw[eventOffSSLCtx:], 42)
	copy(raw[eventOffSAddr:], []byte{10, 0, 0, 1}) // network-order IPv4 10.0.0.1
	copy(raw[eventOffDAddr:], []byte{10, 0, 0, 2}) // 10.0.0.2
	binary.LittleEndian.PutUint32(raw[eventOffDataLen:], uint32(len(data)))
	binary.LittleEndian.PutUint16(raw[eventOffSPort:], 54321)
	binary.LittleEndian.PutUint16(raw[eventOffDPort:], 5432)
	raw[eventOffFamily] = afInet
	raw[eventOffDirection] = byte(TLSDirWrite)
	copy(raw[eventOffData:], data)

	rec, err := decodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PID != 100 || rec.TID != 7 || rec.ConnID != 42 {
		t.Errorf("pid/tid/conn = %d/%d/%d, want 100/7/42", rec.PID, rec.TID, rec.ConnID)
	}
	if rec.Direction != TLSDirWrite {
		t.Errorf("direction = %d, want write", rec.Direction)
	}
	if rec.SrcIP != "10.0.0.1" || rec.DstIP != "10.0.0.2" {
		t.Errorf("ips = %s -> %s, want 10.0.0.1 -> 10.0.0.2", rec.SrcIP, rec.DstIP)
	}
	if rec.SrcPort != 54321 || rec.DstPort != 5432 {
		t.Errorf("ports = %d -> %d, want 54321 -> 5432", rec.SrcPort, rec.DstPort)
	}
	if string(rec.Data) != "hello" {
		t.Errorf("data = %q, want hello", rec.Data)
	}
}

// TestDecodeEventWithIPv6Tuple mirrors TestDecodeEventWithTuple for an
// AF_INET6 tuple (CAP-7): the full 16-byte saddr/daddr must be read, not just
// the first 4 bytes as for AF_INET.
func TestDecodeEventWithIPv6Tuple(t *testing.T) {
	data := []byte("hello")
	raw := make([]byte, eventOffData+len(data))
	binary.LittleEndian.PutUint32(raw[eventOffPID:], 100)
	binary.LittleEndian.PutUint32(raw[eventOffTID:], 7)
	binary.LittleEndian.PutUint64(raw[eventOffSSLCtx:], 42)
	srcIP := net.ParseIP("2001:db8::1").To16()
	dstIP := net.ParseIP("2001:db8::2").To16()
	copy(raw[eventOffSAddr:], srcIP)
	copy(raw[eventOffDAddr:], dstIP)
	binary.LittleEndian.PutUint32(raw[eventOffDataLen:], uint32(len(data)))
	binary.LittleEndian.PutUint16(raw[eventOffSPort:], 54321)
	binary.LittleEndian.PutUint16(raw[eventOffDPort:], 443)
	raw[eventOffFamily] = afInet6
	raw[eventOffDirection] = byte(TLSDirRead)
	copy(raw[eventOffData:], data)

	rec, err := decodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SrcIP != "2001:db8::1" || rec.DstIP != "2001:db8::2" {
		t.Errorf("ips = %s -> %s, want 2001:db8::1 -> 2001:db8::2", rec.SrcIP, rec.DstIP)
	}
	if rec.SrcPort != 54321 || rec.DstPort != 443 {
		t.Errorf("ports = %d -> %d, want 54321 -> 443", rec.SrcPort, rec.DstPort)
	}
	if string(rec.Data) != "hello" {
		t.Errorf("data = %q, want hello", rec.Data)
	}
}

// TestDecodeEventUnresolvedTuple: a zero 4-tuple (kprobe hasn't resolved the
// socket yet) leaves SrcIP/DstIP empty so the caller keeps the synthetic
// endpoint.
func TestDecodeEventUnresolvedTuple(t *testing.T) {
	raw := make([]byte, eventOffData)
	binary.LittleEndian.PutUint32(raw[eventOffPID:], 5)
	raw[eventOffDirection] = byte(TLSDirRead)
	rec, err := decodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SrcIP != "" || rec.DstIP != "" {
		t.Errorf("ips = %q/%q, want empty (unresolved)", rec.SrcIP, rec.DstIP)
	}
}

// TestDecodeEventUnknownFamilyIgnoresAddr guards against a family byte that is
// neither AF_INET nor AF_INET6 (should never happen — record_tuple only ever
// stores one of the two — but decodeEvent must not misread garbage as an
// IPv4/IPv6 address if it ever does).
func TestDecodeEventUnknownFamilyIgnoresAddr(t *testing.T) {
	raw := make([]byte, eventOffData)
	copy(raw[eventOffSAddr:], []byte{10, 0, 0, 1})
	raw[eventOffFamily] = 99
	rec, err := decodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SrcIP != "" || rec.DstIP != "" {
		t.Errorf("ips = %q/%q, want empty (unknown family)", rec.SrcIP, rec.DstIP)
	}
}

func TestDecodeEventPayloadBoundaries(t *testing.T) {
	for _, n := range []int{1, 16383, 16384, 16385} {
		raw := make([]byte, eventOffData+n)
		binary.LittleEndian.PutUint32(raw[eventOffDataLen:], uint32(n))
		for i := range raw[eventOffData:] {
			raw[eventOffData+i] = byte(i)
		}
		rec, err := decodeEvent(raw)
		if err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		if len(rec.Data) != n || rec.Lagged {
			t.Errorf("length %d: got data=%d lagged=%v", n, len(rec.Data), rec.Lagged)
		}
	}
}

func TestDecodeEventLaggedTombstone(t *testing.T) {
	raw := make([]byte, eventOffData)
	binary.LittleEndian.PutUint32(raw[eventOffDataLen:], eventFlagLagged)
	rec, err := decodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Lagged || len(rec.Data) != 0 {
		t.Fatalf("tombstone = lagged=%v data=%d, want lagged with no data", rec.Lagged, len(rec.Data))
	}
}

func TestLossMarkerRetriesFullQueueAndSuppressesTail(t *testing.T) {
	out := make(chan TLSRecord, 1)
	out <- TLSRecord{ConnID: 99}
	lagged := map[uint64]bool{}
	ev := TLSRecord{ConnID: 42, Data: []byte("must not reach parser")}
	forwardLoss(out, lagged, ev)
	if sent, ok := lagged[42]; !ok || sent {
		t.Fatal("full queue must leave loss marker pending")
	}
	<-out
	forwardLoss(out, lagged, ev)
	marker := <-out
	if !marker.Lagged || marker.ConnID != 42 || len(marker.Data) != 0 {
		t.Fatalf("invalid marker: %+v", marker)
	}
	forwardLoss(out, lagged, ev)
	if len(out) != 0 {
		t.Fatal("tail forwarded after delivered loss marker")
	}
}

func TestTerminalEventDoesNotCopyPayload(t *testing.T) {
	raw := make([]byte, eventOffData+16384)
	binary.LittleEndian.PutUint32(raw[eventOffDataLen:], eventFlagLagged|16384)
	rec, err := decodeEvent(raw)
	if err != nil || !rec.Lagged || len(rec.Data) != 0 {
		t.Fatalf("terminal decode: %+v, %v", rec, err)
	}
}
