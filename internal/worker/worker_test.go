package worker

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pablocolson/k8shark/pkg/api"
)

// capturePorts is what feeds the kernel-level BPF filter (see
// internal/worker/capture/bpf.go) — a port missing here never reaches
// userspace at all, unlike buildRespPorts/buildAMQPPorts which only affect
// dispatch after the kernel has already let the packet through.
func TestCapturePortsDefaults(t *testing.T) {
	got := capturePorts(Options{})
	wantTCP := map[int]bool{80: true, 8080: true, redisPort: true, pgPort: true, amqpPort: true, dnsPort: true, mysqlPort: true, mongoPort: true, kafkaPort: true}
	if len(got.TCP) != len(wantTCP) {
		t.Fatalf("TCP ports = %v, want the %d defaults", got.TCP, len(wantTCP))
	}
	for _, p := range got.TCP {
		if !wantTCP[p] {
			t.Errorf("unexpected default TCP port %d", p)
		}
	}
	if len(got.UDP) != 1 || got.UDP[0] != 53 {
		t.Errorf("UDP ports = %v, want [53]", got.UDP)
	}
}

func TestCapturePortsMergesOperatorOverrides(t *testing.T) {
	got := capturePorts(Options{
		RedisPorts:  []int{7000},
		ValkeyPorts: []int{7001},
		AMQPPorts:   []int{5673},
		HTTPPorts:   []int{3000, 8080}, // 8080 duplicates a default on purpose
	})
	want := map[int]bool{
		80: true, 8080: true, redisPort: true, pgPort: true, amqpPort: true, dnsPort: true,
		mysqlPort: true, mongoPort: true, kafkaPort: true,
		7000: true, 7001: true, 5673: true, 3000: true,
	}
	if len(got.TCP) != len(want) {
		t.Fatalf("TCP ports = %v, want exactly %v (duplicates must not double up)", got.TCP, want)
	}
	for _, p := range got.TCP {
		if !want[p] {
			t.Errorf("unexpected TCP port %d", p)
		}
	}
}

// mkICMPv6Packet builds a real Ethernet+IPv6+ICMPv6 wire packet (checksums
// computed over the IPv6 pseudo-header, as RFC 4443 requires) and decodes it
// back exactly as capture.NewLive's gopacket.NewPacketSource would off the
// wire — an end-to-end fixture for route(), not just the handler.
func mkICMPv6Packet(t *testing.T, src, dst string, tc layers.ICMPv6TypeCode) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP(dst),
	}
	icmp6 := &layers.ICMPv6{TypeCode: tc}
	if err := icmp6.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, icmp6, gopacket.Payload("probe")); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestRouteDispatchesICMPv6 is the CAP-7 regression test: before, route() only
// recognised layers.LayerTypeICMPv4, so ping6/unreachable-v6 packets fell
// through to nothing at all (not even a generic L4 flow, since ICMPv6 isn't
// TCP/UDP either) — dual-stack/IPv6-only traffic was silently invisible.
func TestRouteDispatchesICMPv6(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())

	tc := layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeNoRouteToDst)
	pkt := mkICMPv6Packet(t, "2001:db8::1", "2001:db8::2", tc)
	p.route(nil, pkt)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Protocol != api.ProtocolICMP {
		t.Errorf("protocol = %q, want icmp", e.Protocol)
	}
	if e.Status != "error" {
		t.Errorf("status = %q, want error (destination unreachable)", e.Status)
	}
	if e.Source.IP != "2001:db8::1" || e.Destination.IP != "2001:db8::2" {
		t.Errorf("src/dst = %s/%s, want 2001:db8::1/2001:db8::2", e.Source.IP, e.Destination.IP)
	}
}

// TestICMP6DescSeverity checks the RFC 4443 type -> status mapping mirrors
// icmpDesc's v4 severities (unreachable/time-exceeded => error, packet-too-big/
// redirect => warning, everything else — echo, neighbor discovery, MLD =>
// success).
func TestICMP6DescSeverity(t *testing.T) {
	cases := []struct {
		typ  uint8
		want string
	}{
		{layers.ICMPv6TypeDestinationUnreachable, "error"},
		{layers.ICMPv6TypeTimeExceeded, "error"},
		{layers.ICMPv6TypePacketTooBig, "warning"},
		{layers.ICMPv6TypeRedirect, "warning"},
		{layers.ICMPv6TypeEchoRequest, "success"},
		{layers.ICMPv6TypeEchoReply, "success"},
		{layers.ICMPv6TypeNeighborSolicitation, "success"},
	}
	for _, c := range cases {
		_, status := icmp6Desc(layers.CreateICMPv6TypeCode(c.typ, 0))
		if status != c.want {
			t.Errorf("icmp6Desc(type %d) status = %q, want %q", c.typ, status, c.want)
		}
	}
}
