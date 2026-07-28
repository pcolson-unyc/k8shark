package hub

import (
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pablocolson/k8shark/pkg/api"
)

// pcapSnaplen is the snap length recorded in the pcap global header. Frames are
// synthesized from bounded L7 payloads so they never approach this, but a full
// 65535 keeps Wireshark from flagging captures as truncated.
const pcapSnaplen = 65535

// Fallback MACs when an entry carries no L4 metadata (e.g. eBPF-decrypted TLS
// streams, which have no L2 header). Locally-administered addresses so they
// can't be confused with real hardware. Mirrors ui/src/pcap.ts.
var (
	fallbackMACClient = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	fallbackMACServer = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
)

// handlePcap serves GET /api/pcap?filter=&since=&until=&limit=. It replays the
// matching slice of the ring buffer as synthesized Ethernet/IPv4/TCP/UDP/ICMP
// frames and streams a classic libpcap (.pcap) file (magic 0xa1b2c3d4), so an
// operator — or an AI agent via the MCP export tool — can open the captured L7
// exchanges in Wireshark/tshark.
//
// k8shark retains only bounded L7 payload bytes (RawView), never full frames,
// so each entry becomes a *synthesized* request/response pair: real endpoints
// and, when known, real L4 metadata (MACs, TTL, TCP seq/ack/window), but
// reconstructed headers — not a wire capture. Ports it from the client-side
// ui/src/pcap.ts synthesis. IPv6 entries are skipped (an IPv4 header can't
// carry them) rather than emitted as malformed frames.
func (s *Server) handlePcap(w http.ResponseWriter, r *http.Request) {
	// Reuse the shared ?filter=&since=&until= parsing; an unknown IFL field is
	// a compile error surfaced as 400, never a silent match-nothing.
	pred, err := s.queryPredicate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Bound the export: default to the whole buffer, overridable (and clamped
	// to the buffer) via ?limit= for a smaller slice.
	limit := s.store.capacity
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = clampInt(n, 1, s.store.capacity)
		}
	}
	entries := s.store.recent(limit, pred) // newest first

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="k8shark.pcap"`)

	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(pcapSnaplen, layers.LinkTypeEthernet); err != nil {
		// The header is the first bytes written; if even that fails the client
		// is gone, so just log and stop (status is already committed).
		s.log.Warn("pcap header write failed", "err", err)
		return
	}
	// Emit oldest-first so the capture reads chronologically like a real one,
	// regardless of the newest-first order recent() returns.
	var ipID uint16
	for i := len(entries) - 1; i >= 0; i-- {
		s.writeEntryPackets(pw, entries[i], &ipID)
	}
}

// writeEntryPackets emits up to two frames for one entry: the client->server
// request bytes and the server->client response bytes, timestamped at the
// entry time and entry+elapsed respectively. A direction with no recoverable
// bytes is skipped (ICMP is the exception — an empty echo is still a packet).
func (s *Server) writeEntryPackets(pw *pcapgo.Writer, e *api.Entry, ipID *uint16) {
	reqBytes := pcapPayloadBytes(&e.Request)
	if len(reqBytes) > 0 || e.Protocol == api.ProtocolICMP {
		if frame, ok := buildFrame(e, true, reqBytes, 0, ipID); ok {
			s.writePcapPacket(pw, e.Timestamp, frame)
		}
	}
	respBytes := pcapPayloadBytes(&e.Response)
	if len(respBytes) > 0 {
		ts := e.Timestamp
		if e.ElapsedMs > 0 {
			ts = ts.Add(time.Duration(e.ElapsedMs) * time.Millisecond)
		}
		if frame, ok := buildFrame(e, false, respBytes, len(reqBytes), ipID); ok {
			s.writePcapPacket(pw, ts, frame)
		}
	}
}

func (s *Server) writePcapPacket(pw *pcapgo.Writer, ts time.Time, frame []byte) {
	ci := gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(frame), Length: len(frame)}
	if err := pw.WritePacket(ci, frame); err != nil {
		s.log.Debug("pcap packet write failed", "err", err)
	}
}

// transportKind picks the L4 protocol for an entry's synthesized frames.
type transportKind int

const (
	transportTCP transportKind = iota
	transportUDP
	transportICMP
)

func pcapTransport(p api.Protocol) transportKind {
	switch p {
	case api.ProtocolDNS, api.ProtocolUDP:
		return transportUDP
	case api.ProtocolICMP:
		return transportICMP
	default:
		return transportTCP // http/redis/valkey/postgres/amqp/tcp all ride TCP
	}
}

// buildFrame synthesizes one Ethernet+IPv4+L4 frame for a single direction of
// an entry's exchange (forward = client->server request). reqLen is the request
// payload length, used to advance the response's TCP ack. It reports false —
// skip, don't emit garbage — when either endpoint isn't a parseable IPv4
// address (e.g. IPv6 traffic) or serialization fails.
func buildFrame(e *api.Entry, forward bool, payload []byte, reqLen int, ipID *uint16) ([]byte, bool) {
	var fromIP, toIP string
	var fromPort, toPort int
	if forward {
		fromIP, toIP = e.Source.IP, e.Destination.IP
		fromPort, toPort = e.Source.Port, e.Destination.Port
	} else {
		fromIP, toIP = e.Destination.IP, e.Source.IP
		fromPort, toPort = e.Destination.Port, e.Source.Port
	}
	from4 := parseIPv4(fromIP)
	to4 := parseIPv4(toIP)
	if from4 == nil || to4 == nil {
		return nil, false
	}

	srcMAC, dstMAC := frameMACs(e.L4, forward)
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ttl := uint8(64)
	if e.L4 != nil && e.L4.TTL > 0 {
		ttl = uint8(e.L4.TTL)
	}
	*ipID++
	ip := &layers.IPv4{
		Version: 4,
		IHL:     5,
		TTL:     ttl,
		Id:      *ipID,
		Flags:   layers.IPv4DontFragment,
		SrcIP:   from4,
		DstIP:   to4,
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()

	switch pcapTransport(e.Protocol) {
	case transportUDP:
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: layers.UDPPort(fromPort), DstPort: layers.UDPPort(toPort)}
		_ = udp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
			return nil, false
		}
	case transportICMP:
		ip.Protocol = layers.IPProtocolICMPv4
		typ := uint8(layers.ICMPv4TypeEchoReply)
		if forward {
			typ = layers.ICMPv4TypeEchoRequest
		}
		icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, 0)}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(payload)); err != nil {
			return nil, false
		}
	default: // TCP
		ip.Protocol = layers.IPProtocolTCP
		seqBase, ackBase, window := tcpSeeds(e.L4)
		// Best-effort seq/ack: the response acks the request's payload length.
		// Real per-direction tracking isn't available per-entry, so this is an
		// approximation, not a captured stream.
		seq, ack := seqBase, ackBase
		if !forward {
			seq = ackBase
			ack = seqBase + uint32(reqLen)
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(fromPort),
			DstPort: layers.TCPPort(toPort),
			Seq:     seq,
			Ack:     ack,
			Window:  window,
			PSH:     true, // a generic "here's some data" segment
			ACK:     true,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			return nil, false
		}
	}
	return buf.Bytes(), true
}

// tcpSeeds derives the initial seq/ack/window from an entry's L4 metadata,
// falling back to zeros and a typical advertised window when absent.
func tcpSeeds(l4 *api.L4Info) (seq, ack uint32, window uint16) {
	window = 64240
	if l4 == nil {
		return 0, 0, window
	}
	if l4.Window > 0 {
		window = uint16(l4.Window)
	}
	return l4.SeqStart, l4.AckStart, window
}

// frameMACs returns the src/dst MACs for a direction, using the entry's real
// captured MACs when present and locally-administered fallbacks otherwise.
func frameMACs(l4 *api.L4Info, forward bool) (src, dst net.HardwareAddr) {
	var srcRaw, dstRaw string
	if l4 != nil {
		if forward {
			srcRaw, dstRaw = l4.SrcMAC, l4.DstMAC
		} else {
			srcRaw, dstRaw = l4.DstMAC, l4.SrcMAC
		}
	}
	if forward {
		return parseMAC(srcRaw, fallbackMACClient), parseMAC(dstRaw, fallbackMACServer)
	}
	return parseMAC(srcRaw, fallbackMACServer), parseMAC(dstRaw, fallbackMACClient)
}

func parseMAC(s string, fallback net.HardwareAddr) net.HardwareAddr {
	if s != "" {
		if m, err := net.ParseMAC(s); err == nil && len(m) == 6 {
			return m
		}
	}
	return fallback
}

// parseIPv4 returns the 4-byte form of s, or nil for an unparseable address or
// an IPv6 one (which an IPv4 header can't represent).
func parseIPv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// pcapPayloadBytes recovers one direction's application bytes for the
// synthesized frame: the real captured bytes from RawView or the decoded body,
// whichever carries more bytes, else the one-line summary so an entry without
// either still contributes readable content. Mirrors ui/src/pcap.ts
// payloadBytes.
func pcapPayloadBytes(p *api.Payload) []byte {
	if p == nil {
		return nil
	}
	var raw []byte
	switch {
	case p.Raw == nil:
	case len(p.Raw.Data) > 0:
		// Current workers ship the bytes directly (base64 on the wire).
		raw = p.Raw.Data
	case p.Raw.Hex != "":
		// Legacy path: a worker older than this hub pre-rendered the sample as
		// a hexdump -C block, so decode it back. Kept for rolling upgrades and
		// for replaying entries captured by an older build.
		raw = parseHexDump(p.Raw.Hex)
	}
	// Raw and Body are capped independently (worker raw-capture cap vs. the
	// body cap), so Raw can be a much SHORTER sample of the same exchange than
	// the body the hub already holds — preferring Raw unconditionally would let
	// a lowered raw-capture cap silently degrade the export. Pick whichever
	// source carries more bytes, keeping Raw on a tie: Raw is the byte-exact
	// capture, whereas Body has been through decompression/text handling and
	// isn't byte-exact for binary protocols, so at equal length Raw is the more
	// faithful source. Only the lengths are compared — the two views are never
	// merged, since they don't necessarily cover the same bytes.
	if len(raw) > 0 && len(raw) >= len(p.Body) {
		return raw
	}
	text := p.Body
	if text == "" {
		text = p.Summary
	}
	if text == "" {
		// Unreachable with a non-empty raw (that would have won the tie above),
		// so there is nothing left to emit for this direction.
		return nil
	}
	return []byte(text)
}

var (
	// hexOffsetRE matches the leading "<8-hex offset>  " column of a hexdump line.
	hexOffsetRE = regexp.MustCompile(`^[0-9a-f]{8}\s+`)
	// hexByteRE matches a single "hh" byte token in the hex column.
	hexByteRE = regexp.MustCompile(`[0-9a-f]{2}`)
)

// parseHexDump reverses hexdump.go's "hexdump -C"-style block back into raw
// bytes. Each line is "<8-hex offset>  <hex bytes>  |<ascii>|"; splitting on
// " |" drops the ascii column so text there that happens to look like hex
// pairs is never mistaken for a byte. Mirrors ui/src/pcap.ts parseHexDump.
func parseHexDump(dump string) []byte {
	var out []byte
	for _, line := range strings.Split(dump, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		hexPart := line
		if idx := strings.Index(line, " |"); idx >= 0 {
			hexPart = line[:idx]
		}
		hexPart = hexOffsetRE.ReplaceAllString(hexPart, "")
		for _, tok := range hexByteRE.FindAllString(hexPart, -1) {
			if b, err := strconv.ParseUint(tok, 16, 8); err == nil {
				out = append(out, byte(b))
			}
		}
	}
	return out
}
