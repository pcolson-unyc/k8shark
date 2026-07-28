package worker

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pablocolson/k8shark/pkg/api"
)

// flowState accumulates L4 metadata for one connection/flow that is not L7
// dissected. TCP flows are emitted on close (FIN/RST) or idle timeout; UDP flows
// on idle timeout.
type flowState struct {
	proto     api.Protocol
	src, dst  api.Endpoint
	firstSeen time.Time
	lastSeen  time.Time
	packets   int64
	bytes     int64
	synSeen   bool
	finSeen   bool
	rstSeen   bool
	l7        bool // dissected by an L7 parser -> never emit a generic flow
	emitted   bool // already emitted on close -> don't re-emit

	// clientNetEP/clientTrEP are the gopacket endpoints of the client side of
	// the flow, recorded when the orientation is decided (newFlow). trackTCP's
	// per-packet "is this client->server?" test compares against these — a pair
	// of comparable fixed-size structs — instead of rebuilding the IP string
	// and re-parsing the port out of a string on every single packet.
	// f.src/f.dst keep the rendered string/int form regardless: buildL4Info and
	// emitFlow ship those over the wire.
	clientNetEP gopacket.Endpoint
	clientTrEP  gopacket.Endpoint

	// L3 header (copied once from the first packet's l4meta)
	srcMAC, dstMAC string
	ipVersion      int
	ttl            int
	ipFlags        string
	headerHex      string

	// TCP handshake samples & per-direction accounting
	clientFlags, serverFlags     flagSet
	seqStart, ackStart           uint32
	window, mss                  int
	synTS, synAckTS              time.Time
	retransmits                  int
	nextSeqClient, nextSeqServer uint32 // expected next seq per direction
	haveSeqClient, haveSeqServer bool
	clientBytes, serverBytes     int64
	clientPackets, serverPackets int64

	// rawBuf samples this flow's payload bytes (either direction, up to
	// rawCap total — there's no clean request/response split to preserve
	// separately for an undissected flow) for the Raw tab. rawTotal tracks
	// how much payload was actually seen, for the truncated flag.
	rawBuf   []byte
	rawTotal int

	// Last payload-bearing segment seen per direction, for CAP-8 same-packet
	// dedup (see dedupWindow) — AF_PACKET on the "any" interface can observe
	// one physical packet more than once on a CNI-overlay node.
	lastClientSeg, lastServerSeg segFingerprint
}

// dedupWindow bounds how recently a payload-bearing packet with the same
// (direction, seq, len) must have been seen for a repeat to be treated as the
// same wire packet observed via a second/third capture point rather than a
// genuine retransmission (CAP-8). AF_PACKET on the "any" interface sees every
// interface on the host, so on a CNI-overlay node the identical packet can be
// delivered more than once — once per interface it crosses (the physical
// NIC, the CNI's vxlan/overlay interface, the destination pod's veth). Those
// deliveries are a kernel-internal, same-host hand-off, microseconds apart —
// never a real network round trip. A genuine retransmit needs at least one:
// Linux's minimum RTO is 200ms, and even a fast retransmit (triggered by
// duplicate ACKs) needs several real network round trips for those ACKs to
// reach the sender first. dedupWindow only has to separate "same host,
// different interface" from "actually went out over the wire and back" — 5ms
// is generous headroom over the former and nowhere near the latter on any
// real network.
const dedupWindow = 5 * time.Millisecond

// segFingerprint identifies one payload-bearing TCP segment by its byte
// range, to recognise the same packet arriving again via a different capture
// point (see dedupWindow).
type segFingerprint struct {
	seq uint32
	len int
	at  time.Time
}

// seenRecently reports whether seq/len matches the last recorded fingerprint
// within dedupWindow — and if not, records this packet as the new "last
// seen". A detected duplicate leaves the recorded fingerprint untouched, so a
// third delivery of the same packet still compares against the original
// arrival instead of the second one.
func (fp *segFingerprint) seenRecently(seq uint32, length int, ts time.Time) bool {
	if !fp.at.IsZero() && fp.seq == seq && fp.len == length && ts.Sub(fp.at) < dedupWindow {
		return true
	}
	*fp = segFingerprint{seq: seq, len: length, at: ts}
	return false
}

// rawView snapshots the flow's sampled payload as a RawView, or nil if none
// was captured (raw capture disabled, or a flow with no payload bytes, e.g.
// a bare SYN/FIN handshake).
//
// The bytes are copied because f.rawBuf keeps being appended to for the life of
// the flow, while the emitted entry is marshaled later on the sink goroutine.
func (f *flowState) rawView() *api.RawView {
	if len(f.rawBuf) == 0 {
		return nil
	}
	return &api.RawView{
		Data:      append([]byte(nil), f.rawBuf...),
		Bytes:     f.rawTotal,
		Truncated: f.rawTotal > len(f.rawBuf),
	}
}

// captureRaw appends up to rawCap total bytes of payload into f.rawBuf,
// tracking the true total in rawTotal regardless of the cap. No-op once
// disabled (rawCap < 0) or the cap is already reached.
func (f *flowState) captureRaw(payload []byte, rawCap int) {
	if len(payload) == 0 || rawCap < 0 {
		return
	}
	f.rawTotal += len(payload)
	if room := rawCap - len(f.rawBuf); room > 0 {
		take := len(payload)
		if take > room {
			take = room
		}
		f.rawBuf = append(f.rawBuf, payload[:take]...)
	}
}

func (f *flowState) flagStr() string {
	var fl []string
	if f.synSeen {
		fl = append(fl, "SYN")
	}
	if f.finSeen {
		fl = append(fl, "FIN")
	}
	if f.rstSeen {
		fl = append(fl, "RST")
	}
	return strings.Join(fl, ",")
}

// newFlow initialises a flow, orienting src->dst as client->server using the
// heuristic that the ephemeral (higher) port is the client.
func newFlow(proto api.Protocol, netFlow, transport gopacket.Flow, ts time.Time) *flowState {
	sp := portOf(transport.Src().String())
	dp := portOf(transport.Dst().String())
	var src, dst api.Endpoint
	var cliNet, cliTr gopacket.Endpoint
	if sp >= dp {
		src = api.Endpoint{IP: netFlow.Src().String(), Port: sp}
		dst = api.Endpoint{IP: netFlow.Dst().String(), Port: dp}
		cliNet, cliTr = netFlow.Src(), transport.Src()
	} else {
		src = api.Endpoint{IP: netFlow.Dst().String(), Port: dp}
		dst = api.Endpoint{IP: netFlow.Src().String(), Port: sp}
		cliNet, cliTr = netFlow.Dst(), transport.Dst()
	}
	return &flowState{
		proto: proto, src: src, dst: dst,
		clientNetEP: cliNet, clientTrEP: cliTr,
		firstSeen: ts, lastSeen: ts,
	}
}

// maxFlows bounds p.flows so a burst of new connections — a SYN flood, a
// port scan against a still-open port (the cBPF kernel filter already blocks
// most scan traffic outright, see afpacket_linux.go's l7Filter) — can't grow
// the flow-accounting map without limit in between flushFlows cycles (every
// 15s). reqBacklogCap bounds the analogous per-connection backlog the same
// way. A var (not a const) only so tests can shrink it; production code
// never assigns to it.
var maxFlows = 100000

// evictOverCapLocked drops one entry if m is over cap, bumping counter (when
// non-nil) for each eviction. It picks whichever key a single map iteration
// step yields rather than scanning for the actual oldest entry: a full scan
// would itself cost O(len(m)) per insert once at cap, which is exactly the
// kind of unbounded CPU work a flood should not be able to trigger. The
// periodic sweeps (flushFlows for p.flows, gc for the pairing maps) already
// reap stale entries properly, by timestamp, every 15s; this cap only matters
// for the burst between those cycles. Callers must hold the mutex guarding m.
func evictOverCapLocked[V any](m map[string]V, cap int, counter *atomic.Uint64) {
	if len(m) <= cap {
		return
	}
	for k := range m {
		delete(m, k)
		if counter != nil {
			counter.Add(1)
		}
		return
	}
}

// evictOverCapLocked applies the cap above to p.flows. Callers must hold flowMu.
func (p *pipeline) evictOverCapLocked() {
	evictOverCapLocked(p.flows, maxFlows, &p.sink.flowsEvicted)
}

// markL7 flags a connection as L7-dissected so trackTCP won't emit a duplicate
// generic flow for it.
func (p *pipeline) markL7(key string) {
	p.flowMu.Lock()
	if f := p.flows[key]; f != nil {
		f.l7 = true
	} else {
		p.flows[key] = &flowState{l7: true}
		p.evictOverCapLocked()
	}
	p.flowMu.Unlock()
}

// trackTCP accounts one TCP packet, enriches the flow's L4 metadata and emits
// the flow when it closes.
func (p *pipeline) trackTCP(netFlow, transport gopacket.Flow, tcp *layers.TCP, length int, ts time.Time, meta l4meta) {
	key := connKey(netFlow, transport)
	var closed *flowState

	p.flowMu.Lock()
	f := p.flows[key]
	if f == nil {
		f = newFlow(api.ProtocolTCP, netFlow, transport, ts)
		p.flows[key] = f
		p.evictOverCapLocked()
	} else if f.firstSeen.IsZero() {
		// Was created by markL7 before any packet; fill in orientation.
		nf := newFlow(api.ProtocolTCP, netFlow, transport, ts)
		f.src, f.dst, f.firstSeen = nf.src, nf.dst, ts
		f.clientNetEP, f.clientTrEP = nf.clientNetEP, nf.clientTrEP
	}

	// Per-direction accounting. The flow is oriented client->server by newFlow,
	// so a packet whose (netFlow.Src, transport.Src) equals the recorded client
	// endpoints is client->server. gopacket.Endpoint is a comparable value
	// (type + length + a fixed-size zero-padded byte array), so == is an exact
	// match on the same bytes newFlow rendered f.src from — same answer as the
	// old string/port comparison, without formatting anything.
	clientToServer := netFlow.Src() == f.clientNetEP && transport.Src() == f.clientTrEP
	payloadLen := len(tcp.Payload)

	// CAP-8 dedup gate: a payload-bearing packet already seen on this
	// connection/direction/seq/len within dedupWindow is the same wire
	// packet delivered again via another host-local interface, not a
	// retransmission — skip it before any counting (bytes/packets/raw
	// sample/retransmit) double- or triple-counts it. Scoped to
	// payload-bearing packets: a zero-payload ACK/SYN/FIN can legitimately
	// repeat the same seq across genuinely distinct packets (e.g. a stalled
	// sender's keep-alive ACKs, or back-to-back duplicate ACKs triggering a
	// fast retransmit), so seq+len alone can't identify those as duplicates
	// the way it safely can for a specific slice of the byte stream. The
	// flow still counts as alive either way.
	if payloadLen > 0 {
		fp := &f.lastClientSeg
		if !clientToServer {
			fp = &f.lastServerSeg
		}
		if fp.seenRecently(tcp.Seq, payloadLen, ts) {
			f.lastSeen = ts
			p.flowMu.Unlock()
			return
		}
	}

	f.lastSeen = ts
	f.packets++
	f.bytes += int64(length)
	f.captureRaw(tcp.Payload, p.rawCap)

	// Copy the L3 header fields once (from whichever direction is seen first).
	// Rendering happens here, inside the "not filled in yet" guards and after
	// the CAP-8 dedup early-return above, rather than eagerly in extractL4Meta:
	// the MAC strings, the fragment flags and above all the header hexdump are
	// per-flow values, so paying for them per packet was pure waste. headerHex
	// is *not* dead for L7-dissected flows — snapshotL4 -> buildL4Info ships it
	// with every paired entry — so it still has to be computed exactly once per
	// flow, which is what this branch does.
	if f.srcMAC == "" && meta.eth != nil {
		f.srcMAC, f.dstMAC = meta.macStrings()
	}
	if f.ipVersion == 0 && meta.ipVersion != 0 {
		f.ipVersion, f.ttl, f.ipFlags = meta.ipVersion, meta.ttl, meta.ipFlagStr()
	}
	if f.headerHex == "" {
		f.headerHex = meta.renderHeaderHex(p.headerHexCap)
	}

	if clientToServer {
		f.clientBytes += int64(length)
		f.clientPackets++
		f.clientFlags |= tcpFlagSet(tcp)
		f.window = int(tcp.Window)
		if payloadLen > 0 {
			if f.haveSeqClient && tcp.Seq < f.nextSeqClient {
				f.retransmits++
			} else {
				f.nextSeqClient = tcp.Seq + uint32(payloadLen)
				f.haveSeqClient = true
			}
		}
		if tcp.SYN && !tcp.ACK {
			f.seqStart = tcp.Seq
			f.synTS = ts
			f.mss = parseMSS(tcp.Options)
			f.window = int(tcp.Window)
		}
	} else {
		f.serverBytes += int64(length)
		f.serverPackets++
		f.serverFlags |= tcpFlagSet(tcp)
		if payloadLen > 0 {
			if f.haveSeqServer && tcp.Seq < f.nextSeqServer {
				f.retransmits++
			} else {
				f.nextSeqServer = tcp.Seq + uint32(payloadLen)
				f.haveSeqServer = true
			}
		}
		if tcp.SYN && tcp.ACK {
			f.ackStart = tcp.Seq
			f.synAckTS = ts
		}
	}

	if tcp.SYN {
		f.synSeen = true
	}
	if tcp.FIN {
		f.finSeen = true
	}
	if tcp.RST {
		f.rstSeen = true
	}
	if (f.finSeen || f.rstSeen) && !f.emitted && !f.l7 {
		f.emitted = true
		cp := *f
		closed = &cp
	}
	p.flowMu.Unlock()

	if closed != nil {
		reason := "FIN"
		if closed.rstSeen {
			reason = "RST"
		}
		p.emitFlow(closed, reason)
	}
}

// parseMSS returns the MSS advertised in a SYN's TCP options, or 0.
func parseMSS(opts []layers.TCPOption) int {
	for _, o := range opts {
		if o.OptionType == layers.TCPOptionKindMSS && len(o.OptionData) == 2 {
			return int(o.OptionData[0])<<8 | int(o.OptionData[1])
		}
	}
	return 0
}

// buildL4Info renders a flowState copy into the wire L4Info. Returns nil if the
// flow never saw a packet (only a markL7 placeholder).
func buildL4Info(f *flowState) *api.L4Info {
	if f.firstSeen.IsZero() {
		return nil
	}
	info := &api.L4Info{
		SrcMAC: f.srcMAC, DstMAC: f.dstMAC, IPVersion: f.ipVersion,
		TTL: f.ttl, IPFlags: f.ipFlags,
		ClientTCPFlags: f.clientFlags.String(), ServerTCPFlags: f.serverFlags.String(),
		SeqStart: f.seqStart, AckStart: f.ackStart, Window: f.window, MSS: f.mss,
		Retransmits: f.retransmits, DurationMs: f.lastSeen.Sub(f.firstSeen).Milliseconds(),
		ClientBytes: f.clientBytes, ServerBytes: f.serverBytes,
		ClientPackets: f.clientPackets, ServerPackets: f.serverPackets,
		HeaderHex: f.headerHex,
	}
	if !f.synTS.IsZero() && !f.synAckTS.IsZero() {
		info.RTTMs = float64(f.synAckTS.Sub(f.synTS).Microseconds()) / 1000.0
	}
	return info
}

// snapshotL4 returns a copy of the L4Info for a connection, or nil if unknown.
// It takes only flowMu (never nested inside p.mu) to avoid lock-order deadlock.
func (p *pipeline) snapshotL4(key string) *api.L4Info {
	p.flowMu.Lock()
	f := p.flows[key]
	if f == nil || f.firstSeen.IsZero() {
		p.flowMu.Unlock()
		return nil
	}
	cp := *f
	p.flowMu.Unlock()
	return buildL4Info(&cp)
}

// trackUDP accounts one non-DNS UDP packet. UDP has no close signal, so these
// flows are emitted only by flushFlows on idle.
func (p *pipeline) trackUDP(netFlow, transport gopacket.Flow, length int, ts time.Time, payload []byte) {
	key := connKey(netFlow, transport)
	p.flowMu.Lock()
	f := p.flows[key]
	if f == nil {
		f = newFlow(api.ProtocolUDP, netFlow, transport, ts)
		p.flows[key] = f
		p.evictOverCapLocked()
	}
	f.lastSeen = ts
	f.packets++
	f.bytes += int64(length)
	f.captureRaw(payload, p.rawCap)
	p.flowMu.Unlock()
}

// handleICMP emits one entry per ICMPv4 packet (echo, unreachable, etc.).
func (p *pipeline) handleICMP(netFlow gopacket.Flow, icmp *layers.ICMPv4, length int, ts time.Time) {
	desc, status := icmpDesc(icmp.TypeCode)
	p.emitICMPEntry(netFlow, icmp.Payload, length, ts, desc, status)
}

// handleICMPv6 mirrors handleICMP for ICMPv6 (echo, destination unreachable,
// packet-too-big, neighbor discovery, ...) — route() couldn't dispatch these
// at all before CAP-7, so dual-stack/IPv6-only clusters saw silence where a
// v4 cluster would show a ping/unreachable entry.
func (p *pipeline) handleICMPv6(netFlow gopacket.Flow, icmp *layers.ICMPv6, length int, ts time.Time) {
	desc, status := icmp6Desc(icmp.TypeCode)
	p.emitICMPEntry(netFlow, icmp.Payload, length, ts, desc, status)
}

// emitICMPEntry builds and emits the api.Entry shared by the ICMPv4/ICMPv6
// handlers — everything but the type-code decoding is identical.
func (p *pipeline) emitICMPEntry(netFlow gopacket.Flow, payload []byte, length int, ts time.Time, desc, status string) {
	p.sink.emit(&api.Entry{
		ID:          p.node + "-icmp-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    api.ProtocolICMP,
		Timestamp:   ts,
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      api.Endpoint{IP: netFlow.Src().String()},
		Destination: api.Endpoint{IP: netFlow.Dst().String()},
		Request:     api.Payload{Summary: desc, Bytes: int64(length), Raw: rawViewFromBytes(payload, p.rawCap)},
		Response:    api.Payload{Summary: desc},
		Status:      status,
	})
}

// flushFlows emits flows idle longer than the timeout and reaps closed/L7 ones.
//
// The scan and the deletions are separated so flowMu — the lock trackTCP takes
// for every single captured packet — is never held across the whole map. At
// maxFlows that map holds 100 000 entries, and scanning *and* deleting them all
// under one acquisition stalls capture long enough to back tcpassembly up. The
// scan itself still needs the lock (iterating a map while another goroutine
// writes it is a fatal error), but the deletions are batched, releasing flowMu
// between batches. See gcDeleteBatch.
func (p *pipeline) flushFlows(idle time.Duration) {
	now := time.Now()
	var toEmit []*flowState
	var stale []string

	p.flowMu.Lock()
	for k, f := range p.flows {
		if f.emitted {
			stale = append(stale, k)
			continue
		}
		if now.Sub(f.lastSeen) > idle {
			if !f.l7 && !f.firstSeen.IsZero() {
				cp := *f
				toEmit = append(toEmit, &cp)
				// Mark it emitted *now*, while we still hold the lock and while
				// the copy is being taken. Between here and the delete pass
				// below the flow could receive a packet and stop looking idle;
				// without this flag the delete pass would (correctly) leave it
				// alone, and it would later be emitted a second time on close.
				f.emitted = true
			}
			stale = append(stale, k)
		}
	}
	p.flowMu.Unlock()

	for i := 0; i < len(stale); i += gcDeleteBatch {
		end := i + gcDeleteBatch
		if end > len(stale) {
			end = len(stale)
		}
		p.flowMu.Lock()
		for _, k := range stale[i:end] {
			// Re-check under the lock: flowMu was released between batches, so
			// a flow may have been refreshed by a new packet (or the key reused
			// by a brand-new connection) and must not be reaped. Anything
			// already flagged emitted is unconditionally reapable.
			if f := p.flows[k]; f != nil && (f.emitted || now.Sub(f.lastSeen) > idle) {
				delete(p.flows, k)
			}
		}
		p.flowMu.Unlock()
	}

	for _, f := range toEmit {
		p.emitFlow(f, "idle")
	}
}

func (p *pipeline) emitFlow(f *flowState, reason string) {
	status := "success"
	if f.rstSeen {
		status = "error"
	}
	p.sink.emit(&api.Entry{
		ID:          p.node + "-l4-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    f.proto,
		Timestamp:   f.firstSeen,
		ElapsedMs:   f.lastSeen.Sub(f.firstSeen).Milliseconds(),
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      f.src,
		Destination: f.dst,
		Request:     api.Payload{Summary: flowLabel(f), Packets: f.packets, Bytes: f.bytes, Flags: f.flagStr(), Raw: f.rawView()},
		Response:    api.Payload{Summary: reason + " · " + humanBytes(f.bytes) + " · " + strconv.FormatInt(f.packets, 10) + " pkts"},
		Status:      status,
		L4:          buildL4Info(f),
	})
}

// --- helpers ----------------------------------------------------------------

var wellKnownPorts = map[int]string{
	22: "ssh", 25: "smtp", 110: "pop3", 143: "imap", 443: "https", 587: "smtp",
	853: "dns-tls", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
	5672: "amqp", 6379: "redis", 8883: "mqtt", 9042: "cassandra", 9092: "kafka",
	11211: "memcached", 27017: "mongodb", 2379: "etcd", 2181: "zookeeper",
}

func flowLabel(f *flowState) string {
	if name := wellKnownPorts[f.dst.Port]; name != "" {
		return string(f.proto) + " " + name
	}
	return string(f.proto) + "/" + strconv.Itoa(f.dst.Port)
}

func icmpDesc(tc layers.ICMPv4TypeCode) (string, string) {
	switch tc.Type() {
	case layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4TypeTimeExceeded:
		return tc.String(), "error"
	case layers.ICMPv4TypeSourceQuench, layers.ICMPv4TypeRedirect:
		return tc.String(), "warning"
	default:
		return tc.String(), "success"
	}
}

// icmp6Desc mirrors icmpDesc for ICMPv6 (RFC 4443/4861): unreachable/
// time-exceeded are errors, packet-too-big/redirect are warnings (same
// severity intent as v4's source-quench/redirect), everything else — echo,
// neighbor/router discovery, MLD — is informational.
func icmp6Desc(tc layers.ICMPv6TypeCode) (string, string) {
	switch tc.Type() {
	case layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6TypeTimeExceeded:
		return tc.String(), "error"
	case layers.ICMPv6TypePacketTooBig, layers.ICMPv6TypeRedirect:
		return tc.String(), "warning"
	default:
		return tc.String(), "success"
	}
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<20:
		return strconv.FormatFloat(float64(b)/(1<<20), 'f', 1, 64) + " MB"
	case b >= 1<<10:
		return strconv.FormatFloat(float64(b)/(1<<10), 'f', 1, 64) + " KB"
	default:
		return strconv.FormatInt(b, 10) + " B"
	}
}
