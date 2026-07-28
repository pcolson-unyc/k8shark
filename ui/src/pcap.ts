import type { Entry, Payload } from "./types";
import { rawBytes } from "./rawView";

// pcap.ts synthesizes a classic libpcap (.pcap) file from entries already
// loaded client-side — same "export what's on screen" spirit as export.ts's
// CSV/JSON, not a live packet capture. k8shark doesn't retain full-frame
// bytes (see RawView: L7 payload only, bounded/truncated), so each entry's
// request/response becomes one *synthesized* Ethernet+IPv4+TCP/UDP/ICMP
// packet: real src/dst IP:port and, when available, real L4Info (MACs, TTL,
// TCP seq/ack/window/flags), but reconstructed headers, not a wire capture.
// Payload bytes are recovered from the entry's RawView when present (see
// rawView.ts, which handles both the current base64 form and the legacy
// pre-rendered hexdump), falling back to the decoded body/summary text. IPv6
// entries are skipped (not emitted) rather than writing a malformed IPv4
// packet — see ipv4Bytes.

const LINKTYPE_ETHERNET = 1;
const ETHERTYPE_IPV4 = 0x0800;
const PROTO_ICMP = 1;
const PROTO_TCP = 6;
const PROTO_UDP = 17;

// --- byte-level helpers ----------------------------------------------------

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// checksum16 is the standard IP/TCP/UDP ones-complement-of-ones-complement-
// sum-of-16-bit-words algorithm, shared by ipv4Header (over just the header)
// and tcpUdpChecksum (over a pseudo-header + segment).
function checksum16(bytes: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2) {
    const hi = bytes[i];
    const lo = i + 1 < bytes.length ? bytes[i + 1] : 0;
    sum += (hi << 8) | lo;
  }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function u16be(val: number): Uint8Array {
  return new Uint8Array([(val >>> 8) & 0xff, val & 0xff]);
}

function u32be(val: number): Uint8Array {
  return new Uint8Array([(val >>> 24) & 0xff, (val >>> 16) & 0xff, (val >>> 8) & 0xff, val & 0xff]);
}

function parseMac(mac: string | undefined, fallback: Uint8Array): Uint8Array {
  if (mac) {
    const parts = mac.split(":").map((h) => parseInt(h, 16));
    if (parts.length === 6 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      return new Uint8Array(parts);
    }
  }
  return fallback;
}

function ipv4Bytes(ip: string): Uint8Array | null {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return new Uint8Array(parts);
}

// payloadBytes recovers real captured bytes from the RawView (the common
// case: the worker's raw capture covers HTTP/Redis/Postgres/AMQP/DNS/generic
// L4 alike) or the decoded body, whichever carries more bytes, falling back to
// the summary text so an entry with neither still contributes readable content
// to the pcap.
//
// Raw and body are capped independently worker-side, so raw can be a much
// SHORTER sample of the same exchange than the body — preferring raw
// unconditionally would let a lowered raw-capture cap silently degrade the
// export. Ties go to raw: it is the byte-exact capture, whereas the body has
// been through decompression/text handling and isn't byte-exact for binary
// protocols, so at equal length raw is the more faithful source. Only lengths
// are compared — the two views are never merged, since they don't necessarily
// cover the same bytes. Mirrors hub pcapPayloadBytes.
function payloadBytes(p: Payload | undefined): Uint8Array {
  if (!p) return new Uint8Array(0);
  const raw = rawBytes(p.raw);
  // Encode first: the comparison must be byte-vs-byte, since a UTF-8 body is
  // longer in bytes than in JS string units.
  const body = p.body ? new TextEncoder().encode(p.body) : new Uint8Array(0);
  if (raw.length > 0 && raw.length >= body.length) return raw;
  if (body.length > 0) return body;
  return p.summary ? new TextEncoder().encode(p.summary) : new Uint8Array(0);
}

// --- header builders ---------------------------------------------------

function ipv4Header(
  srcIP: Uint8Array,
  dstIP: Uint8Array,
  protocol: number,
  payloadLen: number,
  ttl: number,
  id: number
): Uint8Array {
  const totalLen = 20 + payloadLen;
  const header = concatBytes([
    new Uint8Array([0x45, 0x00]), // version/IHL, TOS
    u16be(totalLen),
    u16be(id & 0xffff),
    new Uint8Array([0x40, 0x00]), // flags=DF, fragment offset 0
    new Uint8Array([ttl & 0xff, protocol & 0xff]),
    new Uint8Array([0, 0]), // checksum placeholder
    srcIP,
    dstIP,
  ]);
  const csum = checksum16(header);
  header[10] = (csum >>> 8) & 0xff;
  header[11] = csum & 0xff;
  return header;
}

// tcpUdpChecksum computes the TCP/UDP checksum over an IPv4 pseudo-header
// (src IP, dst IP, zero, protocol, segment length) followed by the segment
// itself (header with its checksum field zeroed, plus payload).
function tcpUdpChecksum(srcIP: Uint8Array, dstIP: Uint8Array, protocol: number, segment: Uint8Array): number {
  const pseudo = concatBytes([srcIP, dstIP, new Uint8Array([0, protocol]), u16be(segment.length)]);
  return checksum16(concatBytes([pseudo, segment]));
}

function tcpSegment(
  srcIP: Uint8Array,
  dstIP: Uint8Array,
  srcPort: number,
  dstPort: number,
  seq: number,
  ack: number,
  window: number,
  payload: Uint8Array
): Uint8Array {
  const flags = 0x18; // PSH+ACK: a generic "here's some data" segment
  const headerNoChecksum = concatBytes([
    u16be(srcPort),
    u16be(dstPort),
    u32be(seq >>> 0),
    u32be(ack >>> 0),
    new Uint8Array([0x50, flags]), // data offset 5 (no options), flags
    u16be(window & 0xffff),
    new Uint8Array([0, 0]), // checksum placeholder
    new Uint8Array([0, 0]), // urgent pointer
  ]);
  const segment = concatBytes([headerNoChecksum, payload]);
  const csum = tcpUdpChecksum(srcIP, dstIP, PROTO_TCP, segment);
  segment[16] = (csum >>> 8) & 0xff;
  segment[17] = csum & 0xff;
  return segment;
}

function udpSegment(srcIP: Uint8Array, dstIP: Uint8Array, srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const length = 8 + payload.length;
  const headerNoChecksum = concatBytes([u16be(srcPort), u16be(dstPort), u16be(length), new Uint8Array([0, 0])]);
  const segment = concatBytes([headerNoChecksum, payload]);
  const csum = tcpUdpChecksum(srcIP, dstIP, PROTO_UDP, segment);
  // 0 means "no checksum" for UDP over IPv4 — only overwrite when the
  // computed value isn't the reserved all-zero sentinel.
  if (csum !== 0) {
    segment[6] = (csum >>> 8) & 0xff;
    segment[7] = csum & 0xff;
  }
  return segment;
}

function icmpSegment(isEcho: boolean, payload: Uint8Array): Uint8Array {
  const header = concatBytes([
    new Uint8Array([isEcho ? 8 : 0, 0]), // type: 8=echo request, 0=echo reply
    new Uint8Array([0, 0]), // checksum placeholder
    new Uint8Array([0, 0, 0, 0]), // id, sequence
  ]);
  const segment = concatBytes([header, payload]);
  const csum = checksum16(segment);
  segment[2] = (csum >>> 8) & 0xff;
  segment[3] = csum & 0xff;
  return segment;
}

function protocolNumber(entry: Entry): number {
  switch (entry.protocol) {
    case "dns":
    case "udp":
      return PROTO_UDP;
    case "icmp":
      return PROTO_ICMP;
    default:
      return PROTO_TCP; // http/redis/valkey/postgres/amqp/tcp all ride TCP
  }
}

const FALLBACK_MAC_A = new Uint8Array([0x02, 0, 0, 0, 0, 0x01]);
const FALLBACK_MAC_B = new Uint8Array([0x02, 0, 0, 0, 0, 0x02]);

// buildFrame assembles one Ethernet+IPv4+L4 frame for a single direction
// (client->server or server->client) of an entry's exchange.
// reqLen is the request direction's payload length, which the response frame
// needs for its ack. It is passed in rather than recomputed: the caller already
// decoded the request payload, and re-deriving it here would re-run the base64
// decode (and, for a legacy entry, the whole hexdump parse) once per response
// frame in the export.
function buildFrame(
  entry: Entry,
  direction: "req" | "resp",
  payload: Uint8Array,
  packetId: number,
  reqLen: number
): Uint8Array | null {
  const forward = direction === "req";
  const fromIP = ipv4Bytes(forward ? entry.src.ip : entry.dst.ip);
  const toIP = ipv4Bytes(forward ? entry.dst.ip : entry.src.ip);
  if (!fromIP || !toIP) return null; // IPv6 or unparseable — skip rather than emit garbage

  const srcMac = parseMac(forward ? entry.l4?.srcMac : entry.l4?.dstMac, forward ? FALLBACK_MAC_A : FALLBACK_MAC_B);
  const dstMac = parseMac(forward ? entry.l4?.dstMac : entry.l4?.srcMac, forward ? FALLBACK_MAC_B : FALLBACK_MAC_A);
  const ethernet = concatBytes([dstMac, srcMac, u16be(ETHERTYPE_IPV4)]);

  const protocol = protocolNumber(entry);
  const fromPort = forward ? entry.src.port : entry.dst.port;
  const toPort = forward ? entry.dst.port : entry.src.port;

  let l4Segment: Uint8Array;
  if (protocol === PROTO_TCP) {
    const seqBase = entry.l4?.seqStart ?? 0;
    const ackBase = entry.l4?.ackStart ?? 0;
    // Best-effort sequence numbers: the response ack advances by the
    // request's payload length. Real per-direction seq/ack tracking isn't
    // available per-entry, so this is an approximation, not a real capture.
    const seq = forward ? seqBase : ackBase;
    const ack = forward ? ackBase : seqBase + reqLen;
    l4Segment = tcpSegment(fromIP, toIP, fromPort, toPort, seq, ack, entry.l4?.window ?? 64240, payload);
  } else if (protocol === PROTO_UDP) {
    l4Segment = udpSegment(fromIP, toIP, fromPort, toPort, payload);
  } else {
    l4Segment = icmpSegment(forward, payload);
  }

  const ip = ipv4Header(fromIP, toIP, protocol, l4Segment.length, entry.l4?.ttl ?? 64, packetId);
  return concatBytes([ethernet, ip, l4Segment]);
}

// --- pcap container ------------------------------------------------------

function globalHeader(): Uint8Array {
  return concatBytes([
    new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1]), // magic, little-endian byte order
    new Uint8Array([2, 0, 4, 0]), // version 2.4
    new Uint8Array(8), // thiszone, sigfigs
    new Uint8Array([0xff, 0xff, 0, 0]), // snaplen 65535 (LE)
    new Uint8Array([LINKTYPE_ETHERNET, 0, 0, 0]),
  ]);
}

function recordHeader(tsSec: number, tsUsec: number, len: number): Uint8Array {
  const le32 = (v: number) => new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
  return concatBytes([le32(tsSec), le32(tsUsec), le32(len), le32(len)]);
}

// entriesToPcap synthesizes a classic (non-pcapng) .pcap file: one frame per
// request/response side that has a body, in timestamp order. Entries without
// a parseable IPv4 src/dst on the relevant side are silently omitted.
export function entriesToPcap(entries: Entry[]): Uint8Array {
  const chunks: Uint8Array[] = [globalHeader()];
  let packetId = 0;

  // Oldest-first so the pcap reads chronologically like a real capture,
  // regardless of the newest-first order the table displays entries in.
  const ordered = [...entries].sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  for (const entry of ordered) {
    const baseMs = Date.parse(entry.timestamp);
    if (Number.isNaN(baseMs)) continue;

    const reqBytes = payloadBytes(entry.request);
    if (reqBytes.length > 0 || entry.protocol === "icmp") {
      const frame = buildFrame(entry, "req", reqBytes, ++packetId, reqBytes.length);
      if (frame) {
        const tsSec = Math.floor(baseMs / 1000);
        const tsUsec = (baseMs % 1000) * 1000;
        chunks.push(recordHeader(tsSec, tsUsec, frame.length), frame);
      }
    }

    const respBytes = payloadBytes(entry.response);
    if (respBytes.length > 0) {
      const frame = buildFrame(entry, "resp", respBytes, ++packetId, reqBytes.length);
      if (frame) {
        const respMs = baseMs + Math.max(entry.elapsedMs, 0);
        const tsSec = Math.floor(respMs / 1000);
        const tsUsec = (respMs % 1000) * 1000;
        chunks.push(recordHeader(tsSec, tsUsec, frame.length), frame);
      }
    }
  }

  return concatBytes(chunks);
}
