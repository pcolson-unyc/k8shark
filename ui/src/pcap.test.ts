import { describe, expect, it } from "vitest";
import { entriesToPcap } from "./pcap";
import type { Entry } from "./types";

function entry(overrides: Partial<Entry> & { id: string }): Entry {
  return {
    protocol: "http",
    timestamp: "2026-01-01T00:00:00.000Z",
    elapsedMs: 10,
    node: "node-1",
    src: { ip: "10.0.0.1", port: 40000 },
    dst: { ip: "10.0.0.2", port: 80 },
    request: { summary: "GET /", raw: { hex: hexDumpOf("GET / HTTP/1.1\r\n\r\n"), bytes: 19 } },
    response: { summary: "200", raw: { hex: hexDumpOf("HTTP/1.1 200 OK\r\n\r\n"), bytes: 20 } },
    status: "success",
    statusCode: 200,
    ...overrides,
  };
}

// hexDumpOf mirrors the worker's hexdump.go format closely enough for
// parseHexDump to round-trip it: "<offset>  <hex bytes...>  |<ascii>|".
function hexDumpOf(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let out = "";
  for (let off = 0; off < bytes.length; off += 16) {
    const line = bytes.slice(off, off + 16);
    const hex = Array.from(line, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(line, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    out += `${off.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|\n`;
  }
  return out;
}

// readU32LE/readU16LE read the little-endian pcap file structure back out
// for assertions, independent of pcap.ts's own (also little-endian) writers.
function readU32LE(b: Uint8Array, off: number): number {
  // >>> 0 forces unsigned interpretation — plain `|`/`<<` operate on signed
  // 32-bit ints in JS, so 0xa1b2c3d4's set high bit would otherwise read
  // back negative.
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}
function readU16BE(b: Uint8Array, off: number): number {
  return (b[off] << 8) | b[off + 1];
}

describe("entriesToPcap", () => {
  it("writes just a valid global header for an empty entry list", () => {
    const out = entriesToPcap([]);
    expect(out.length).toBe(24);
    expect(readU32LE(out, 0)).toBe(0xa1b2c3d4); // magic, byte-order-correct once read back LE
    expect(out[20]).toBe(1); // linktype ethernet (LE u32, low byte first)
  });

  it("emits one packet record per side (request + response) with recoverable payload bytes", () => {
    const out = entriesToPcap([entry({ id: "a" })]);
    let off = 24;
    const frames: Uint8Array[] = [];
    while (off < out.length) {
      const inclLen = readU32LE(out, off + 8);
      const frame = out.slice(off + 16, off + 16 + inclLen);
      frames.push(frame);
      off += 16 + inclLen;
    }
    expect(frames).toHaveLength(2);

    for (const frame of frames) {
      // Ethernet (14) + IPv4 (20, no options) header boundary checks.
      expect(readU16BE(frame, 12)).toBe(0x0800); // ethertype IPv4
      expect(frame[14] >> 4).toBe(4); // IP version 4
      expect(frame[23]).toBe(6); // protocol TCP (http rides TCP)
    }

    const reqFrame = frames[0];
    const reqPayload = new TextDecoder().decode(reqFrame.slice(14 + 20 + 20));
    expect(reqPayload).toContain("GET / HTTP/1.1");

    const respFrame = frames[1];
    const respPayload = new TextDecoder().decode(respFrame.slice(14 + 20 + 20));
    expect(respPayload).toContain("200 OK");
  });

  it("orders packets chronologically regardless of input order", () => {
    const early = entry({ id: "early", timestamp: "2026-01-01T00:00:00.000Z", request: { summary: "one", raw: { hex: hexDumpOf("one") } }, response: {} });
    const late = entry({ id: "late", timestamp: "2026-01-01T00:00:05.000Z", request: { summary: "two", raw: { hex: hexDumpOf("two") } }, response: {} });
    const out = entriesToPcap([late, early]); // late first in the input array

    const firstRecordSec = readU32LE(out, 24);
    const secondRecordOff = 24 + 16 + readU32LE(out, 24 + 8);
    const secondRecordSec = readU32LE(out, secondRecordOff);
    expect(firstRecordSec).toBeLessThan(secondRecordSec);
  });

  it("skips a side with no payload bytes and no raw capture", () => {
    const out = entriesToPcap([entry({ id: "a", request: { summary: "" }, response: {} })]);
    expect(out.length).toBe(24); // global header only, no packet records
  });

  it("falls back to summary text when raw capture is absent", () => {
    const out = entriesToPcap([entry({ id: "a", request: { summary: "fallback text" }, response: {} })]);
    const inclLen = readU32LE(out, 24 + 8);
    const frame = out.slice(24 + 16, 24 + 16 + inclLen);
    const payload = new TextDecoder().decode(frame.slice(14 + 20 + 20));
    expect(payload).toBe("fallback text");
  });

  // firstFramePayload returns the application bytes of the first (and, in these
  // tests, only) packet record: 24-byte global header, 16-byte record header,
  // then Ethernet (14) + IPv4 (20) + TCP (20).
  function firstFramePayload(out: Uint8Array): string {
    const inclLen = readU32LE(out, 24 + 8);
    const frame = out.slice(24 + 16, 24 + 16 + inclLen);
    return new TextDecoder().decode(frame.slice(14 + 20 + 20));
  }

  // The raw hexdump and the body are capped independently worker-side, so raw
  // is not always the bigger sample of an exchange.
  it("exports the body when the raw sample is shorter than it", () => {
    const body = "GET /health HTTP/1.1\r\nHost: svc\r\nAccept: */*\r\n\r\n";
    const out = entriesToPcap([
      // Raw truncated to 8 bytes while the entry still carries the whole body:
      // a lowered raw-capture cap must not silently shrink the export.
      entry({ id: "a", request: { body, summary: "GET /health", raw: { hex: hexDumpOf(body.slice(0, 8)), bytes: 8 } }, response: {} }),
    ]);
    expect(firstFramePayload(out)).toBe(body);
  });

  it("exports raw bytes when there is no body at all (generic L4 / DNS)", () => {
    const out = entriesToPcap([
      entry({ id: "a", protocol: "tcp", request: { summary: "tcp flow", raw: { hex: hexDumpOf("PING\r\n"), bytes: 6 } }, response: {} }),
    ]);
    expect(firstFramePayload(out)).toBe("PING\r\n");
  });

  it("keeps raw's precedence on a tie — it is the byte-exact capture", () => {
    const out = entriesToPcap([
      entry({ id: "a", request: { body: "xxxxxx", raw: { hex: hexDumpOf("PING\r\n"), bytes: 6 } }, response: {} }),
    ]);
    expect(firstFramePayload(out)).toBe("PING\r\n");
  });

  it("skips entries with a non-IPv4 (or unparseable) address instead of emitting a malformed packet", () => {
    const out = entriesToPcap([
      entry({ id: "a", src: { ip: "fe80::1", port: 1 }, response: {} }),
    ]);
    expect(out.length).toBe(24);
  });
});
