import { describe, it, expect } from "vitest";
import { parseHexDump, rawBytes, renderHexDump } from "./rawView";

// GO_GOLDEN pins renderHexDump against the real output of
// internal/worker/hexdump.go's hexDump(), captured by running it. The two
// renderers must agree byte for byte: entries from an older worker arrive with
// a Go-rendered `hex` block that is displayed as-is, right next to blocks this
// module renders from `data`, and the hub's pcap export parses the Go form back
// into bytes. A drift here shows up as two visually different dumps in the same
// panel, or a corrupt pcap.
//
// Cases cover, in order: a multi-line dump with a short final line; a
// single byte; an exactly-16-byte line; 17 bytes (the short-final-line padding
// path); the printable-range boundaries 0x00/0x1f/0x20/0x7e/0x7f/0xff; and a
// binary RESP frame.
const GO_GOLDEN: { b64: string; dump: string }[] = [
  {
    b64: "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGFwaQ0KDQo=",
    dump:
      "00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|\n" +
      "00000010  48 6f 73 74 3a 20 61 70  69 0d 0a 0d 0a           |Host: api....|\n",
  },
  {
    b64: "eA==",
    dump: "00000000  78                                                |x|\n",
  },
  {
    b64: "MDEyMzQ1Njc4OWFiY2RlZg==",
    dump: "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n",
  },
  {
    b64: "MDEyMzQ1Njc4OWFiY2RlZmc=",
    dump:
      "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n" +
      "00000010  67                                                |g|\n",
  },
  {
    b64: "AB8gfn//QQ==",
    dump: "00000000  00 1f 20 7e 7f ff 41                              |.. ~..A|\n",
  },
  {
    b64: "KjINCiQzDQpHRVQNCiQ1DQpteWtleQ0K",
    dump:
      "00000000  2a 32 0d 0a 24 33 0d 0a  47 45 54 0d 0a 24 35 0d  |*2..$3..GET..$5.|\n" +
      "00000010  0a 6d 79 6b 65 79 0d 0a                           |.mykey..|\n",
  },
];

describe("renderHexDump", () => {
  it.each(GO_GOLDEN)("matches internal/worker/hexdump.go byte for byte ($b64)", ({ b64, dump }) => {
    expect(renderHexDump(rawBytes({ data: b64 }))).toBe(dump);
  });

  it("returns empty for empty input, like the Go side", () => {
    expect(renderHexDump(new Uint8Array(0))).toBe("");
  });

  it("round-trips through the legacy parser", () => {
    // renderHexDump -> parseHexDump is the same path the pcap export takes for
    // an entry produced by an older worker, so it must be lossless.
    for (const { b64 } of GO_GOLDEN) {
      const bytes = rawBytes({ data: b64 });
      expect(Array.from(parseHexDump(renderHexDump(bytes)))).toEqual(Array.from(bytes));
    }
  });
});

describe("rawBytes", () => {
  it("decodes base64 data", () => {
    expect(Array.from(rawBytes({ data: "aGk=" }))).toEqual([0x68, 0x69]);
  });

  it("prefers data over a legacy hex block when both are present", () => {
    // A worker sends one or the other, never both — but if a mixed frame ever
    // appears, data is the authoritative form and must win.
    const raw = { data: "aGk=", hex: "00000000  ff ff                                             |..|\n" };
    expect(Array.from(rawBytes(raw))).toEqual([0x68, 0x69]);
  });

  it("falls back to the legacy hex block when there is no data", () => {
    expect(Array.from(rawBytes({ hex: GO_GOLDEN[1].dump }))).toEqual([0x78]);
  });

  it("returns empty rather than throwing on malformed base64", () => {
    // A corrupt frame must degrade to an empty raw view, not blow up the
    // detail panel — there is no error boundary above it.
    expect(rawBytes({ data: "!!!not base64!!!" }).length).toBe(0);
  });

  it("returns empty for an undefined or empty raw view", () => {
    expect(rawBytes(undefined).length).toBe(0);
    expect(rawBytes({}).length).toBe(0);
  });
});
