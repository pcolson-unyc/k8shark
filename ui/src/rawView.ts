import type { RawView } from "./types";

// rawView.ts owns the two directions of the RawView wire format.
//
// A worker used to pre-render each captured sample as a `hexdump -C` text
// block and ship that. The block is 79 characters per 16 bytes — 4.94x the
// bytes it describes — so it dominated both the worker's CPU and the bytes on
// every hop, to render something the UI shows for at most one entry at a time.
// Current workers send the raw bytes instead (base64, 1.33x) and the dump is
// rendered here, on demand, for whichever entry the user actually opened.
//
// `hex` is still read as a fallback so a worker older than its hub keeps
// working. Both readers below take the same order: `data` first, then `hex`.

/** Decodes base64 into bytes. Returns empty on malformed input rather than throwing. */
function decodeBase64(b64: string): Uint8Array {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array(0);
  }
}

/**
 * parseHexDump recovers bytes from the legacy `hexdump -C`-style block:
 *   00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
 * Only the hex columns are read; the offset and the ascii gutter are ignored,
 * so a truncated final line is handled without special-casing.
 */
export function parseHexDump(dump: string): Uint8Array {
  const bytes: number[] = [];
  for (const line of dump.split("\n")) {
    if (!line.trim()) continue;
    const barIdx = line.indexOf(" |");
    const hexPart = (barIdx >= 0 ? line.slice(0, barIdx) : line).replace(/^[0-9a-f]{8}\s+/, "");
    const tokens = hexPart.match(/[0-9a-f]{2}/g);
    if (!tokens) continue;
    for (const t of tokens) bytes.push(parseInt(t, 16));
  }
  return new Uint8Array(bytes);
}

/** rawBytes returns a RawView's captured bytes, from either wire form. */
export function rawBytes(raw: RawView | undefined): Uint8Array {
  if (!raw) return new Uint8Array(0);
  if (raw.data) return decodeBase64(raw.data);
  if (raw.hex) return parseHexDump(raw.hex);
  return new Uint8Array(0);
}

const HEXDIGITS = "0123456789abcdef";

/**
 * renderHexDump formats bytes as a `hexdump -C`-style block, byte-identical to
 * what internal/worker/hexdump.go produces — the two must agree, because a
 * legacy entry's `hex` field is displayed as-is alongside blocks rendered here.
 * Layout per line: 8 offset digits, two spaces, 16 three-character hex columns
 * with an extra space after the 8th, then " |", the ascii gutter, "|".
 */
export function renderHexDump(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const line = bytes.subarray(off, Math.min(off + 16, bytes.length));
    let s = off.toString(16).padStart(8, "0") + "  ";
    for (let j = 0; j < 16; j++) {
      if (j < line.length) {
        s += HEXDIGITS[line[j] >> 4] + HEXDIGITS[line[j] & 0xf] + " ";
      } else {
        s += "   ";
      }
      if (j === 7) s += " ";
    }
    s += " |";
    for (const c of line) s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
    lines.push(s + "|");
  }
  return lines.join("\n") + "\n";
}
