package worker

import (
	"strings"

	"github.com/google/gopacket/layers"
)

// hexdigits is the nibble->ASCII lookup used by hexDump. Rendering through it
// (rather than fmt) is what keeps hexDump off the reflection/format-parsing
// path: this function runs for every captured request, response, generic L4
// flow and — before the per-flow gate in trackTCP — used to run per packet, so
// it is the worker's single hottest formatting site.
const hexdigits = "0123456789abcdef"

// hexLineWidth is the exact byte length of one *full* hexDump line:
// 8 offset digits + 2 spaces + 16*3 hex columns + 1 group gap + 1 gutter space
// + "|" + 16 ascii + "|" + "\n" = 79. Used only to size the builder up front so
// the whole dump is a single allocation; a short final line just leaves a few
// bytes of slack.
const hexLineWidth = 79

// hexDump renders b as an offset/hex/ascii block in the classic `hexdump -C`
// style, capped at cap bytes. It returns "" for empty input (or a non-positive
// cap). Output is bounded so it is safe to attach to an entry and ship over the
// wire.
//
// The exact byte layout is a wire contract, not cosmetics: internal/hub/pcap.go
// (parseHexDump) and ui/src/pcap.ts parse this text back into bytes to build a
// downloadable pcap. Any change to spacing, casing or the ascii gutter breaks
// pcap export — TestHexDumpGolden pins the format, and
// TestHexDumpMatchesReferenceRenderer cross-checks it against a straightforward
// fmt-based reference over random inputs.
func hexDump(b []byte, cap int) string {
	if cap <= 0 || len(b) == 0 {
		return ""
	}
	if len(b) > cap {
		b = b[:cap]
	}
	var sb strings.Builder
	sb.Grow(((len(b) + 15) / 16) * hexLineWidth)
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		line := b[off:end]
		// Offset, "%08x  ": lowercase hex zero-padded to 8 digits, widening
		// beyond 8 only past 4 GiB (unreachable — dumps are capped at a few KB
		// — but kept so the field never silently wraps). Hand-rolled rather
		// than fmt.Fprintf(&sb, ...) because taking the Builder's address for
		// fmt forces it to escape to the heap, which costs a second allocation
		// per dump on top of the buffer.
		digits := 8
		if off>>32 != 0 {
			for shift := 60; shift > 28; shift -= 4 {
				if (off>>uint(shift))&0xf != 0 {
					digits = shift/4 + 1
					break
				}
			}
		}
		for i := digits - 1; i >= 0; i-- {
			sb.WriteByte(hexdigits[(off>>uint(i*4))&0xf])
		}
		sb.WriteString("  ")
		// hex columns (two groups of 8, extra space between)
		for j := 0; j < 16; j++ {
			if j < len(line) {
				c := line[j]
				sb.WriteByte(hexdigits[c>>4])
				sb.WriteByte(hexdigits[c&0x0f])
				sb.WriteByte(' ')
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}
		// ascii column
		sb.WriteString(" |")
		for _, c := range line {
			if c >= 0x20 && c < 0x7f {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// flagSet is a small bitset over the TCP control flags, used to union the flags
// seen per direction of a connection.
type flagSet uint8

const (
	flagSYN flagSet = 1 << iota
	flagACK
	flagFIN
	flagRST
	flagPSH
	flagURG
)

// flagNames is the rendering order of the six control-flag bits. Stable: it is
// what "SYN,ACK,FIN" means.
var flagNames = []struct {
	bit  flagSet
	name string
}{
	{flagSYN, "SYN"}, {flagACK, "ACK"}, {flagFIN, "FIN"},
	{flagRST, "RST"}, {flagPSH, "PSH"}, {flagURG, "URG"},
}

// flagStrings precomputes String() for all 64 combinations of the six defined
// bits. buildL4Info renders both directions' flag sets for every emitted entry,
// and the old loop-and-Join built a fresh []string plus a fresh joined string
// each time — 64 immutable strings built once at init cost nothing and make the
// call a single array index.
var flagStrings = buildFlagStrings()

func buildFlagStrings() [64]string {
	var t [64]string
	for v := range t {
		var out []string
		for _, fl := range flagNames {
			if flagSet(v)&fl.bit != 0 {
				out = append(out, fl.name)
			}
		}
		t[v] = strings.Join(out, ",")
	}
	return t
}

// String renders the set as "SYN,ACK,FIN" in a stable order.
//
// The &0x3f mask is behaviour-preserving rather than a truncation: only bits
// 0..5 are defined (flagSYN..flagURG), and the original loop simply ignored
// anything above them — so a value with high bits set rendered exactly like the
// same value with those bits cleared.
func (f flagSet) String() string {
	return flagStrings[f&0x3f]
}

// tcpFlagSet extracts the control-flag bitset from a TCP layer.
func tcpFlagSet(tcp *layers.TCP) flagSet {
	var f flagSet
	if tcp.SYN {
		f |= flagSYN
	}
	if tcp.ACK {
		f |= flagACK
	}
	if tcp.FIN {
		f |= flagFIN
	}
	if tcp.RST {
		f |= flagRST
	}
	if tcp.PSH {
		f |= flagPSH
	}
	if tcp.URG {
		f |= flagURG
	}
	return f
}
