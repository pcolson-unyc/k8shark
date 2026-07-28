package worker

import (
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

func TestHexDumpEmpty(t *testing.T) {
	if got := hexDump(nil, 128); got != "" {
		t.Errorf("hexDump(nil) = %q, want empty", got)
	}
	if got := hexDump([]byte("x"), 0); got != "" {
		t.Errorf("hexDump with cap 0 = %q, want empty", got)
	}
	if got := hexDump([]byte("x"), -1); got != "" {
		t.Errorf("hexDump with negative cap = %q, want empty", got)
	}
	if got := hexDump([]byte{}, 128); got != "" {
		t.Errorf("hexDump(empty slice) = %q, want empty", got)
	}
}

// TestHexDumpGolden pins the exact bytes hexDump emits. This is a wire
// contract, not cosmetics: internal/hub/pcap.go (parseHexDump) and
// ui/src/pcap.ts parse this text back into packet bytes for the pcap export,
// so a change in column widths, the two-space offset gutter, the extra space
// after column 7, the "   " padding of a short final line, the " |" ascii
// prefix or the trailing "|\n" silently breaks pcap download.
func TestHexDumpGolden(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		cap  int
		want string
	}{
		{
			name: "one byte",
			in:   []byte{0x41},
			cap:  128,
			want: "00000000  41                                                |A|\n",
		},
		{
			name: "exactly 16 bytes",
			in:   []byte("0123456789abcdef"),
			cap:  128,
			want: "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n",
		},
		{
			// 17 bytes => a full line plus a one-byte final line, which
			// exercises the "   " padding of the missing hex columns.
			name: "17 bytes pads the short final line",
			in:   []byte("0123456789abcdefX"),
			cap:  128,
			want: "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n" +
				"00000010  58                                                |X|\n",
		},
		{
			name: "longer than cap is truncated",
			in:   []byte("0123456789abcdefXYZ"),
			cap:  17,
			want: "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n" +
				"00000010  58                                                |X|\n",
		},
		{
			// The printable range is [0x20, 0x7f): 0x1f and 0x7f render as '.',
			// 0x20 (space) and 0x7e (~) render as themselves.
			name: "printable-range boundaries",
			in:   []byte{0x00, 0x1f, 0x20, 0x7e, 0x7f, 0xff},
			cap:  128,
			want: "00000000  00 1f 20 7e 7f ff                                 |.. ~..|\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hexDump(tc.in, tc.cap)
			if got != tc.want {
				t.Errorf("hexDump(%q, %d):\n got %q\nwant %q", tc.in, tc.cap, got, tc.want)
			}
		})
	}
}

// referenceHexDump is the original fmt-based renderer, kept verbatim as the
// oracle for the hand-rolled nibble-table version in hexdump.go.
func referenceHexDump(b []byte, cap int) string {
	if cap <= 0 || len(b) == 0 {
		return ""
	}
	if len(b) > cap {
		b = b[:cap]
	}
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		line := b[off:end]
		fmt.Fprintf(&sb, "%08x  ", off)
		for j := 0; j < 16; j++ {
			if j < len(line) {
				fmt.Fprintf(&sb, "%02x ", line[j])
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}
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

// TestHexDumpMatchesReferenceRenderer cross-checks the optimised renderer
// against the reference for every length from 0 to 200 (all line-boundary and
// short-final-line cases) over random bytes, plus a few explicit caps.
func TestHexDumpMatchesReferenceRenderer(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for n := 0; n <= 200; n++ {
		b := make([]byte, n)
		rng.Read(b)
		for _, c := range []int{-1, 0, 1, 7, 8, 15, 16, 17, 63, 128, 4096} {
			want := referenceHexDump(b, c)
			if got := hexDump(b, c); got != want {
				t.Fatalf("hexDump(len=%d, cap=%d) mismatch:\n got %q\nwant %q", n, c, got, want)
			}
		}
	}
	// Every byte value, in order, so the full 0x00..0xff nibble table and the
	// printable/non-printable split are covered exactly once.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if got, want := hexDump(all, 256), referenceHexDump(all, 256); got != want {
		t.Errorf("full byte range mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestHexDumpFormat(t *testing.T) {
	got := hexDump([]byte("HTTP/1.1"), 128)
	// One line: offset, hex bytes, ascii gutter.
	if !strings.HasPrefix(got, "00000000  ") {
		t.Errorf("missing offset prefix: %q", got)
	}
	if !strings.Contains(got, "48 54 54 50") { // "HTTP"
		t.Errorf("missing hex bytes: %q", got)
	}
	if !strings.Contains(got, "|HTTP/1.1|") {
		t.Errorf("missing ascii gutter: %q", got)
	}
}

func TestHexDumpCapTruncates(t *testing.T) {
	in := append([]byte(strings.Repeat("A", 8)), []byte(strings.Repeat("B", 12))...)
	got := hexDump(in, 8) // only the first 8 'A' bytes should be dumped
	if strings.Count(got, "41") != 8 {
		t.Errorf("expected 8 'A' (0x41) bytes, got %q", got)
	}
	if strings.Contains(got, "42") || strings.Contains(got, "B") {
		t.Errorf("cap not honoured, 'B' bytes leaked: %q", got)
	}
	if !strings.Contains(got, "|AAAAAAAA|") {
		t.Errorf("ascii gutter wrong: %q", got)
	}
}

func TestHexDumpSingleAllocation(t *testing.T) {
	b := make([]byte, 256)
	got := testing.AllocsPerRun(100, func() { _ = hexDump(b, 256) })
	if got > 1 {
		t.Errorf("hexDump allocated %v times per call, want 1", got)
	}
}

// TestCapReaderRawMemoisesSample covers the capReader.raw() memo
// (pipeline.go): the captured sample must be reused once buf has frozen at
// max, while the Bytes/Truncated fields must keep tracking total, which goes on
// growing. (It lives here rather than in a pipeline test file because it began
// as a test about not re-rendering a hexdump per entry.)
func TestCapReaderRawMemoisesSample(t *testing.T) {
	// max = 8, so the first 8 bytes are the frozen "connection head" and every
	// later read only advances total.
	cr := newCapReader(strings.NewReader("abcdefghIJKLMNOPqrst"), 8)
	buf := make([]byte, 4)
	read := func() {
		t.Helper()
		if _, err := io.ReadFull(cr, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
	}

	read() // total 4, buf 4 — still growing
	v1 := cr.raw()
	if v1.Bytes != 4 || v1.Truncated {
		t.Fatalf("after 4B: Bytes=%d Truncated=%v, want 4/false", v1.Bytes, v1.Truncated)
	}

	read() // total 8, buf 8 — buf grew, the sample must change with it
	v2 := cr.raw()
	if string(v2.Data) == string(v1.Data) {
		t.Error("sample did not update while buf was still growing")
	}
	if string(v2.Data) != "abcdefgh" {
		t.Errorf("data = %q, want the first 8 bytes", v2.Data)
	}
	if v2.Hex != "" {
		t.Errorf("Hex = %q, want empty — current workers ship bytes, not a pre-rendered dump", v2.Hex)
	}
	if v2.Bytes != 8 || v2.Truncated {
		t.Fatalf("after 8B: Bytes=%d Truncated=%v, want 8/false", v2.Bytes, v2.Truncated)
	}

	read() // total 12, buf frozen at 8
	v3 := cr.raw()
	if &v3.Data[0] != &v2.Data[0] {
		t.Error("sample was re-copied though buf was frozen — the memo is not holding")
	}
	if v3.Bytes != 12 || !v3.Truncated {
		t.Errorf("after 12B: Bytes=%d Truncated=%v, want 12/true", v3.Bytes, v3.Truncated)
	}

	read() // total 16
	if v4 := cr.raw(); v4.Bytes != 16 || !v4.Truncated {
		t.Errorf("after 16B: Bytes=%d Truncated=%v, want 16/true", v4.Bytes, v4.Truncated)
	}

	// With buf frozen, raw() must not re-copy: the only allocation left is the
	// RawView itself. A re-copy would add the sample's own buffer.
	var keep *api.RawView
	if n := testing.AllocsPerRun(50, func() { keep = cr.raw() }); n > 1 {
		t.Errorf("cached raw() allocated %v times per call, want 1 (the RawView) — the sample is being re-copied", n)
	}
	if string(keep.Data) != string(v2.Data) {
		t.Errorf("cached sample drifted: %q vs %q", keep.Data, v2.Data)
	}
}

func TestFlagSetString(t *testing.T) {
	f := flagSYN | flagACK | flagFIN
	if got := f.String(); got != "SYN,ACK,FIN" {
		t.Errorf("flagSet.String() = %q, want SYN,ACK,FIN", got)
	}
	if got := flagSet(0).String(); got != "" {
		t.Errorf("empty flagSet = %q, want empty", got)
	}
}

// TestFlagSetStringTable checks the precomputed table against the original
// loop-and-join renderer for every possible flagSet value, including the
// undefined high bits (which both renderings must ignore).
func TestFlagSetStringTable(t *testing.T) {
	reference := func(f flagSet) string {
		var out []string
		for _, fl := range []struct {
			bit  flagSet
			name string
		}{
			{flagSYN, "SYN"}, {flagACK, "ACK"}, {flagFIN, "FIN"},
			{flagRST, "RST"}, {flagPSH, "PSH"}, {flagURG, "URG"},
		} {
			if f&fl.bit != 0 {
				out = append(out, fl.name)
			}
		}
		return strings.Join(out, ",")
	}
	for v := 0; v < 256; v++ {
		f := flagSet(v)
		if got, want := f.String(), reference(f); got != want {
			t.Fatalf("flagSet(%d).String() = %q, want %q", v, got, want)
		}
	}
	if got := testing.AllocsPerRun(100, func() { _ = (flagSYN | flagACK).String() }); got != 0 {
		t.Errorf("flagSet.String() allocated %v times per call, want 0", got)
	}
}
