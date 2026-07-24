package worker

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"strconv"
	"strings"
	"testing"
)

func gzipBytes(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	if _, err := gw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func deflateBytes(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	fw, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestDecompressBodyGzip(t *testing.T) {
	want := `{"hello":"world"}`
	got, truncated := decompressBody(gzipBytes(t, want), false, "gzip", 4096)
	if got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
}

func TestDecompressBodyDeflate(t *testing.T) {
	want := "plain text body"
	got, truncated := decompressBody(deflateBytes(t, want), false, "deflate", 4096)
	if got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
}

func TestDecompressBodyContentEncodingCaseAndSpace(t *testing.T) {
	want := "case insensitive"
	got, _ := decompressBody(gzipBytes(t, want), false, " GZIP ", 4096)
	if got != want {
		t.Errorf("body = %q, want %q (Content-Encoding matching should be case/space insensitive)", got, want)
	}
}

// The output limit guards against a small compressed payload expanding into
// something huge (a zip bomb) — it must cap the DECOMPRESSED size regardless
// of how much larger the true decompressed content actually is.
func TestDecompressBodyOutputLimitGuardsZipBomb(t *testing.T) {
	huge := strings.Repeat("A", 10_000)
	got, truncated := decompressBody(gzipBytes(t, huge), false, "gzip", 100)
	if len(got) != 100 {
		t.Errorf("len(body) = %d, want exactly 100 (the limit)", len(got))
	}
	if !truncated {
		t.Error("truncated = false, want true (output exceeded the limit)")
	}
}

func TestDecompressBodyExactFitNotTruncated(t *testing.T) {
	exact := strings.Repeat("B", 100)
	got, truncated := decompressBody(gzipBytes(t, exact), false, "gzip", 100)
	if got != exact {
		t.Errorf("body = %q, want %q", got, exact)
	}
	if truncated {
		t.Error("truncated = true, want false (decompressed content exactly fit the limit)")
	}
}

func TestDecompressBodyNoContentEncodingPassesThrough(t *testing.T) {
	raw := "not compressed"
	got, truncated := decompressBody(raw, false, "", 4096)
	if got != raw || truncated {
		t.Errorf("got (%q, %v), want (%q, false) — no Content-Encoding means no-op", got, truncated, raw)
	}
}

// A body claiming Content-Encoding: gzip that isn't actually valid gzip
// (e.g. cut short by bodyCap before decompressBody ever sees it, or just a
// mislabeled response) must fall back to the original bytes, not crash or
// return garbage.
func TestDecompressBodyInvalidGzipFallsBack(t *testing.T) {
	raw := "this is not gzip data"
	got, truncated := decompressBody(raw, false, "gzip", 4096)
	if got != raw || truncated {
		t.Errorf("got (%q, %v), want (%q, false) — invalid gzip should fall back unchanged", got, truncated, raw)
	}
}

func TestSafeBodyPrintablePassesThrough(t *testing.T) {
	s := `{"ok":true}`
	if got := safeBody(s); got != s {
		t.Errorf("safeBody(%q) = %q, want unchanged", s, got)
	}
}

func TestSafeBodyBinaryBecomesHexPreview(t *testing.T) {
	bin := string([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x00, 0x01})
	got := safeBody(bin)
	if got == bin {
		t.Fatal("safeBody left binary data unchanged — should have rendered a hex preview")
	}
	if !strings.HasPrefix(got, `\x1f8b0800fffe0001`) {
		t.Errorf("safeBody(binary) = %q, want a \\x-prefixed hex preview", got)
	}
}

// End-to-end: a gzip-compressed HTTP response body must come out decompressed
// and readable in the entry, not as opaque compressed bytes.
func TestConsumeHTTPGzipResponseIsDecompressed(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	rNet, rTr, sNet, sTr := flows(40400, 80)

	want := `{"message":"hello, this is a compressed JSON body"}`
	gz := gzipBytes(t, want)

	p.consumeHTTP(rNet, rTr, strings.NewReader("GET /x HTTP/1.1\r\nHost: h\r\n\r\n"))
	resp := "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " +
		strconv.Itoa(len(gz)) + "\r\n\r\n" + gz
	p.consumeHTTP(sNet, sTr, strings.NewReader(resp))

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Response.Body != want {
		t.Errorf("Response.Body = %q, want decompressed %q", got[0].Response.Body, want)
	}
}
