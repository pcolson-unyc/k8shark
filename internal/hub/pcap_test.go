package hub

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pablocolson/k8shark/pkg/api"
)

// classicPcapMagic is the on-disk little-endian encoding of the microsecond
// libpcap magic 0xa1b2c3d4 that pcapgo.NewWriter emits.
var classicPcapMagic = []byte{0xd4, 0xc3, 0xb2, 0xa1}

// readPcapPackets re-reads a synthesized pcap body back into raw frames, so a
// test can assert gopacket can actually parse what handlePcap produced.
func readPcapPackets(t *testing.T, body []byte) [][]byte {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}
	if lt := r.LinkType(); lt != layers.LinkTypeEthernet {
		t.Fatalf("link type = %v, want Ethernet", lt)
	}
	var pkts [][]byte
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadPacketData: %v", err)
		}
		cp := make([]byte, len(data))
		copy(cp, data)
		pkts = append(pkts, cp)
	}
	return pkts
}

func pcapHTTPEntry(id, dstNS string, ts time.Time) *api.Entry {
	return &api.Entry{
		ID:          id,
		Protocol:    api.ProtocolHTTP,
		Timestamp:   ts,
		ElapsedMs:   12,
		Source:      api.Endpoint{IP: "10.0.0.1", Port: 5000},
		Destination: api.Endpoint{IP: "10.0.0.2", Port: 80, Namespace: dstNS},
		Request:     api.Payload{Body: "GET /health HTTP/1.1\r\nHost: svc\r\n\r\n"},
		Response:    api.Payload{Body: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"},
		Status:      "success",
	}
}

func pcapDNSEntry(id string, ts time.Time) *api.Entry {
	return &api.Entry{
		ID:          id,
		Protocol:    api.ProtocolDNS,
		Timestamp:   ts,
		Source:      api.Endpoint{IP: "10.0.0.3", Port: 5353},
		Destination: api.Endpoint{IP: "10.0.0.4", Port: 53, Namespace: "kube-system"},
		Request:     api.Payload{Summary: "A example.com"},
		Response:    api.Payload{Summary: "example.com A 1.2.3.4"},
		Status:      "success",
	}
}

// A synthesized pcap starts with the classic magic, re-reads with gopacket, and
// the first frame decodes as Ethernet/IPv4/TCP carrying the request bytes.
func TestHandlePcapMagicAndReadable(t *testing.T) {
	s := New(slog.Default(), Options{})
	base := time.Now().Add(-time.Minute)
	s.store.add(pcapHTTPEntry("h1", "shop", base))         // TCP, oldest
	s.store.add(pcapDNSEntry("d1", base.Add(time.Second))) // UDP

	rec := httptest.NewRecorder()
	s.handlePcap(rec, httptest.NewRequest(http.MethodGet, "/api/pcap", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.tcpdump.pcap" {
		t.Errorf("Content-Type = %q, want application/vnd.tcpdump.pcap", ct)
	}
	body := rec.Body.Bytes()
	if !bytes.HasPrefix(body, classicPcapMagic) {
		t.Fatalf("body does not start with pcap magic %x, got %x", classicPcapMagic, body[:min(4, len(body))])
	}

	pkts := readPcapPackets(t, body)
	// http (req+resp) + dns (req+resp) = 4 frames.
	if len(pkts) != 4 {
		t.Fatalf("packet count = %d, want 4", len(pkts))
	}

	// First frame is the http request: Ethernet/IPv4/TCP carrying the body.
	pkt := gopacket.NewPacket(pkts[0], layers.LayerTypeEthernet, gopacket.Default)
	if pkt.Layer(layers.LayerTypeIPv4) == nil {
		t.Fatal("first frame has no IPv4 layer")
	}
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		t.Fatal("first frame has no TCP layer")
	}
	if tcp.DstPort != 80 {
		t.Errorf("first frame TCP dst port = %d, want 80", tcp.DstPort)
	}
	if app := pkt.ApplicationLayer(); app == nil || !bytes.Contains(app.Payload(), []byte("GET /health")) {
		t.Errorf("first frame payload missing request bytes: %v", pkt.ApplicationLayer())
	}

	// The dns frames ride UDP.
	dnsPkt := gopacket.NewPacket(pkts[2], layers.LayerTypeEthernet, gopacket.Default)
	if dnsPkt.Layer(layers.LayerTypeUDP) == nil {
		t.Error("dns frame has no UDP layer")
	}
}

// RawView.hex (worker hexdump format) is decoded back into the frame payload.
func TestHandlePcapDecodesRawHex(t *testing.T) {
	s := New(slog.Default(), Options{})
	// "hexdump -C"-style block for the 5 bytes "PING\n" (0x50 0x49 0x4e 0x47 0x0a).
	hex := "00000000  50 49 4e 47 0a                                   |PING.|\n"
	e := &api.Entry{
		ID:          "raw1",
		Protocol:    api.ProtocolRedis,
		Timestamp:   time.Now(),
		Source:      api.Endpoint{IP: "10.1.0.1", Port: 6000},
		Destination: api.Endpoint{IP: "10.1.0.2", Port: 6379},
		Request:     api.Payload{Raw: &api.RawView{Hex: hex, Bytes: 5}},
	}
	s.store.add(e)

	rec := httptest.NewRecorder()
	s.handlePcap(rec, httptest.NewRequest(http.MethodGet, "/api/pcap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	pkts := readPcapPackets(t, rec.Body.Bytes())
	if len(pkts) != 1 {
		t.Fatalf("packet count = %d, want 1 (request only)", len(pkts))
	}
	pkt := gopacket.NewPacket(pkts[0], layers.LayerTypeEthernet, gopacket.Default)
	app := pkt.ApplicationLayer()
	if app == nil || !bytes.Equal(app.Payload(), []byte("PING\n")) {
		t.Errorf("payload = %v, want decoded raw-hex bytes PING\\n", app)
	}
}

// A filter narrows the exported packets; an unknown IFL field is a 400.
func TestHandlePcapFilterAndUnknownField(t *testing.T) {
	s := New(slog.Default(), Options{})
	base := time.Now().Add(-time.Minute)
	s.store.add(pcapHTTPEntry("h1", "shop", base))
	s.store.add(pcapDNSEntry("d1", base.Add(time.Second)))

	// Unfiltered: 4 frames (2 http + 2 dns).
	rec := httptest.NewRecorder()
	s.handlePcap(rec, httptest.NewRequest(http.MethodGet, "/api/pcap", nil))
	if got := len(readPcapPackets(t, rec.Body.Bytes())); got != 4 {
		t.Fatalf("unfiltered packet count = %d, want 4", got)
	}

	// Filter to http only: 2 frames.
	rec = httptest.NewRecorder()
	httpOnly := "/api/pcap?filter=" + url.QueryEscape(`protocol == "http"`)
	s.handlePcap(rec, httptest.NewRequest(http.MethodGet, httpOnly, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered status = %d, want 200", rec.Code)
	}
	if got := len(readPcapPackets(t, rec.Body.Bytes())); got != 2 {
		t.Errorf("http-filtered packet count = %d, want 2", got)
	}

	// Unknown field is a compile error surfaced as 400 (never match-nothing).
	rec = httptest.NewRecorder()
	badFilter := "/api/pcap?filter=" + url.QueryEscape("nonsense.field == 1")
	s.handlePcap(rec, httptest.NewRequest(http.MethodGet, badFilter, nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown-field status = %d, want 400", rec.Code)
	}
}

// since/until restrict the export to a time window.
func TestHandlePcapTimeWindow(t *testing.T) {
	s := New(slog.Default(), Options{})
	now := time.Now()
	s.store.add(pcapHTTPEntry("old", "shop", now.Add(-time.Hour)))
	s.store.add(pcapHTTPEntry("new", "shop", now))

	rec := httptest.NewRecorder()
	s.handlePcap(rec, httptest.NewRequest(http.MethodGet, "/api/pcap?since=30m", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Only the "new" entry survives the window: its request + response = 2.
	if got := len(readPcapPackets(t, rec.Body.Bytes())); got != 2 {
		t.Errorf("since=30m packet count = %d, want 2", got)
	}
}

// pcapHexDumpOf renders bytes in the worker hexdump.go "hexdump -C" style, so a
// test can build a RawView.Hex block that parseHexDump round-trips.
func pcapHexDumpOf(b []byte) string {
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		line := b[off:end]
		fmt.Fprintf(&sb, "%08x  ", off)
		for _, c := range line {
			fmt.Fprintf(&sb, "%02x ", c)
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

// The raw hexdump and the body are capped independently, so raw is not always
// the bigger sample: the export must take whichever direction carries more
// bytes, and keep raw on a tie (byte-exact capture beats decompressed text).
func TestPcapPayloadBytesPrefersLongerSource(t *testing.T) {
	body := "GET /health HTTP/1.1\r\nHost: svc\r\nAccept: */*\r\n\r\n"
	tests := []struct {
		name string
		p    api.Payload
		want string
	}{{
		// The regression: a raw-capture cap lowered below the body cap must not
		// silently shrink the export down to the truncated raw sample.
		name: "raw shorter than body -> body",
		p:    api.Payload{Body: body, Raw: &api.RawView{Hex: pcapHexDumpOf([]byte(body[:8])), Bytes: 8}},
		want: body,
	}, {
		// Generic L4 / DNS entries carry raw bytes and no decoded body at all.
		name: "raw only -> raw",
		p:    api.Payload{Raw: &api.RawView{Hex: pcapHexDumpOf([]byte("PING\r\n")), Bytes: 6}},
		want: "PING\r\n",
	}, {
		// Equal lengths: raw wins — it never went through decompression/text
		// handling, so it's the more faithful of two same-sized views.
		name: "equal length -> raw",
		p:    api.Payload{Body: "xxxxxx", Raw: &api.RawView{Hex: pcapHexDumpOf([]byte("PING\r\n")), Bytes: 6}},
		want: "PING\r\n",
	}, {
		name: "neither -> summary",
		p:    api.Payload{Summary: "A example.com"},
		want: "A example.com",
	}, {
		name: "empty payload -> nothing",
		p:    api.Payload{},
		want: "",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pcapPayloadBytes(&tc.p); string(got) != tc.want {
				t.Errorf("pcapPayloadBytes = %q, want %q", got, tc.want)
			}
		})
	}
}

// End-to-end: the exported frame for an entry whose raw sample is shorter than
// its body carries the full body bytes, not the truncated raw sample.
func TestHandlePcapPrefersLongerBodyOverShortRaw(t *testing.T) {
	s := New(slog.Default(), Options{})
	body := "GET /health HTTP/1.1\r\nHost: svc\r\n\r\n"
	s.store.add(&api.Entry{
		ID:          "short-raw",
		Protocol:    api.ProtocolHTTP,
		Timestamp:   time.Now(),
		Source:      api.Endpoint{IP: "10.2.0.1", Port: 5000},
		Destination: api.Endpoint{IP: "10.2.0.2", Port: 80},
		// Raw capped at 8 bytes while the hub still holds the whole body.
		Request: api.Payload{Body: body, Raw: &api.RawView{Hex: pcapHexDumpOf([]byte(body[:8])), Bytes: 8}},
	})

	rec := httptest.NewRecorder()
	s.handlePcap(rec, httptest.NewRequest(http.MethodGet, "/api/pcap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	pkts := readPcapPackets(t, rec.Body.Bytes())
	if len(pkts) != 1 {
		t.Fatalf("packet count = %d, want 1 (request only)", len(pkts))
	}
	pkt := gopacket.NewPacket(pkts[0], layers.LayerTypeEthernet, gopacket.Default)
	app := pkt.ApplicationLayer()
	if app == nil || !bytes.Equal(app.Payload(), []byte(body)) {
		t.Errorf("payload = %q, want the full body %q", app, body)
	}
}

// parseHexDump handles multi-line blocks and ignores the ascii column even when
// it contains hex-looking text.
func TestParseHexDump(t *testing.T) {
	// The ascii column "|GET / HTTP|" must not be re-read as bytes.
	dump := "00000000  47 45 54 20 2f 20 48 54  54 50                   |GET / HTTP|\n"
	got := parseHexDump(dump)
	if string(got) != "GET / HTTP" {
		t.Errorf("parseHexDump = %q, want %q", got, "GET / HTTP")
	}
	if len(parseHexDump("   \n")) != 0 {
		t.Error("blank input should decode to no bytes")
	}
}

// TestPcapPayloadBytesPrefersDataOverHex covers the RawView wire migration:
// current workers ship raw bytes in Data, older ones pre-rendered them into
// Hex, and the hub must read both — Data first, since it is the authoritative
// form and needs no parsing at all.
func TestPcapPayloadBytesPrefersDataOverHex(t *testing.T) {
	want := []byte("GET / HTTP/1.1\r\n\r\n")

	t.Run("data is used directly", func(t *testing.T) {
		got := pcapPayloadBytes(&api.Payload{Raw: &api.RawView{Data: want, Bytes: len(want)}})
		if string(got) != string(want) {
			t.Errorf("payload = %q, want %q", got, want)
		}
	})

	t.Run("legacy hex is still decoded when there is no data", func(t *testing.T) {
		got := pcapPayloadBytes(&api.Payload{Raw: &api.RawView{Hex: pcapHexDumpOf(want), Bytes: len(want)}})
		if string(got) != string(want) {
			t.Errorf("payload = %q, want %q — the old-worker fallback is broken", got, want)
		}
	})

	t.Run("data wins over hex if a frame somehow carries both", func(t *testing.T) {
		got := pcapPayloadBytes(&api.Payload{Raw: &api.RawView{
			Data: want,
			Hex:  pcapHexDumpOf([]byte("stale stale stale stale stale")), // longer, and wrong
		}})
		if string(got) != string(want) {
			t.Errorf("payload = %q, want the Data bytes %q", got, want)
		}
	})

	t.Run("a longer body still beats a short data sample", func(t *testing.T) {
		body := "GET /health HTTP/1.1\r\nHost: svc\r\nAccept: */*\r\n\r\n"
		got := pcapPayloadBytes(&api.Payload{
			Raw:  &api.RawView{Data: []byte("GET /heal"), Bytes: len(body), Truncated: true},
			Body: body,
		})
		if string(got) != body {
			t.Errorf("payload = %q, want the fuller body %q", got, body)
		}
	})
}
