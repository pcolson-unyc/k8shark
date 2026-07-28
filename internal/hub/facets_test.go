package hub

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

func entryWithNamespace(ns string) *api.Entry {
	e := sample()
	e.Destination.Namespace = ns
	return e
}

func TestFacetIndexValuesSortedCountDescValueAscTiebreak(t *testing.T) {
	f := newFacetIndex()
	// "shop" observed 3x, "platform" 3x (tie -> value asc), "kube-system" 1x.
	for i := 0; i < 3; i++ {
		f.observe(entryWithNamespace("shop"))
	}
	for i := 0; i < 3; i++ {
		f.observe(entryWithNamespace("platform"))
	}
	f.observe(entryWithNamespace("kube-system"))

	vals, tracked := f.values("dst.namespace", "", 10)
	if !tracked {
		t.Fatalf("expected dst.namespace to be tracked")
	}
	want := []FieldValue{
		{Value: "platform", Count: 3},
		{Value: "shop", Count: 3},
		{Value: "kube-system", Count: 1},
	}
	if len(vals) != len(want) {
		t.Fatalf("got %d values, want %d: %+v", len(vals), len(want), vals)
	}
	for i, w := range want {
		if vals[i] != w {
			t.Errorf("values[%d] = %+v, want %+v", i, vals[i], w)
		}
	}
}

// The guarantee here is the memory bound, not which key goes: eviction now
// drops the least-seen of a random facetEvictSample-sized sample rather than
// scanning all facetTrackCap keys for the global minimum on every new value of
// a saturated field (thousands of times a second for src.ip / pod names, under
// the index's single mutex). This test was deliberately relaxed from "evicts
// the global minimum" to "stays at cap, and the new value is what got room" —
// asserting the exact victim would be asserting an implementation detail the
// counter never promised (see facetEvictSample: space-saving in spirit, not a
// strict guarantee).
func TestFacetIndexStaysAtCap(t *testing.T) {
	f := newFacetIndex()

	// Fill "node" (tracked, string) to exactly facetTrackCap distinct values.
	for i := 0; i < facetTrackCap; i++ {
		name := "node-" + itoa(i)
		times := i + 1
		for j := 0; j < times; j++ {
			e := sample()
			e.Node = name
			f.observe(e)
		}
	}

	vals, tracked := f.values("node", "", facetTrackCap+10)
	if !tracked {
		t.Fatalf("expected node to be tracked")
	}
	if len(vals) != facetTrackCap {
		t.Fatalf("got %d distinct values, want %d", len(vals), facetTrackCap)
	}

	// Keep feeding brand-new values well past the cap: the counter must never
	// grow beyond it, and the value just observed must be present.
	for i := 0; i < 5*facetTrackCap; i++ {
		e := sample()
		e.Node = "node-new-" + itoa(i)
		f.observe(e)

		vals, _ = f.values("node", "", facetTrackCap+10)
		if len(vals) != facetTrackCap {
			t.Fatalf("after %d new values got %d distinct, want %d (cap breached)", i+1, len(vals), facetTrackCap)
		}
	}
	found := false
	for _, v := range vals {
		if v.Value == "node-new-"+itoa(5*facetTrackCap-1) {
			found = true
		}
	}
	if !found {
		t.Error("the most recently observed value was not recorded")
	}
}

// entryNoSubObjects is a fully-populated entry with every protocol sub-object
// left nil: the shape every facetGate must report absent.
func entryNoSubObjects() *api.Entry {
	return &api.Entry{
		Protocol: api.ProtocolHTTP, Node: "node-1", Status: "error", StatusCode: 503, ElapsedMs: 12,
		TraceID:     "abc",
		Source:      api.Endpoint{IP: "10.0.1.10", Port: 34567, Name: "frontend", Namespace: "shop", Workload: "web"},
		Destination: api.Endpoint{IP: "10.0.1.14", Port: 8080, Name: "payment", Namespace: "shop", Workload: "pay"},
		Request: api.Payload{
			Method: "POST", Path: "/api/checkout", Host: "payment.shop", Question: "q", Command: "GET",
			Query: "select 1", Exchange: "orders", RoutingKey: "new", Queue: "payments", ReplyTo: "cb",
			Class: "Basic", Flags: "SYN", WSOpcode: "text", ContentType: "application/json",
			DeliveryTag: 42, CorrelationID: "cid", Size: 12, Bytes: 10, Packets: 2, Summary: "POST /api/checkout",
			Body: "{}", StatusCode: 503,
		},
		Response: api.Payload{
			StatusCode: 503, ContentType: "application/json", Answer: "1.2.3.4", RowCount: 7,
			Size: 99, Summary: "503", Body: "err",
		},
	}
}

// Every field named by a facetGate must genuinely be unreachable when that
// gate reports absent — otherwise skipping the group would under-count and
// silently change what /api/fields reports. Pinned against an entry whose
// plain Payload/Endpoint members are all populated, so a getter that drifted
// to reading a shared field (rather than the nil-guarded sub-object) fails
// here instead of quietly losing values in production.
func TestFacetGatesMatchGetters(t *testing.T) {
	bare := entryNoSubObjects()
	for gi, g := range facetGates {
		if g.present(bare) {
			t.Errorf("facetGates[%d].present reports present on an entry with no sub-objects", gi)
		}
		for _, name := range g.fields {
			spec, ok := fieldSpecByName[name]
			if !ok || !spec.TrackValues {
				t.Errorf("facetGates[%d] names %q, which is not a value-tracked catalog field", gi, name)
				continue
			}
			get := fieldGetter(name)
			if get == nil {
				t.Errorf("facetGates[%d] names %q, which has no fieldGetter", gi, name)
				continue
			}
			if v := get(bare); v != "" {
				t.Errorf("gated field %q returns %q when its gate is absent; it would be under-counted", name, v)
			}
		}
	}
	// Every tracked counter must be reachable from exactly one of the two
	// ingest-path views — a field in neither would never be observed again.
	f := newFacetIndex()
	seen := map[*fieldCounter]int{}
	for _, fc := range f.ungated {
		seen[fc]++
	}
	for _, g := range f.groups {
		for _, fc := range g.counters {
			seen[fc]++
		}
	}
	for name, fc := range f.fields {
		if seen[fc] != 1 {
			t.Errorf("counter %q appears %d times across ungated+groups, want exactly 1", name, seen[fc])
		}
	}
}

// The gate split is a pure speed-up: what observe() records must be exactly
// what calling every tracked getter on every entry would record.
func TestFacetObserveCountsMatchFullScan(t *testing.T) {
	entries := []*api.Entry{
		sample(),
		richEntry(),
		entryNoSubObjects(),
		{Protocol: api.ProtocolKafka, Request: api.Payload{Kafka: &api.KafkaDetail{APIKey: "Produce", Topic: "orders"}}},
		{Protocol: api.ProtocolMongo, Request: api.Payload{Mongo: &api.MongoDetail{Command: "find", Collection: "users"}}},
		{Protocol: api.ProtocolMySQL,
			Request:  api.Payload{MySQL: &api.MySQLDetail{Command: "COM_QUERY"}},
			Response: api.Payload{MySQL: &api.MySQLDetail{ErrorCode: 1146}}},
		{Protocol: api.ProtocolAMQP, Request: api.Payload{Class: "Basic", Method: "Publish", Exchange: "orders"}},
		{Protocol: api.ProtocolTCP, L4: &api.L4Info{TTL: 64, MSS: 1460, IPVersion: 4, IPFlags: "DF",
			ClientTCPFlags: "SYN", ServerTCPFlags: "SYN,ACK", TLS: &api.TLSInfo{SNI: "api.example.com"}}},
		{Protocol: api.ProtocolDNS,
			Request:  api.Payload{DNS: &api.DNSDetail{Questions: []api.DNSQuestion{{Name: "x", Type: "A"}}}},
			Response: api.Payload{DNS: &api.DNSDetail{Rcode: "NOERROR", Authoritative: true}}},
	}

	f := newFacetIndex()
	// ref is only a source of the full getter set, never observed into.
	ref := newFacetIndex()
	want := map[string]map[string]int64{}
	for _, e := range entries {
		f.observe(e)
		for name, fc := range ref.fields {
			if v := fc.get(e); v != "" {
				if want[name] == nil {
					want[name] = map[string]int64{}
				}
				want[name][v]++
			}
		}
	}

	for name, fc := range f.fields {
		w := want[name]
		if len(fc.counts) != len(w) {
			t.Errorf("field %q: observed %v, want %v", name, fc.counts, w)
			continue
		}
		for v, c := range w {
			if fc.counts[v] != c {
				t.Errorf("field %q value %q: observed %d, want %d", name, v, fc.counts[v], c)
			}
		}
	}
}

func TestFacetIndexUntrackedFieldReturnsFalse(t *testing.T) {
	f := newFacetIndex()
	f.observe(sample())

	if _, tracked := f.values("postgres.query", "", 10); tracked {
		t.Errorf("postgres.query is freetext/untracked, values() should report tracked=false")
	}
	if _, tracked := f.values("request.path", "", 10); tracked {
		t.Errorf("request.path is freetext/untracked, values() should report tracked=false")
	}
	if _, tracked := f.values("nonexistent.field", "", 10); tracked {
		t.Errorf("unknown field should report tracked=false")
	}
}

func TestFacetIndexPrefixCaseInsensitive(t *testing.T) {
	f := newFacetIndex()
	f.observe(entryWithNamespace("Shop"))
	f.observe(entryWithNamespace("platform"))

	vals, tracked := f.values("dst.namespace", "sh", 10)
	if !tracked {
		t.Fatalf("expected dst.namespace to be tracked")
	}
	if len(vals) != 1 || vals[0].Value != "Shop" {
		t.Errorf("prefix %q = %+v, want just [Shop]", "sh", vals)
	}

	vals, _ = f.values("dst.namespace", "SH", 10)
	if len(vals) != 1 || vals[0].Value != "Shop" {
		t.Errorf("prefix %q = %+v, want just [Shop]", "SH", vals)
	}
}

// headerFieldNames tracks distinct header keys per side (not values), sorted
// by occurrence count, so handleFields can offer request.header.<name>/
// response.header.<name> as autocompletable field names.
func TestFacetIndexHeaderFieldNames(t *testing.T) {
	f := newFacetIndex()
	f.observe(&api.Entry{Request: api.Payload{Headers: map[string]string{"x-request-id": "1", "content-type": "json"}}})
	f.observe(&api.Entry{
		Request:  api.Payload{Headers: map[string]string{"x-request-id": "2"}},
		Response: api.Payload{Headers: map[string]string{"server": "nginx"}},
	})

	req, resp := f.headerFieldNames()
	reqSet := map[string]bool{}
	for _, n := range req {
		reqSet[n] = true
	}
	if !reqSet["x-request-id"] || !reqSet["content-type"] {
		t.Errorf("request header names = %v, want x-request-id and content-type", req)
	}
	if len(resp) != 1 || resp[0] != "server" {
		t.Errorf("response header names = %v, want just [server]", resp)
	}
	// x-request-id was seen on both entries, content-type on only one, so it
	// must sort first (count descending).
	if req[0] != "x-request-id" {
		t.Errorf("req[0] = %q, want x-request-id (higher count)", req[0])
	}
}

func TestFacetIndexSnapshotOmitsFreetextAndCapsTopN(t *testing.T) {
	f := newFacetIndex()
	f.observe(sample())

	snap := f.snapshot()
	if _, ok := snap["postgres.query"]; ok {
		t.Errorf("snapshot should not include untracked/freetext fields")
	}
	if _, ok := snap["dst.namespace"]; !ok {
		t.Errorf("snapshot should include tracked fields")
	}

	for i := 0; i < facetTopN+10; i++ {
		e := sample()
		e.Destination.Namespace = "ns-" + itoa(i)
		f.observe(e)
	}
	snap = f.snapshot()
	if len(snap["dst.namespace"]) > facetTopN {
		t.Errorf("snapshot()[dst.namespace] has %d entries, want <= %d", len(snap["dst.namespace"]), facetTopN)
	}
}

// BenchmarkFacetObserve covers the facet index's ingest path — it runs once
// per entry, under a single process-wide mutex, so its cost is a hard ceiling
// on hub ingest. The high-cardinality case is the one that matters: with pod
// names and IPs the tracked counters sit permanently at facetTrackCap, which is
// what makes eviction (not the getters) dominate.
func BenchmarkFacetObserve(b *testing.B) {
	entries := func(cardinal bool) []*api.Entry {
		out := make([]*api.Entry, 4096)
		for i := range out {
			e := sample()
			if cardinal {
				e.Source.IP = "10." + itoa(i%251) + "." + itoa((i/251)%251) + ".1"
				e.Destination.IP = "10.1." + itoa(i%251) + "." + itoa((i/251)%251)
				e.Source.Name = "web-" + itoa(i%997)
				e.Destination.Name = "api-" + itoa(i%997)
				e.Node = "node-" + itoa(i%37)
				e.Request.Host = "svc-" + itoa(i%701) + ".shop"
			}
			out[i] = e
		}
		return out
	}
	for _, c := range []struct {
		name     string
		cardinal bool
	}{{"static", false}, {"high-cardinality", true}} {
		b.Run(c.name, func(b *testing.B) {
			es := entries(c.cardinal)
			f := newFacetIndex()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f.observe(es[i%len(es)])
			}
		})
	}
}

// itoa avoids pulling in strconv just for test fixture names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// --- ServeMux smoke test -----------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestServeMuxRoutesDoNotShadowExisting(t *testing.T) {
	srv := New(discardLogger(), Options{})
	srv.store.add(sample())

	mux := http.NewServeMux()
	mux.HandleFunc("/api/entries", srv.handleEntries)
	mux.HandleFunc("/api/entry/", srv.handleEntry)
	mux.HandleFunc("/api/stats", srv.handleStats)
	mux.HandleFunc("/api/fields", srv.handleFields)
	mux.HandleFunc("/api/fields/", srv.handleFieldValues)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cases := []struct {
		path       string
		wantStatus int
	}{
		{"/api/entries", http.StatusOK},
		{"/api/stats", http.StatusOK},
		{"/api/fields", http.StatusOK},
		{"/api/fields/protocol/values", http.StatusOK},
		{"/api/fields/request.path/values", http.StatusOK}, // known but untracked -> 200 (empty list), not 404
		{"/api/fields/nonexistent/values", http.StatusNotFound},
	}
	for _, c := range cases {
		resp, err := http.Get(ts.URL + c.path)
		if err != nil {
			t.Fatalf("GET %s: %v", c.path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != c.wantStatus {
			t.Errorf("GET %s = %d, want %d", c.path, resp.StatusCode, c.wantStatus)
		}
	}
}

// TestFreshStoreStillOffersStaticEnumValues verifies that /api/fields
// surfaces protocol's static domain (e.g. "amqp"/"valkey") even with zero
// traffic observed so far.
func TestFreshStoreStillOffersStaticEnumValues(t *testing.T) {
	srv := New(discardLogger(), Options{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/fields", nil)
	srv.handleFields(rec, req)

	var body struct {
		Fields []fieldMeta `json:"fields"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	var proto *fieldMeta
	for i := range body.Fields {
		if body.Fields[i].Name == "protocol" {
			proto = &body.Fields[i]
		}
	}
	if proto == nil {
		t.Fatalf("protocol field missing from /api/fields response")
	}
	seen := map[string]bool{}
	for _, v := range proto.Values {
		seen[v.Value] = true
	}
	for _, want := range []string{"amqp", "valkey", "http"} {
		if !seen[want] {
			t.Errorf("expected protocol values to include %q even with no traffic, got %+v", want, proto.Values)
		}
	}
}

// /api/fields must surface observed header keys as synthetic
// request.header.<name>/response.header.<name> entries (DIS-12), with no
// value list (header values are freetext), alongside the static catalog.
func TestHandleFieldsIncludesObservedHeaderNames(t *testing.T) {
	srv := New(discardLogger(), Options{})
	srv.store.add(&api.Entry{
		ID:       "x",
		Protocol: api.ProtocolHTTP,
		Request:  api.Payload{Headers: map[string]string{"x-request-id": "abc"}},
		Response: api.Payload{Headers: map[string]string{"server": "nginx"}},
	})

	rec := httptest.NewRecorder()
	srv.handleFields(rec, httptest.NewRequest(http.MethodGet, "/api/fields", nil))

	var body struct {
		Fields []fieldMeta `json:"fields"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	byName := map[string]fieldMeta{}
	for _, fm := range body.Fields {
		byName[fm.Name] = fm
	}

	reqField, ok := byName["request.header.x-request-id"]
	if !ok {
		t.Fatalf("request.header.x-request-id missing from /api/fields, got %+v", byName)
	}
	if reqField.Type != FieldTypeString || len(reqField.Values) != 0 {
		t.Errorf("request.header.x-request-id = %+v, want string type with no value list", reqField)
	}
	if _, ok := byName["response.header.server"]; !ok {
		t.Errorf("response.header.server missing from /api/fields, got %+v", byName)
	}
	// A header only ever seen on the request side must not also appear on the
	// response side (and vice versa).
	if _, ok := byName["response.header.x-request-id"]; ok {
		t.Error("response.header.x-request-id should not exist (that header was only ever on the request side)")
	}
}
