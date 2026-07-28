package hub

import (
	"sort"
	"strings"
	"sync"

	"github.com/pablocolson/k8shark/pkg/api"
)

// FieldType identifies how a filterable field's values should be presented
// (and compared) in the IFL autocomplete UI.
type FieldType string

const (
	FieldTypeEnum     FieldType = "enum"     // small closed domain, == / !=
	FieldTypeNumber   FieldType = "number"   // numeric compares, unquoted values
	FieldTypeString   FieldType = "string"   // discrete-ish string, value list offered
	FieldTypeFreetext FieldType = "freetext" // high-cardinality/unbounded, no value list
)

// FieldValue is one observed (or statically known) value for a field, with
// its occurrence count. This is the hub-local JSON shape shared by
// /api/fields and /api/fields/{field}/values.
type FieldValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// FieldSpec describes one filterable field for the /api/fields catalog.
type FieldSpec struct {
	Name        string // canonical name, e.g. "dst.namespace"
	Type        FieldType
	Operators   []string // valid ops, in menu order
	TrackValues bool     // facet index records observed values for this field
	EnumValues  []string // static domain always offered (e.g. protocol, status)
}

// Operator sets by field type. "in" (list membership) applies broadly;
// "matches" (regex) and "startswith" are string-oriented, so they're offered
// for string/freetext fields but not enum/number ones (nothing stops typing
// them manually elsewhere — this only shapes the autocomplete menu).
var (
	opsEnum   = []string{"==", "!=", "in"}
	opsString = []string{"==", "!=", "contains", "matches", "startswith", "in"}
	opsNumber = []string{"==", "!=", ">", "<", ">=", "<=", "in"}
	opsText   = []string{"==", "!=", "contains", "matches", "startswith"}
)

// fieldCatalog is the authoritative list of everything the IFL autocomplete
// UI can offer, in the stable order /api/fields reports them. It mirrors the
// switch in fieldGetter (filter.go) but collapses aliases to a single
// canonical name. Value extraction reuses fieldGetter directly -- no
// duplicated accessors here.
var fieldCatalog = []FieldSpec{
	{Name: "protocol", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"http", "dns", "redis", "valkey", "postgres", "mysql", "mongodb", "kafka", "tcp", "udp", "icmp", "amqp", "ws"}},
	{Name: "status", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"success", "warning", "error"}},
	{Name: "node", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "elapsedMs", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "namespace", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "src.name", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "src.namespace", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "src.workload", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "dst.name", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "dst.namespace", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "dst.workload", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "src.ip", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "dst.ip", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "src.port", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "dst.port", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: true},
	{Name: "http.method", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "response.status", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: true},
	{Name: "request.host", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "request.path", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "dns.question", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "dns.answer", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "redis.command", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "postgres.query", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "request.body", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "response.body", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "bytes", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "packets", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "flags", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "summary", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	// EXT-3: end-to-end correlation id (traceparent trace-id / x-request-id /
	// x-correlation-id) extracted from HTTP request headers into Entry.TraceID.
	// Per-request, unbounded cardinality, so freetext and not value-tracked.
	{Name: "trace.id", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},

	// Richer sub-object fields (WS3). Enum/low-cardinality fields are tracked;
	// freetext and high-cardinality numerics are not (see performance bounds).
	{Name: "http.version", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "response.contenttype", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "dns.rcode", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "dns.type", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "redis.db", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: true},
	{Name: "redis.reply", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "postgres.error", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "postgres.statement", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "postgres.txstatus", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"I", "T", "E"}},

	// MySQL / MongoDB (DIS-11). MySQL SQL text is queryable via the shared
	// query/sql field; these add the protocol-specific extras.
	{Name: "mysql.command", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "mysql.error", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: true},
	{Name: "mongo.collection", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "mongo.command", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},

	// Kafka (DIS-8). Topic is a discrete-ish string set; api_key is a small
	// closed domain (Produce/Fetch/Metadata/...), so both are value-tracked.
	{Name: "kafka.topic", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "kafka.apikey", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "l4.ttl", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: true},
	{Name: "l4.retransmits", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.window", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.mss", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: true},
	{Name: "l4.rttms", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.durationms", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.clientbytes", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.serverbytes", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "tls.sni", Type: FieldTypeString, Operators: opsString, TrackValues: true},

	// AMQP (WS5).
	{Name: "amqp.class", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"Connection", "Channel", "Exchange", "Queue", "Basic"}},
	{Name: "amqp.method", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true},
	{Name: "amqp.exchange", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "amqp.routingkey", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "amqp.queue", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "amqp.deliverytag", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	// Basic content-header properties (DIS-9). correlation-id is per-message
	// (unbounded cardinality), so it isn't value-tracked; reply-to is
	// typically a small set of callback queues, so it is.
	{Name: "amqp.correlationid", Type: FieldTypeFreetext, Operators: opsText, TrackValues: false},
	{Name: "amqp.replyto", Type: FieldTypeString, Operators: opsString, TrackValues: true},

	// WebSocket (DIS-6). Frames captured after a 101 Switching Protocols.
	{Name: "ws.opcode", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"text", "binary", "close", "ping", "pong", "continuation"}},

	// Previously display-only fields, now filterable (roadmap: "champs backend
	// déjà calculés, invisibles côté UI").
	{Name: "redis.pipelinedepth", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: true},
	{Name: "postgres.portal", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "dns.authoritative", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"true", "false"}},
	{Name: "dns.recursionavailable", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"true", "false"}},
	{Name: "request.size", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "response.size", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "postgres.rowcount", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "http.ttfbms", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},

	// Remaining L4Info fields (previously view-only in the detail L4 tab).
	{Name: "l4.srcmac", Type: FieldTypeString, Operators: opsString, TrackValues: false},
	{Name: "l4.dstmac", Type: FieldTypeString, Operators: opsString, TrackValues: false},
	{Name: "l4.ipversion", Type: FieldTypeEnum, Operators: opsEnum, TrackValues: true,
		EnumValues: []string{"4", "6"}},
	{Name: "l4.ipflags", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "l4.clienttcpflags", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "l4.servertcpflags", Type: FieldTypeString, Operators: opsString, TrackValues: true},
	{Name: "l4.seqstart", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.ackstart", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.clientpackets", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
	{Name: "l4.serverpackets", Type: FieldTypeNumber, Operators: opsNumber, TrackValues: false},
}

// fieldSpecByName is the derived lookup table built once at init.
var fieldSpecByName map[string]FieldSpec

func init() {
	fieldSpecByName = make(map[string]FieldSpec, len(fieldCatalog))
	for _, spec := range fieldCatalog {
		fieldSpecByName[spec.Name] = spec
	}
}

const (
	// facetTrackCap bounds how many distinct values are tracked per field, so
	// memory stays flat regardless of cardinality (e.g. free-form request
	// hosts or IPs).
	facetTrackCap = 200
	// facetTopN is how many top values (by count) are surfaced per field in
	// the /api/fields bulk snapshot.
	facetTopN = 50
	// facetEvictSample is how many keys the at-cap eviction looks at before
	// dropping the least-seen of them. Go randomises map iteration order, so
	// the first k keys are a free random sample — no reservoir bookkeeping, no
	// extra state. Scanning all facetTrackCap keys instead (the previous
	// behaviour) ran on *every* value of a saturated high-cardinality field
	// (src.ip, pod names), i.e. thousands of times a second under one
	// process-wide mutex; a sample keeps the counter at cap for the same cost
	// as a handful of map probes. Still space-saving in spirit, and as before
	// not a strict guarantee about which key goes.
	facetEvictSample = 8
)

// fieldCounter holds observed value counts for a single tracked field. It has
// no mutex of its own -- callers hold the parent facetIndex's mu. get is
// resolved once at construction (see newFacetIndex) rather than looked up by
// name on every observed entry, since fieldGetter's switch would otherwise be
// re-traversed (and a fresh closure allocated) ~45 times per entry ingested.
type fieldCounter struct {
	get    func(*api.Entry) string
	counts map[string]int64
}

// increment bumps v's count. If v is a brand new key and the counter is
// already at facetTrackCap distinct values, the lowest-count key of a random
// facetEvictSample-sized sample is evicted first, keeping the counter at cap
// (see facetEvictSample -- space-saving in spirit, not a strict guarantee).
// Caller holds facetIndex.mu.
func (fc *fieldCounter) increment(v string) {
	if _, exists := fc.counts[v]; !exists && len(fc.counts) >= facetTrackCap {
		var evictKey string
		var evictCount int64
		seen := 0
		for k, c := range fc.counts {
			if seen == 0 || c < evictCount {
				evictKey, evictCount = k, c
			}
			seen++
			if seen == facetEvictSample {
				break
			}
		}
		if seen > 0 {
			delete(fc.counts, evictKey)
		}
	}
	fc.counts[v]++
}

// facetGate groups tracked fields that all read through the same nil-guarded
// sub-object, with the one presence test that decides whether any of them can
// possibly yield a value. observe() runs per ingested entry, and the great
// majority of the ~50 tracked fields belong to a protocol the entry isn't:
// checking `e.Request.Redis != nil` once skips every redis getter in one
// branch instead of calling each to have it return "".
//
// Gating on the sub-object pointer rather than on e.Protocol is deliberate:
// the counts must come out *identical* to calling every getter, and only the
// nil guard proves that. Protocol is not a safe proxy — several tracked fields
// read shared Payload members that more than one dissector fills (http.method
// is also an AMQP entry's "Publish"/"Consume", via Request.Method), so keying
// off e.Protocol would silently change what /api/fields reports.
type facetGate struct {
	present func(*api.Entry) bool
	fields  []string
}

// facetGates lists every tracked catalog field whose getter is guarded by a
// sub-object pointer, grouped by that pointer. Fields absent from this list are
// evaluated for every entry (they read plain Payload/Endpoint members, which
// any protocol may carry). Keep it in sync with fieldGetter: a field listed
// here whose getter no longer nil-guards on the same pointer would under-count
// -- TestFacetGatesMatchGetters pins that.
var facetGates = []facetGate{
	{func(e *api.Entry) bool { return e.Request.HTTP != nil }, []string{"http.version"}},
	{func(e *api.Entry) bool { return e.Request.DNS != nil }, []string{"dns.type"}},
	{func(e *api.Entry) bool { return e.Response.DNS != nil }, []string{"dns.rcode", "dns.authoritative", "dns.recursionavailable"}},
	{func(e *api.Entry) bool { return e.Request.Redis != nil }, []string{"redis.db", "redis.pipelinedepth"}},
	{func(e *api.Entry) bool { return e.Request.Postgres != nil }, []string{"postgres.statement", "postgres.portal"}},
	{func(e *api.Entry) bool { return e.Response.Postgres != nil }, []string{"postgres.error", "postgres.txstatus"}},
	{func(e *api.Entry) bool { return e.Request.MySQL != nil }, []string{"mysql.command"}},
	{func(e *api.Entry) bool { return e.Response.MySQL != nil }, []string{"mysql.error"}},
	{func(e *api.Entry) bool { return e.Request.Mongo != nil }, []string{"mongo.collection", "mongo.command"}},
	{func(e *api.Entry) bool { return e.Request.Kafka != nil }, []string{"kafka.topic", "kafka.apikey"}},
	{func(e *api.Entry) bool { return e.L4 != nil }, []string{
		"l4.ttl", "l4.mss", "l4.ipversion", "l4.ipflags", "l4.clienttcpflags", "l4.servertcpflags", "tls.sni",
	}},
}

// facetGroup is a compiled facetGate: the presence test plus the counters it
// guards, resolved once at construction.
type facetGroup struct {
	present  func(*api.Entry) bool
	counters []*fieldCounter
}

// facetIndex tracks observed values per field, for IFL autocomplete. It owns
// its own mutex, fully decoupled from store.mu.
type facetIndex struct {
	mu     sync.Mutex
	fields map[string]*fieldCounter // canonical field name -> counter (TrackValues fields only)

	// ungated/groups are the ingest-path view of fields: a flat slice (ranging
	// a map re-hashes every bucket per entry, and observe() runs on every one)
	// split into the counters every entry must be checked against and the
	// sub-object-gated groups (see facetGate). Both hold the same *fieldCounter
	// pointers the fields map does -- one counter, two indexes.
	ungated []*fieldCounter
	groups  []facetGroup

	// requestHeaderNames/responseHeaderNames track distinct HTTP header keys
	// observed on each side, powering request.header.<name>/
	// response.header.<name> field-*name* autocomplete (DIS-12): unlike
	// fields above, a single entry can contribute many keys at once and
	// there's no fixed catalog entry to key on (the header name is
	// open-ended), so these live outside the fields map and are surfaced
	// separately -- see headerFieldNames, consumed by handleFields.
	requestHeaderNames  *fieldCounter
	responseHeaderNames *fieldCounter
}

// newFacetIndex builds an index pre-populated with one counter per
// TrackValues==true entry in fieldCatalog, each holding its resolved
// fieldGetter so observe() never has to look one up by name again.
func newFacetIndex() *facetIndex {
	f := &facetIndex{
		fields:              make(map[string]*fieldCounter),
		requestHeaderNames:  &fieldCounter{counts: map[string]int64{}},
		responseHeaderNames: &fieldCounter{counts: map[string]int64{}},
	}
	for _, spec := range fieldCatalog {
		if !spec.TrackValues {
			continue
		}
		get := fieldGetter(spec.Name)
		if get == nil {
			continue // catalog/getter drift — never panic the ingest path
		}
		f.fields[spec.Name] = &fieldCounter{get: get, counts: map[string]int64{}}
	}

	// Split the counters into the ingest-path views. A field named by a gate but
	// missing from fields (untracked or dropped by the drift guard above) is
	// simply skipped, so a stale gate entry can never resurrect a counter.
	gated := make(map[string]bool, len(facetGates))
	for _, g := range facetGates {
		grp := facetGroup{present: g.present}
		for _, name := range g.fields {
			fc, ok := f.fields[name]
			if !ok {
				continue
			}
			gated[name] = true
			grp.counters = append(grp.counters, fc)
		}
		if len(grp.counters) > 0 {
			f.groups = append(f.groups, grp)
		}
	}
	// Catalog order, so the ingest path walks the counters deterministically.
	for _, spec := range fieldCatalog {
		if fc, ok := f.fields[spec.Name]; ok && !gated[spec.Name] {
			f.ungated = append(f.ungated, fc)
		}
	}
	return f
}

// observe records one entry's tracked field values, using each counter's
// getter resolved once at construction (see newFacetIndex) -- no duplicated
// field-accessor logic and no per-entry, per-field lookup into filter.go's
// fieldGetter switch. Protocol-specific counters are reached through their
// sub-object gate (see facetGate) so an entry only pays for the getters that
// can yield anything; the recorded counts are the same either way. It also
// records any HTTP header keys present, for headerFieldNames.
func (f *facetIndex) observe(e *api.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fc := range f.ungated {
		v := fc.get(e)
		if v == "" {
			continue
		}
		fc.increment(v)
	}
	for _, g := range f.groups {
		if !g.present(e) {
			continue
		}
		for _, fc := range g.counters {
			v := fc.get(e)
			if v == "" {
				continue
			}
			fc.increment(v)
		}
	}
	for name := range e.Request.Headers {
		f.requestHeaderNames.increment(name)
	}
	for name := range e.Response.Headers {
		f.responseHeaderNames.increment(name)
	}
}

// headerFieldNames returns the observed request/response header keys
// (bounded to facetTrackCap distinct keys per side, same as any other
// tracked field), sorted by occurrence count descending then name ascending.
// handleFields turns each into a synthetic "request.header.<name>" /
// "response.header.<name>" catalog entry so the front's field-name
// autocomplete can offer them, even though they aren't in the static
// fieldCatalog.
func (f *facetIndex) headerFieldNames() (req, resp []string) {
	f.mu.Lock()
	reqVals := countsToFieldValues(f.requestHeaderNames.counts)
	respVals := countsToFieldValues(f.responseHeaderNames.counts)
	f.mu.Unlock()

	sortFieldValues(reqVals)
	sortFieldValues(respVals)
	return fieldValueNames(reqVals), fieldValueNames(respVals)
}

// countsToFieldValues copies a counts map into a FieldValue slice. Caller
// holds facetIndex.mu.
func countsToFieldValues(counts map[string]int64) []FieldValue {
	out := make([]FieldValue, 0, len(counts))
	for v, c := range counts {
		out = append(out, FieldValue{Value: v, Count: c})
	}
	return out
}

// fieldValueNames extracts just the Value of each FieldValue, preserving order.
func fieldValueNames(vals []FieldValue) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = v.Value
	}
	return out
}

// values returns field's observed values matching prefix (case-insensitive
// prefix match), sorted by count descending then value ascending as a
// tiebreak, truncated to limit. The second return is whether field is
// tracked at all (false for freetext/untracked/unknown fields).
func (f *facetIndex) values(field, prefix string, limit int) ([]FieldValue, bool) {
	f.mu.Lock()
	fc, ok := f.fields[field]
	if !ok {
		f.mu.Unlock()
		return nil, false
	}
	lowerPrefix := strings.ToLower(prefix)
	out := make([]FieldValue, 0, len(fc.counts))
	for v, c := range fc.counts {
		if prefix == "" || strings.HasPrefix(strings.ToLower(v), lowerPrefix) {
			out = append(out, FieldValue{Value: v, Count: c})
		}
	}
	f.mu.Unlock()

	sortFieldValues(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, true
}

// snapshot returns the top facetTopN values (count desc, value asc tiebreak)
// for every tracked field. Used to build the /api/fields bulk response.
func (f *facetIndex) snapshot() map[string][]FieldValue {
	f.mu.Lock()
	raw := make(map[string][]FieldValue, len(f.fields))
	for name, fc := range f.fields {
		vals := make([]FieldValue, 0, len(fc.counts))
		for v, c := range fc.counts {
			vals = append(vals, FieldValue{Value: v, Count: c})
		}
		raw[name] = vals
	}
	f.mu.Unlock()

	out := make(map[string][]FieldValue, len(raw))
	for name, vals := range raw {
		sortFieldValues(vals)
		if len(vals) > facetTopN {
			vals = vals[:facetTopN]
		}
		out[name] = vals
	}
	return out
}

// sortFieldValues sorts count descending, then value ascending as a tiebreak.
func sortFieldValues(vals []FieldValue) {
	sort.Slice(vals, func(i, j int) bool {
		if vals[i].Count != vals[j].Count {
			return vals[i].Count > vals[j].Count
		}
		return vals[i].Value < vals[j].Value
	})
}
