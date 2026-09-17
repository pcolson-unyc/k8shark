package hub

import (
	"strings"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

func sample() *api.Entry {
	return &api.Entry{
		Protocol:    api.ProtocolHTTP,
		Node:        "node-1",
		Status:      "error",
		StatusCode:  503,
		Source:      api.Endpoint{IP: "10.0.1.10", Port: 34567, Name: "frontend", Namespace: "shop"},
		Destination: api.Endpoint{IP: "10.0.1.14", Port: 8080, Name: "payment", Namespace: "shop"},
		Request:     api.Payload{Method: "POST", Path: "/api/checkout", Host: "payment.shop"},
		Response:    api.Payload{StatusCode: 503},
	}
}

func TestCompileFilter(t *testing.T) {
	e := sample()
	cases := []struct {
		expr string
		want bool
	}{
		{"", true},
		{`protocol == "http"`, true},
		{`protocol == "dns"`, false},
		{`protocol != "dns"`, true},
		{"response.status >= 500", true},
		{"response.status > 503", false},
		{"response.status >= 500 and http.method == \"POST\"", true},
		{"response.status < 500 or dst.name == \"payment\"", true},
		{`http.method == "GET"`, false},
		{`request.path contains "checkout"`, true},
		{`request.path contains "cart"`, false},
		{`not (protocol == "dns")`, true},
		{`dst.namespace == "shop" and src.name == "frontend"`, true},
		{`status == "error"`, true},
		{"checkout", true},           // full-text
		{"nonexistent-token", false}, // full-text miss
		{`dst.port == 8080`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestNamespaceFilter exercises the bare "namespace"/"ns" field, which
// matches either src or dst rather than a single struct field — sample()
// isn't useful here since both sides share the same namespace, so this uses
// an entry with two distinct ones.
func TestNamespaceFilter(t *testing.T) {
	e := &api.Entry{
		Source:      api.Endpoint{Namespace: "shop"},
		Destination: api.Endpoint{Namespace: "platform"},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`namespace == "shop"`, true},         // matches src
		{`namespace == "platform"`, true},     // matches dst
		{`namespace == "kube-system"`, false}, // matches neither
		{`ns == "shop"`, true},                // alias
		{`namespace contains "plat"`, true},   // substring on dst
		// != means "neither side matches" (exclude noise), not the De
		// Morgan-literal "either side differs" (which response.status-style
		// != would make true for nearly every entry here).
		{`namespace != "shop"`, false},       // src does match "shop"
		{`namespace != "kube-system"`, true}, // neither side is kube-system
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

// richEntry exercises the WS3 sub-object filter fields.
func richEntry() *api.Entry {
	return &api.Entry{
		Protocol: api.ProtocolPostgres,
		Status:   "error",
		Request: api.Payload{
			Size:     12,
			HTTP:     &api.HTTPDetail{Version: "HTTP/2.0", ContentType: "application/grpc"},
			Redis:    &api.RedisDetail{DBIndex: 3, PipelineDepth: 2},
			Postgres: &api.PGDetail{StatementName: "stmt_s1", Portal: "p1"},
			DNS:      &api.DNSDetail{Questions: []api.DNSQuestion{{Name: "x", Type: "AAAA"}}},
		},
		Response: api.Payload{
			ContentType: "application/json",
			Size:        99,
			RowCount:    7,
			DNS: &api.DNSDetail{
				Rcode: "NXDOMAIN", Answers: []api.DNSRecord{{Data: "1.2.3.4"}},
				Authoritative: true, RecursionAvl: true,
			},
			Redis:    &api.RedisDetail{Reply: "OK"},
			Postgres: &api.PGDetail{Error: &api.PGError{Code: "40P01"}, TxStatus: "E"},
			HTTP:     &api.HTTPDetail{TTFBMs: 42},
		},
		L4: &api.L4Info{
			TTL: 64, Retransmits: 2, MSS: 1460, Window: 64240, RTTMs: 1.5, ClientBytes: 100,
			SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", IPVersion: 4, IPFlags: "DF",
			ClientTCPFlags: "SYN,ACK", ServerTCPFlags: "SYN,ACK,FIN", SeqStart: 1000, AckStart: 2000,
			DurationMs: 250, ClientPackets: 5, ServerPackets: 7,
			TLS: &api.TLSInfo{SNI: "api.example.com"},
		},
	}
}

func TestCompileFilterRichFields(t *testing.T) {
	e := richEntry()
	cases := []struct {
		expr string
		want bool
	}{
		{`l4.retransmits > 0`, true},
		{`l4.retransmits == 2`, true},
		{`l4.ttl == 64`, true},
		{`l4.mss >= 1400`, true},
		{`dns.rcode == "NXDOMAIN"`, true},
		{`dns.rcode == "NOERROR"`, false},
		{`dns.type == "AAAA"`, true},
		{`postgres.statement contains "s1"`, true},
		{`postgres.error == "40P01"`, true},
		{`pg.code == "40P01"`, true},
		{`postgres.txstatus == "E"`, true},
		{`http.version == "HTTP/2.0"`, true},
		{`response.contenttype contains "json"`, true},
		{`redis.db == 3`, true},
		{`redis.reply == "OK"`, true},
		{`tls.sni contains "example.com"`, true},
		{`tls.sni == "other"`, false},
		{"api.example.com", true}, // full-text via SNI
		{"1.2.3.4", true},         // full-text via DNS answer data

		// Previously display-only fields, now filterable.
		{`redis.pipelinedepth == 2`, true},
		{`redis.pipelinedepth > 5`, false},
		{`postgres.portal == "p1"`, true},
		{`dns.authoritative == "true"`, true},
		{`dns.recursionavailable == "true"`, true},
		{`dns.recursionavl == "true"`, true},
		{`request.size == 12`, true},
		{`response.size > 50`, true},
		{`postgres.rowcount == 7`, true},
		{`rowcount == 7`, true},
		{`http.ttfbms == 42`, true},

		// Remaining L4Info fields.
		{`l4.srcmac == "aa:bb:cc:dd:ee:ff"`, true},
		{`l4.dstmac contains "55:66"`, true},
		{`l4.ipversion == 4`, true},
		{`l4.ipflags == "DF"`, true},
		{`l4.clienttcpflags contains "SYN"`, true},
		{`l4.servertcpflags == "SYN,ACK,FIN"`, true},
		{`l4.seqstart == 1000`, true},
		{`l4.ackstart == 2000`, true},
		{`l4.durationms >= 250`, true},
		{`l4.clientpackets == 5`, true},
		{`l4.serverpackets == 7`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestCompileFilterAMQP(t *testing.T) {
	e := &api.Entry{
		Protocol: api.ProtocolAMQP,
		Status:   "success",
		Request: api.Payload{
			Class: "Basic", Method: "Publish", Exchange: "orders", RoutingKey: "new",
			Queue: "payments", DeliveryTag: 42, Summary: "PUBLISH orders/new",
		},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`protocol == "amqp"`, true},
		{`protocol == "amqp" and amqp.exchange == "orders"`, true},
		{`amqp.routingkey == "new"`, true},
		{`amqp.routing-key == "new"`, true},
		{`amqp.queue == "payments"`, true},
		{`amqp.deliverytag == 42`, true},
		{`amqp.class == "Basic"`, true},
		{`amqp.method == "Publish"`, true},
		{`amqp.exchange == "other"`, false},
		{"orders", true}, // full-text via exchange
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	// amqp.method must not leak HTTP verbs (Method is a shared field).
	http := &api.Entry{Protocol: api.ProtocolHTTP, Request: api.Payload{Method: "POST"}}
	pred, _ := CompileFilter(`amqp.method == "POST"`)
	if pred(http) {
		t.Error("amqp.method matched an HTTP POST (should be AMQP-scoped)")
	}
}

// mongo.collection / mongo.command resolve against the OP_MSG-extracted
// MongoDetail; mysql.command / mysql.error against the MySQLDetail, and MySQL
// SQL text via the shared query field (DIS-11).
func TestCompileFilterMongoAndMySQL(t *testing.T) {
	mongo := &api.Entry{
		Protocol: api.ProtocolMongo,
		Status:   "error",
		Request:  api.Payload{Query: "find users", Summary: "find users", Mongo: &api.MongoDetail{Command: "find", Collection: "users", Database: "shop"}},
		Response: api.Payload{Summary: "not authorized", Mongo: &api.MongoDetail{ErrMsg: "not authorized"}},
	}
	mysql := &api.Entry{
		Protocol: api.ProtocolMySQL,
		Status:   "error",
		Request:  api.Payload{Query: "SELECT id FROM users", Summary: "SELECT id FROM users", MySQL: &api.MySQLDetail{Command: "COM_QUERY"}},
		Response: api.Payload{Summary: "ERROR 1146", MySQL: &api.MySQLDetail{ErrorCode: 1146, ErrorMessage: "Table doesn't exist"}},
	}
	cases := []struct {
		e    *api.Entry
		expr string
		want bool
	}{
		{mongo, `protocol == "mongodb"`, true},
		{mongo, `mongo.collection == "users"`, true},
		{mongo, `mongo.collection == "orders"`, false},
		{mongo, `mongo.collection contains "use"`, true},
		{mongo, `mongo.command == "find"`, true},
		{mongo, `"find users"`, true}, // full-text via query/summary
		{mysql, `protocol == "mysql"`, true},
		{mysql, `mysql.command == "COM_QUERY"`, true},
		{mysql, `mysql.error == 1146`, true},
		{mysql, `mysql.error > 1000`, true},
		{mysql, `query contains "users"`, true}, // shared SQL text field
		{mysql, `sql contains "SELECT"`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(c.e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	// mongo.collection is empty (never matches) on a non-mongo entry.
	pred, _ := CompileFilter(`mongo.collection == "users"`)
	if pred(&api.Entry{Protocol: api.ProtocolHTTP}) {
		t.Error("mongo.collection matched a non-MongoDB entry")
	}
}

// kafka.topic / kafka.apikey resolve against the request-side KafkaDetail
// extracted from the request header/body (DIS-8).
func TestCompileFilterKafka(t *testing.T) {
	e := &api.Entry{
		Protocol: api.ProtocolKafka,
		Status:   "success",
		Request: api.Payload{
			Summary: "PRODUCE topic=orders (v9)",
			Kafka:   &api.KafkaDetail{APIKey: "Produce", APIVersion: 9, Topic: "orders", ClientID: "producer-1", CorrelationID: 42},
		},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`protocol == "kafka"`, true},
		{`kafka.topic == "orders"`, true},
		{`kafka.topic == "payments"`, false},
		{`kafka.topic contains "ord"`, true},
		{`kafka.apikey == "Produce"`, true},
		{`kafka.apikey == "produce"`, true}, // case-insensitive
		{`kafka.apikey == "Fetch"`, false},
		{`protocol == "kafka" and kafka.topic == "orders"`, true},
		{"orders", true}, // full-text via topic/summary
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	// kafka.topic is empty (never matches) on a non-Kafka entry.
	pred, _ := CompileFilter(`kafka.topic == "orders"`)
	if pred(&api.Entry{Protocol: api.ProtocolHTTP}) {
		t.Error("kafka.topic matched a non-Kafka entry")
	}
}

// ws.opcode resolves against a post-101 WebSocket frame entry (DIS-6).
func TestCompileFilterWebSocket(t *testing.T) {
	e := &api.Entry{
		Protocol: api.ProtocolWS,
		Status:   "success",
		Request:  api.Payload{WSOpcode: "text", Summary: "text hello", Body: "hello"},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`protocol == "ws"`, true},
		{`ws.opcode == "text"`, true},
		{`ws.opcode == "binary"`, false},
		{`ws.opcode in ("text", "close")`, true},
		{`protocol == "ws" and ws.opcode == "text"`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	// ws.opcode is empty (never matches) on a non-ws entry.
	http := &api.Entry{Protocol: api.ProtocolHTTP, Request: api.Payload{Method: "GET"}}
	pred, _ := CompileFilter(`ws.opcode == "text"`)
	if pred(http) {
		t.Error("ws.opcode matched a non-WebSocket entry")
	}
}

// request.header.<name>/response.header.<name> resolve against the already-
// captured (and lowercased, per flattenHeaders) Payload.Headers map, matching
// case-insensitively on the field name itself same as any other field; a bare
// prefix with no header name is an unknown field, not a match-nothing.
func TestHTTPHeaderFilterFields(t *testing.T) {
	e := &api.Entry{
		Protocol: api.ProtocolHTTP,
		Request:  api.Payload{Headers: map[string]string{"x-request-id": "abc-123", "content-type": "application/json"}},
		Response: api.Payload{Headers: map[string]string{"content-type": "application/json", "server": "nginx"}},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`request.header.x-request-id == "abc-123"`, true},
		{`request.header.X-Request-Id == "abc-123"`, true}, // field name is case-insensitive
		{`request.header.x-request-id == "other"`, false},
		{`request.header.content-type contains "json"`, true},
		{`response.header.server == "nginx"`, true},
		{`response.header.x-request-id == "abc-123"`, false}, // request-only header, not on response
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	if _, err := CompileFilter(`request.header. == "x"`); err == nil {
		t.Error(`"request.header." with no name should be a compile error, not a silent match-nothing`)
	}
}

// trace.id (EXT-3) resolves against the top-level Entry.TraceID: it matches an
// entry carrying that correlation id and not others, and never matches an entry
// with no trace id.
func TestCompileFilterTraceID(t *testing.T) {
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	e := &api.Entry{Protocol: api.ProtocolHTTP, TraceID: traceID}
	cases := []struct {
		expr string
		want bool
	}{
		{`trace.id == "` + traceID + `"`, true},
		{`trace.id == "deadbeef"`, false},
		{`trace.id contains "929d"`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	// An entry without a trace id must not match.
	pred, err := CompileFilter(`trace.id == "` + traceID + `"`)
	if err != nil {
		t.Fatal(err)
	}
	if pred(&api.Entry{Protocol: api.ProtocolHTTP}) {
		t.Error("trace.id matched an entry with no TraceID")
	}
}

// Numeric L4 fields must not spuriously match when L4 is absent (missing => ""
// not "0").
func TestL4FieldMissingIsEmpty(t *testing.T) {
	e := &api.Entry{Protocol: api.ProtocolHTTP}
	pred, err := CompileFilter(`l4.retransmits == 0`)
	if err != nil {
		t.Fatal(err)
	}
	if pred(e) {
		t.Error(`l4.retransmits == 0 matched an entry with no L4 (want false)`)
	}
}

func TestCompileFilterErrors(t *testing.T) {
	for _, expr := range []string{`protocol == `, `( protocol == "http"`, `"unterminated`} {
		if _, err := CompileFilter(expr); err == nil {
			t.Errorf("expected error for %q, got nil", expr)
		}
	}
}

// Latency and workload are first-class filter fields — the two most common
// debugging pivots ("what's slow?", "which service?").
func TestCompileFilterLatencyAndWorkload(t *testing.T) {
	e := sample()
	e.ElapsedMs = 750
	e.Source.Workload = "frontend"
	e.Destination.Workload = "payment"
	e.L4 = &api.L4Info{DurationMs: 1200}
	cases := []struct {
		expr string
		want bool
	}{
		{`elapsedMs > 500`, true},
		{`elapsedms > 500`, true}, // case-insensitive
		{`latency > 500`, true},   // alias
		{`elapsedMs > 800`, false},
		{`elapsedMs <= 750`, true},
		{`src.workload == "frontend"`, true},
		{`dst.workload == "payment"`, true},
		{`dst.workload == "checkout"`, false},
		{`l4.durationms >= 1000`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	// l4.durationms must not match when L4 is absent.
	pred, _ := CompileFilter(`l4.durationms == 0`)
	if pred(sample()) {
		t.Error("l4.durationms == 0 matched an entry with no L4 (want false)")
	}
}

// An unknown field in a comparison must be a compile error, not a silent
// match-nothing — a typo would otherwise read as "no matching traffic".
func TestCompileFilterUnknownField(t *testing.T) {
	for _, expr := range []string{
		`http.status_code == 500`, // typo of response.status
		`namespcae == "shop"`,
		`elapsed_ms > 100`,
	} {
		if _, err := CompileFilter(expr); err == nil {
			t.Errorf("expected unknown-field error for %q, got nil", expr)
		}
	}
	// Bare tokens (full-text) still compile — only `field op value` is strict.
	if _, err := CompileFilter("checkout"); err != nil {
		t.Errorf("bare token should compile, got %v", err)
	}
}

// Every catalog entry must resolve through fieldGetter, so the /api/fields
// autocomplete never advertises a field the filter would then reject.
func TestFieldCatalogMatchesGetter(t *testing.T) {
	for _, spec := range fieldCatalog {
		if fieldGetter(spec.Name) == nil {
			t.Errorf("catalog field %q has no fieldGetter case", spec.Name)
		}
	}
}

// TestCompileFilterDoS guards the unauthenticated ?filter= surface: a
// pathologically nested or oversized expression must return an error, never a
// panic/stack-overflow crash.
func TestCompileFilterDoS(t *testing.T) {
	// Thousands of leading '(' — would recurse into a stack overflow without the
	// depth guard.
	if _, err := CompileFilter(strings.Repeat("(", 5000)); err == nil {
		t.Error("5000 '(' should error, got nil")
	}
	// A long "not not not ..." chain — same deep-recursion risk via parseUnary.
	if _, err := CompileFilter(strings.Repeat("not ", 5000) + "checkout"); err == nil {
		t.Error("long 'not' chain should error, got nil")
	}
	// An oversized (but well-formed-looking) input is rejected before parsing.
	if _, err := CompileFilter(strings.Repeat("a", maxFilterLen+1)); err == nil {
		t.Error("oversized filter should error, got nil")
	}

	// A normal, moderately-nested filter still compiles and evaluates correctly.
	pred, err := CompileFilter(`not (protocol == "dns" or (dst.namespace == "shop" and http.method == "POST"))`)
	if err != nil {
		t.Fatalf("moderately-nested filter errored: %v", err)
	}
	if pred(sample()) {
		t.Error("expected the sample (http POST in shop) to be excluded by the negation")
	}
}

// TestMatchesOperator exercises the regex "matches" operator.
func TestMatchesOperator(t *testing.T) {
	e := sample() // Request.Path == "/api/checkout"
	cases := []struct {
		expr string
		want bool
	}{
		{`request.path matches "^/api/"`, true},
		{`request.path matches "^/v[0-9]+/"`, false},
		{`request.path matches "check.ut"`, true}, // "." matches any char, unanchored
		{`request.host matches "^payment"`, true},
		{`request.host matches "^shop"`, false},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestMatchesOperatorRejectsInvalidRegex(t *testing.T) {
	if _, err := CompileFilter(`request.path matches "(unclosed"`); err == nil {
		t.Error("an invalid regex should fail to compile, got nil error")
	}
}

func TestMatchesOperatorRejectsOversizedPattern(t *testing.T) {
	huge := strings.Repeat("a", maxRegexLen+1)
	if _, err := CompileFilter(`request.path matches "` + huge + `"`); err == nil {
		t.Error("an oversized regex pattern should be rejected, got nil error")
	}
}

// TestStartswithOperator exercises the "startswith" operator (case-insensitive
// prefix match).
func TestStartswithOperator(t *testing.T) {
	e := sample() // Request.Host == "payment.shop"
	cases := []struct {
		expr string
		want bool
	}{
		{`request.host startswith "payment"`, true},
		{`request.host startswith "PAYMENT"`, true}, // case-insensitive
		{`request.host startswith "shop"`, false},
		{`request.path startswith "/api"`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestCIDRMatching exercises == / != against a CIDR literal on an IP field:
// range containment, not the literal string equality every other == compare
// does (dst.ip is never itself the literal string "10.0.0.0/8", so this
// can't misfire against a real exact-match use).
func TestCIDRMatching(t *testing.T) {
	e := sample() // Source.IP == "10.0.1.10", Destination.IP == "10.0.1.14"
	cases := []struct {
		expr string
		want bool
	}{
		{`dst.ip == "10.0.0.0/8"`, true},
		{`dst.ip == "10.0.1.0/24"`, true},
		{`dst.ip == "10.0.1.14/32"`, true}, // single-host CIDR
		{`dst.ip == "10.0.2.0/24"`, false}, // adjacent /24, not containing
		{`dst.ip == "192.168.0.0/16"`, false},
		{`dst.ip != "10.0.2.0/24"`, true}, // negation: not contained -> true
		{`dst.ip != "10.0.0.0/8"`, false}, // negation: contained -> false
		{`src.ip == "10.0.1.0/24"`, true},
		{`dst.ip == "10.0.1.14"`, true}, // plain literal, unaffected by CIDR handling
		{`dst.ip == "10.0.1.15"`, false},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestCIDRMatchingIPv6 mirrors TestCIDRMatching for an IPv6 destination —
// net.ParseCIDR/ParseIP handle both families, so this should need no
// separate code path.
func TestCIDRMatchingIPv6(t *testing.T) {
	e := sample()
	e.Destination.IP = "2001:db8::1"
	cases := []struct {
		expr string
		want bool
	}{
		{`dst.ip == "2001:db8::/32"`, true},
		{`dst.ip == "2001:db9::/32"`, false},
		{`dst.ip != "2001:db9::/32"`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestCIDRMatchingFallsBackOnUnparseableCIDR checks that a want value which
// merely contains a slash but isn't a valid CIDR (or an actual value that
// isn't a parseable IP) degrades to a plain false rather than panicking or
// erroring — the compile still succeeds, it just never matches.
func TestCIDRMatchingFallsBackOnUnparseableCIDR(t *testing.T) {
	e := sample()
	for _, expr := range []string{
		`dst.ip == "not/a/cidr"`,
		`request.path == "10.0.0.0/8"`, // want parses as CIDR, actual ("/api/checkout") isn't an IP
	} {
		pred, err := CompileFilter(expr)
		if err != nil {
			t.Fatalf("CompileFilter(%q) error: %v", expr, err)
		}
		if pred(e) {
			t.Errorf("filter %q matched, want false", expr)
		}
	}
}

// TestInOperator exercises the "in (...)" list-membership operator: quoted
// strings, bare numbers, case-insensitivity, and the either-side namespace
// pseudo-field.
func TestInOperator(t *testing.T) {
	e := sample() // dst.namespace == "shop", response.status == 503
	cases := []struct {
		expr string
		want bool
	}{
		{`dst.namespace in ("shop", "platform")`, true},
		{`dst.namespace in ("PLATFORM", "SHOP")`, true}, // case-insensitive
		{`dst.namespace in ("prod", "staging")`, false},
		{`response.status in (500, 502, 503)`, true},
		{`response.status in (200, 201)`, false},
		{`namespace in ("shop")`, true}, // either-side pseudo-field
		{`namespace in ("kube-system")`, false},
		{`protocol in ("http", "dns")`, true},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Errorf("CompileFilter(%q) error: %v", c.expr, err)
			continue
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestInOperatorSyntaxErrors(t *testing.T) {
	cases := []string{
		`dst.namespace in`,                 // missing list entirely
		`dst.namespace in "shop"`,          // missing parens
		`dst.namespace in (`,               // unterminated
		`dst.namespace in ()`,              // empty list
		`dst.namespace in ("shop"`,         // missing closing paren
		`dst.namespace in ("shop" "prod")`, // missing comma
	}
	for _, expr := range cases {
		if _, err := CompileFilter(expr); err == nil {
			t.Errorf("CompileFilter(%q) should have errored", expr)
		}
	}
}

func TestInOperatorRejectsOversizedList(t *testing.T) {
	var items []string
	for i := 0; i < maxInListLen+1; i++ {
		items = append(items, `"x"`)
	}
	expr := `dst.namespace in (` + strings.Join(items, ", ") + `)`
	if _, err := CompileFilter(expr); err == nil {
		t.Error("an oversized in-list should be rejected, got nil error")
	}
}

// An ordering comparison against a non-numeric literal used to compile fine
// and then silently match nothing — `elapsedMs > "abc"` reading as "no slow
// traffic" rather than "you typed nonsense". Now that the literal is parsed
// once at compile time (instead of on every evaluation), reject it there, the
// same stance the language already takes on an unknown field name.
func TestOrderingOperatorRejectsNonNumericLiteral(t *testing.T) {
	for _, expr := range []string{
		`elapsedMs > "abc"`,
		`response.status < "five hundred"`,
		`dst.port >= "high"`,
		`l4.ttl <= "x"`,
	} {
		if _, err := CompileFilter(expr); err == nil {
			t.Errorf("CompileFilter(%q) should reject a non-numeric literal for an ordering operator", expr)
		}
	}
	// A numeric literal — quoted or bare — still compiles and evaluates.
	e := sample() // StatusCode 503
	for _, expr := range []string{`response.status > 500`, `response.status > "500"`} {
		pred, err := CompileFilter(expr)
		if err != nil {
			t.Fatalf("CompileFilter(%q) error: %v", expr, err)
		}
		if !pred(e) {
			t.Errorf("filter %q = false, want true", expr)
		}
	}
	// An unknown field is still reported as such, not as a bad literal, when
	// both are wrong.
	_, err := CompileFilter(`bogus.field > "abc"`)
	if err == nil || !strings.Contains(err.Error(), "unknown filter field") {
		t.Errorf("bogus.field > \"abc\" error = %v, want an unknown-field error", err)
	}
}

// The value on the right of a comparison is a constant of the expression, so
// its CIDR/numeric/lowercase form is derived once at compile time. This pins
// the observable half of that: a compiled predicate must not allocate per
// evaluation for a plain string compare.
func TestComparisonPredicateDoesNotAllocatePerEval(t *testing.T) {
	pred, err := CompileFilter(`http.method == "POST"`)
	if err != nil {
		t.Fatal(err)
	}
	e := sample()
	if allocs := testing.AllocsPerRun(100, func() { _ = pred(e) }); allocs != 0 {
		t.Errorf("`http.method == \"POST\"` allocates %.1f times per evaluation, want 0 "+
			"(the right-hand literal must be parsed at compile time, not per entry)", allocs)
	}
	// Same for the either-side namespace pseudo-field, which applies the
	// matcher twice per entry.
	nsPred, err := CompileFilter(`namespace != "kube-system"`)
	if err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = nsPred(e) }); allocs != 0 {
		t.Errorf("`namespace != \"kube-system\"` allocates %.1f times per evaluation, want 0", allocs)
	}
}

// "contains" folds case on both sides. The needle is pre-lowered at compile
// time and tried against the raw value first (payload text is usually already
// lowercase), so this pins that the fallback still matches a mixed-case value.
func TestContainsIsCaseInsensitiveBothSides(t *testing.T) {
	e := sample()
	e.Request.Path = "/API/CheckOut"
	cases := []struct {
		expr string
		want bool
	}{
		{`request.path contains "checkout"`, true}, // needle lower, value mixed
		{`request.path contains "CHECKOUT"`, true}, // needle upper, value mixed
		{`request.path contains "CheckOut"`, true}, // exact
		{`request.path contains "cart"`, false},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Fatalf("CompileFilter(%q) error: %v", c.expr, err)
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}
}

// startswith compares only the first len(needle) bytes rather than lowercasing
// the whole (possibly 100 KB) value. Multi-byte needles must still fold
// correctly, and a value shorter than the needle must not slice out of range.
func TestStartswithMultiByteAndShortValue(t *testing.T) {
	e := sample()
	e.Request.Host = "Café-Payments.shop"
	cases := []struct {
		expr string
		want bool
	}{
		{`request.host startswith "café"`, true},  // multi-byte, needle lower
		{`request.host startswith "CAFÉ"`, true},  // multi-byte, needle upper
		{`request.host startswith "Café-"`, true}, // multi-byte + ASCII tail
		{`request.host startswith "cafe"`, false}, // é is not e
		// Needle longer than the value: must be a clean false, not a panic on
		// the prefix slice.
		{`request.host startswith "Café-Payments.shop-and-then-some"`, false},
	}
	for _, c := range cases {
		pred, err := CompileFilter(c.expr)
		if err != nil {
			t.Fatalf("CompileFilter(%q) error: %v", c.expr, err)
		}
		if got := pred(e); got != c.want {
			t.Errorf("filter %q = %v, want %v", c.expr, got, c.want)
		}
	}

	// The whole point: the value is never copied to test its prefix.
	pred, err := CompileFilter(`response.body startswith "{"`)
	if err != nil {
		t.Fatal(err)
	}
	big := &api.Entry{Response: api.Payload{Body: "{" + strings.Repeat("x", 100_000)}}
	if allocs := testing.AllocsPerRun(50, func() { _ = pred(big) }); allocs != 0 {
		t.Errorf("startswith on a 100 KB body allocates %.1f times per evaluation, want 0", allocs)
	}
	if !pred(big) {
		t.Error(`response.body startswith "{" did not match a body starting with "{"`)
	}
}

// fulltext lowercases while assembling the haystack instead of folding the
// finished string, so this pins that the folding itself is unchanged —
// including for non-ASCII, where Unicode folding can change the encoded byte
// length and a byte-wise loop would corrupt the result.
func TestFulltextLowercasesEquivalently(t *testing.T) {
	e := sample()
	e.Node = "NODE-Ünïcode"
	e.Request.Host = "Payment.SHOP"
	e.Request.Summary = "POST /API/Checkout"
	e.Destination.Name = "PAYMENT-ÄPI"

	got := fulltext(e)
	if want := strings.ToLower(got); got != want {
		t.Errorf("fulltext() is not fully lowercased:\n got %q\nwant %q", got, want)
	}
	for _, needle := range []string{"node-ünïcode", "payment.shop", "post /api/checkout", "payment-äpi"} {
		if !strings.Contains(got, needle) {
			t.Errorf("fulltext() = %q, missing lowercased %q", got, needle)
		}
	}

	// And the bare-token (full-text) filter that consumes it still folds case.
	for _, expr := range []string{"CHECKOUT", "checkout", "Ünïcode"} {
		pred, err := CompileFilter(expr)
		if err != nil {
			t.Fatalf("CompileFilter(%q) error: %v", expr, err)
		}
		if !pred(e) {
			t.Errorf("full-text filter %q = false, want true", expr)
		}
	}
}

// An unknown field must still be a compile error with the new operators, same
// as with ==/!=/contains.
func TestNewOperatorsRejectUnknownField(t *testing.T) {
	cases := []string{
		`bogus.field matches "x"`,
		`bogus.field startswith "x"`,
		`bogus.field in ("x")`,
	}
	for _, expr := range cases {
		if _, err := CompileFilter(expr); err == nil {
			t.Errorf("CompileFilter(%q) should have errored on an unknown field", expr)
		}
	}
}

func TestNumericGetterPreservesMissingAndZeroSemantics(t *testing.T) {
	e := &api.Entry{Response: api.Payload{MySQL: &api.MySQLDetail{ErrorCode: 0}}}
	pred, err := CompileFilter(`mysql.error > 1`)
	if err != nil {
		t.Fatal(err)
	}
	if pred(e) {
		t.Fatal("mysql.error zero sentinel should remain missing")
	}
	e.Response.MySQL.ErrorCode = 2
	if !pred(e) {
		t.Fatal("populated mysql.error should compare numerically")
	}
}
