package worker

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

// service is a fake workload used by the demo traffic generator.
type service struct {
	name string
	ns   string
	ip   string
}

var demoServices = []service{
	{"frontend", "shop", "10.0.1.10"},
	{"checkout", "shop", "10.0.1.11"},
	{"cart", "shop", "10.0.1.12"},
	{"catalog", "shop", "10.0.1.13"},
	{"payment", "shop", "10.0.1.14"},
	{"auth", "platform", "10.0.2.20"},
	{"redis", "platform", "10.0.2.21"},
	{"postgres", "platform", "10.0.2.22"},
	{"rabbitmq", "platform", "10.0.2.25"},
	{"coredns", "kube-system", "10.0.0.10"},
}

// amqpOps is the synthetic AMQP method set the demo cycles through. corrID and
// replyTo are the Basic content-header properties (DIS-9), set on the RPC-style
// publish/deliver so those filter fields are exercised in demo mode.
var amqpOps = []struct {
	class, method, summary, exchange, rk, queue, body, status string
	tag                                                       uint64
	corrID, replyTo                                           string
}{
	{"Basic", "Publish", "PUBLISH orders/new (512 B)", "orders", "new", "", `{"order":4821,"total":39.9}`, "success", 0, "req-4821", "amq.rabbitmq.reply-to"},
	{"Basic", "Deliver", "DELIVER orders/new tag=42", "orders", "new", "", `{"order":4821}`, "success", 42, "req-4821", ""},
	{"Queue", "Declare", "QUEUE.DECLARE payments", "", "", "payments", "", "success", 0, "", ""},
	{"Basic", "Ack", "ACK tag=42", "", "", "", "", "success", 42, "", ""},
	{"Basic", "Return", "RETURN 312 orders/lost", "orders", "lost", "", "", "error", 0, "", ""},
	{"Connection", "Close", "CONNECTION.CLOSE 320 CONNECTION_FORCED", "", "", "", "", "error", 0, "", ""},
}

var httpPaths = []string{
	"/", "/api/products", "/api/products/42", "/api/cart", "/api/checkout",
	"/api/orders", "/healthz", "/metrics", "/api/user/profile", "/api/pay",
}
var httpMethods = []string{"GET", "GET", "GET", "POST", "PUT", "DELETE"}
var dnsNames = []string{
	"catalog.shop.svc.cluster.local", "redis.platform.svc.cluster.local",
	"payment.shop.svc.cluster.local", "api.stripe.com", "auth.platform.svc.cluster.local",
}
var redisCmds = []string{"GET session:9a2f", "SET cart:42 ...", "INCR views", "EXPIRE lock:job 30", "HGETALL user:7"}
var pgQueries = []string{
	"SELECT * FROM orders WHERE id = $1",
	"INSERT INTO carts (user_id, sku) VALUES ($1, $2)",
	"UPDATE inventory SET qty = qty - 1 WHERE sku = $1",
	"SELECT u.id, u.email FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.token = $1",
	"DELETE FROM sessions WHERE expires_at < now()",
	"SELECT count(*) FROM products",
}
var mysqlQueriesDemo = []string{
	"SELECT * FROM orders WHERE id = 4821",
	"INSERT INTO carts (user_id, sku) VALUES (7, 'A1')",
	"UPDATE inventory SET qty = qty - 1 WHERE sku = 'A1'",
	"SELECT id, email FROM users WHERE active = 1",
	"DELETE FROM sessions WHERE expires_at < NOW()",
}
var mongoOpsDemo = []struct{ command, collection string }{
	{"find", "orders"},
	{"insert", "carts"},
	{"update", "inventory"},
	{"aggregate", "products"},
	{"delete", "sessions"},
}
var kafkaOpsDemo = []struct {
	apiKey     string
	apiVersion int
	topic      string
}{
	{"Produce", 9, "orders"},
	{"Fetch", 12, "orders"},
	{"Produce", 9, "payments"},
	{"Metadata", 9, ""},
	{"ApiVersions", 3, ""},
}

// runDemo emits synthetic entries to the sink at roughly rps until stopped.
func runDemo(s *sink, node, nodeIP string, rps int, stop <-chan struct{}) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	interval := time.Second / time.Duration(max(rps, 1))
	t := time.NewTicker(interval)
	defer t.Stop()
	var seq int64
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if s.paused() {
				// A demo worker is still a worker: the hub's pause/resume
				// control (see sink.reader) can't tell it apart from a real
				// one, so it stops "capturing" (generating) the same way.
				continue
			}
			seq++
			s.emit(genEntry(rnd, node, nodeIP, seq))
		}
	}
}

func genEntry(rnd *rand.Rand, node, nodeIP string, seq int64) *api.Entry {
	src := demoServices[rnd.Intn(len(demoServices))]
	dst := demoServices[rnd.Intn(len(demoServices))]
	for dst.name == src.name {
		dst = demoServices[rnd.Intn(len(demoServices))]
	}
	now := time.Now()
	id := node + "-" + strconv.FormatInt(now.UnixNano(), 36) + "-" + strconv.FormatInt(seq, 36)
	elapsed := int64(rnd.Intn(180) + 1)

	e := &api.Entry{
		ID:        id,
		Timestamp: now,
		ElapsedMs: elapsed,
		Node:      node,
		NodeIP:    nodeIP,
		Source:    api.Endpoint{IP: src.ip, Port: 30000 + rnd.Intn(20000), Name: src.name, Namespace: src.ns},
	}

	switch rnd.Intn(12) {
	case 0, 1: // DNS
		q := dnsNames[rnd.Intn(len(dnsNames))]
		e.Protocol = api.ProtocolDNS
		e.Destination = api.Endpoint{IP: "10.0.0.10", Port: 53, Name: "coredns", Namespace: "kube-system"}
		id := rnd.Intn(65535)
		e.Request = api.Payload{
			Question: q, Summary: "A? " + q,
			DNS: &api.DNSDetail{ID: id, Questions: []api.DNSQuestion{{Name: q, Type: "A", Class: "IN"}}},
		}
		if rnd.Intn(12) == 0 { // NXDOMAIN
			e.Response = api.Payload{Summary: "NXDOMAIN", DNS: &api.DNSDetail{
				ID: id, Rcode: "NXDOMAIN", RecursionAvl: true,
				Authority: []api.DNSRecord{{Name: "cluster.local", Type: "SOA", TTL: 30, Data: "ns.dns.svc.cluster.local. hostmaster. 1 3600"}},
			}}
			e.Status, e.StatusCode = "error", 0
		} else {
			answer := fmt.Sprintf("10.0.%d.%d", rnd.Intn(4), rnd.Intn(255))
			e.Response = api.Payload{Answer: answer, Summary: "answer", DNS: &api.DNSDetail{
				ID: id, Rcode: "NOERROR", RecursionAvl: true,
				Answers: []api.DNSRecord{{Name: q, Type: "A", TTL: uint32(30 + rnd.Intn(300)), Data: answer}},
			}}
			e.Status, e.StatusCode = "success", 0
		}
	case 2: // Redis / Valkey (same RESP wire protocol; label is config-driven,
		// see pipeline.respPorts — the demo generator just picks one for variety).
		cmd := redisCmds[rnd.Intn(len(redisCmds))]
		if rnd.Intn(6) == 0 {
			// Small chance of a Valkey-labelled entry, targeting a distinct fake
			// destination so it's visually distinguishable from Redis in the demo.
			e.Protocol = api.ProtocolValkey
			e.Destination = api.Endpoint{IP: "10.0.2.23", Port: 6379, Name: "valkey", Namespace: "platform"}
		} else {
			e.Protocol = api.ProtocolRedis
			e.Destination = api.Endpoint{IP: "10.0.2.21", Port: 6379, Name: "redis", Namespace: "platform"}
		}
		args := strings.Fields(cmd)
		e.Request = api.Payload{
			Command: cmd, Summary: cmd,
			Redis: &api.RedisDetail{Args: args, DBIndex: rnd.Intn(4), PipelineDepth: rnd.Intn(3)},
			Raw:   demoRaw(demoRESP(args)),
		}
		e.Response = api.Payload{
			Summary: "OK", Body: "+OK",
			Redis: &api.RedisDetail{Reply: "OK", ReplyType: "string"},
			Raw:   demoRaw("+OK\r\n"),
		}
		e.Status, e.StatusCode = "success", 0
	case 3: // Postgres
		q := pgQueries[rnd.Intn(len(pgQueries))]
		e.Protocol = api.ProtocolPostgres
		e.Destination = api.Endpoint{IP: "10.0.2.22", Port: 5432, Name: "postgres", Namespace: "platform"}
		e.Request = api.Payload{
			Query: q, Summary: q,
			Postgres: &api.PGDetail{StatementName: "s" + strconv.Itoa(rnd.Intn(5)), Params: demoPGParams(q)},
			Raw:      demoRaw("Q\x00\x00\x00" + string(rune(len(q)+5)) + q + "\x00"),
		}
		if rnd.Intn(20) == 0 {
			e.Response = api.Payload{
				Summary: "ERROR: deadlock detected (40P01)",
				Postgres: &api.PGDetail{
					Error:    &api.PGError{Severity: "ERROR", Code: "40P01", Message: "deadlock detected", Hint: "See server log for query details."},
					TxStatus: "E",
				},
			}
			e.Status, e.StatusCode = "error", 0
		} else {
			rows := rnd.Intn(50)
			tag := pgDemoTag(q, rows)
			e.Response = api.Payload{
				Summary: tag, RowCount: rows,
				Postgres: &api.PGDetail{Tag: tag, TxStatus: "I", Columns: demoPGColumns(q)},
			}
			e.Status, e.StatusCode = "success", 0
		}
	case 4: // L4 flows: generic tcp/udp/icmp
		genL4(rnd, e)
	case 6: // MySQL
		genMySQL(rnd, e)
	case 7: // MongoDB
		genMongo(rnd, e)
	case 8: // Kafka
		genKafka(rnd, e)
	case 5: // AMQP (RabbitMQ 0-9-1)
		op := amqpOps[rnd.Intn(len(amqpOps))]
		e.Protocol = api.ProtocolAMQP
		e.Destination = api.Endpoint{IP: "10.0.2.25", Port: 5672, Name: "rabbitmq", Namespace: "platform"}
		e.Request = api.Payload{
			Class: op.class, Method: op.method,
			Exchange: op.exchange, RoutingKey: op.rk, Queue: op.queue, DeliveryTag: op.tag,
			CorrelationID: op.corrID, ReplyTo: op.replyTo,
			Summary: op.summary,
		}
		if op.body != "" {
			e.Request.Body = op.body
			e.Request.Size = len(op.body)
			e.Request.ContentType = "application/json"
		}
		e.Response = api.Payload{Summary: op.summary}
		e.Status, e.StatusCode = op.status, 0
	default: // HTTP
		method := httpMethods[rnd.Intn(len(httpMethods))]
		path := httpPaths[rnd.Intn(len(httpPaths))]
		code := weightedStatus(rnd)
		e.Protocol = api.ProtocolHTTP
		e.Destination = api.Endpoint{IP: dst.ip, Port: 8080, Name: dst.name, Namespace: dst.ns}
		reqCT := ""
		if method == "POST" || method == "PUT" {
			reqCT = "application/json"
		}
		host := dst.name + "." + dst.ns
		e.Request = api.Payload{
			Method:      method,
			Path:        path,
			Host:        host,
			Summary:     method + " " + path,
			ContentType: reqCT,
			Headers:     map[string]string{"user-agent": "k8shark-demo/1.0", "accept": "application/json"},
			HTTP:        &api.HTTPDetail{Version: "HTTP/1.1", ContentType: reqCT, Query: demoQuery(rnd)},
			Raw:         demoRaw(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: k8shark-demo/1.0\r\nAccept: application/json\r\n\r\n"),
		}
		body := demoJSONBody(code)
		// TTFB is modeled as the bulk of the total latency (headers/status-line
		// dominate for these small JSON bodies), leaving a smaller random tail
		// for body transfer — there's no real request/response gap to measure
		// in synthetic traffic, unlike the real dissectors.
		ttfb := elapsed/2 + int64(rnd.Intn(int(elapsed/2)+1))
		e.Response = api.Payload{
			StatusCode:  code,
			Summary:     strconv.Itoa(code) + " " + statusText(code),
			Headers:     map[string]string{"content-type": "application/json"},
			ContentType: "application/json",
			Body:        body,
			Size:        len(body),
			HTTP:        &api.HTTPDetail{Version: "HTTP/1.1", ContentType: "application/json", TTFBMs: ttfb},
			Raw:         demoRaw("HTTP/1.1 " + strconv.Itoa(code) + " " + statusText(code) + "\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body),
		}
		e.StatusCode = code
		e.Status = classifyHTTP(code)
	}
	attachDemoL4(rnd, e)
	return e
}

// synthetic MACs — the 02:… locally-administered prefix marks these as demo data,
// never mistaken for a real captured address.
const (
	demoSrcMAC = "02:00:00:00:00:01"
	demoDstMAC = "02:00:00:00:00:02"
)

// attachDemoL4 hangs a plausible-but-synthetic L4Info off a demo entry so the
// dashboard's L4 tab is populated without a live capture. ICMP gets none.
func attachDemoL4(rnd *rand.Rand, e *api.Entry) {
	switch e.Protocol {
	case api.ProtocolICMP:
		return
	case api.ProtocolDNS, api.ProtocolUDP:
		info := &api.L4Info{
			SrcMAC: demoSrcMAC, DstMAC: demoDstMAC, IPVersion: 4, TTL: 64,
			HeaderHex:     demoHeaderHex(),
			ClientBytes:   int64(40 + rnd.Intn(80)),
			ServerBytes:   int64(60 + rnd.Intn(200)),
			ClientPackets: 1, ServerPackets: 1,
			DurationMs: e.ElapsedMs,
		}
		if e.Protocol == api.ProtocolUDP && e.Request.Bytes > 0 {
			info.ClientBytes, info.ClientPackets = e.Request.Bytes, e.Request.Packets
		}
		e.L4 = info
	default: // TCP-based: http / redis / valkey / postgres / tcp
		cb := int64(120 + rnd.Intn(600))
		sb := int64(200 + rnd.Intn(4000))
		if e.Request.Bytes > 0 { // generic tcp flow already has a byte total
			cb = e.Request.Bytes / 2
			sb = e.Request.Bytes - cb
		}
		info := &api.L4Info{
			SrcMAC: demoSrcMAC, DstMAC: demoDstMAC, IPVersion: 4, TTL: 64, IPFlags: "DF",
			ClientTCPFlags: "SYN,ACK,PSH,FIN", ServerTCPFlags: "SYN,ACK,PSH,FIN",
			SeqStart: rnd.Uint32(), AckStart: rnd.Uint32(),
			Window: 64240, MSS: 1460,
			RTTMs:         float64(rnd.Intn(3000)+100) / 1000.0,
			DurationMs:    e.ElapsedMs,
			ClientBytes:   cb,
			ServerBytes:   sb,
			ClientPackets: int64(2 + rnd.Intn(10)),
			ServerPackets: int64(2 + rnd.Intn(20)),
			HeaderHex:     demoHeaderHex(),
		}
		if rnd.Intn(15) == 0 {
			info.Retransmits = 1 + rnd.Intn(3)
		}
		e.L4 = info
	}
}

// demoRaw builds a bounded RawView from synthetic wire bytes so the Raw tab is
// populated in demo mode (live capture fills this from the actual stream).
func demoRaw(s string) *api.RawView {
	b := []byte(s)
	if len(b) > 512 {
		b = b[:512]
	}
	return &api.RawView{Data: b, Bytes: len(s), Truncated: len(s) > len(b)}
}

// demoRESP renders a command as a RESP array, for the Redis Raw view.
func demoRESP(args []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(a), a)
	}
	return sb.String()
}

// demoHeaderHex returns a fixed bounded hexdump of a plausible Ethernet+IPv4+TCP
// header, so the L4 tab's header view is populated in demo mode.
func demoHeaderHex() string {
	hdr := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, // eth
		0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0x0a, 0x00, 0x01, 0x0a, 0x0a, 0x00, 0x02, 0x15, // ipv4
		0x9c, 0x40, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00, // tcp
	}
	return hexDump(hdr, 128)
}

// demoQuery occasionally returns a parsed query-param map for the HTTP request tab.
func demoQuery(rnd *rand.Rand) map[string]string {
	if rnd.Intn(3) != 0 {
		return nil
	}
	return map[string]string{"page": strconv.Itoa(1 + rnd.Intn(9)), "limit": "20"}
}

// demoJSONBody returns a small plausible JSON response body for the Body tab.
func demoJSONBody(code int) string {
	if code >= 400 {
		return `{"error":"` + statusText(code) + `","code":` + strconv.Itoa(code) + `}`
	}
	return `{"ok":true,"data":{"id":42,"items":3}}`
}

// demoPGParams fabricates bind-parameter values matching the $N placeholders in q.
func demoPGParams(q string) []string {
	n := strings.Count(q, "$")
	if n == 0 {
		return nil
	}
	vals := []string{"42", "'a1b2c3'", "17", "true", "'2026-07-09'"}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, vals[i%len(vals)])
	}
	return out
}

// demoPGColumns fabricates a RowDescription for SELECT demo queries.
func demoPGColumns(q string) []api.PGColumn {
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(q)), "SELECT") {
		return nil
	}
	return []api.PGColumn{
		{Name: "id", TypeOID: 23, Type: "int4"},
		{Name: "email", TypeOID: 1043, Type: "varchar"},
	}
}

func weightedStatus(rnd *rand.Rand) int {
	switch n := rnd.Intn(100); {
	case n < 80:
		return []int{200, 201, 204}[rnd.Intn(3)]
	case n < 90:
		return []int{301, 304}[rnd.Intn(2)]
	case n < 97:
		return []int{400, 401, 403, 404}[rnd.Intn(4)]
	default:
		return []int{500, 502, 503}[rnd.Intn(3)]
	}
}

var l4Targets = []struct {
	name, ns, ip string
	port         int
	proto        api.Protocol
}{
	// mysql (3306), mongodb (27017) and kafka (9092) are now emitted as dissected
	// ProtocolMySQL/ProtocolMongo/ProtocolKafka entries (see genMySQL/genMongo/
	// genKafka) rather than generic flows.
	{"gateway", "platform", "10.0.2.1", 443, api.ProtocolTCP},
	{"statsd", "platform", "10.0.2.33", 8125, api.ProtocolUDP},
	{"ntp", "kube-system", "10.0.0.5", 123, api.ProtocolUDP},
}

// genL4 fills e with a synthetic generic L4 flow (tcp/udp) or an ICMP event.
func genL4(rnd *rand.Rand, e *api.Entry) {
	if rnd.Intn(5) == 0 { // ICMP
		e.Protocol = api.ProtocolICMP
		e.Destination = api.Endpoint{IP: "10.0.2.9"}
		if rnd.Intn(4) != 0 {
			e.Request = api.Payload{Summary: "EchoRequest"}
			e.Response = api.Payload{Summary: "EchoReply"}
			e.Status = "success"
		} else {
			e.Request = api.Payload{Summary: "DestinationUnreachable(Host)"}
			e.Response = api.Payload{Summary: "DestinationUnreachable(Host)"}
			e.Status = "error"
		}
		return
	}
	t := l4Targets[rnd.Intn(len(l4Targets))]
	pkts := int64(rnd.Intn(400) + 4)
	bytes := pkts * int64(rnd.Intn(600)+60)
	label := string(t.proto) + "/" + strconv.Itoa(t.port)
	if name := wellKnownPorts[t.port]; name != "" {
		label = string(t.proto) + " " + name
	}
	reason, flags := "FIN", "SYN,FIN"
	e.Status = "success"
	switch {
	case t.proto == api.ProtocolUDP:
		reason, flags = "idle", ""
	case rnd.Intn(12) == 0:
		reason, flags, e.Status = "RST", "SYN,RST", "error"
	}
	e.Protocol = t.proto
	e.Destination = api.Endpoint{IP: t.ip, Port: t.port, Name: t.name, Namespace: t.ns}
	e.Request = api.Payload{Summary: label, Packets: pkts, Bytes: bytes, Flags: flags}
	e.Response = api.Payload{Summary: reason + " · " + humanBytes(bytes) + " · " + strconv.FormatInt(pkts, 10) + " pkts"}
}

// genMySQL fills e with a synthetic MySQL query interaction (DIS-11).
func genMySQL(rnd *rand.Rand, e *api.Entry) {
	q := mysqlQueriesDemo[rnd.Intn(len(mysqlQueriesDemo))]
	e.Protocol = api.ProtocolMySQL
	e.Destination = api.Endpoint{IP: "10.0.2.30", Port: 3306, Name: "mysql", Namespace: "platform"}
	e.Request = api.Payload{
		Query: q, Summary: q,
		MySQL: &api.MySQLDetail{Command: "COM_QUERY"},
	}
	if rnd.Intn(20) == 0 {
		e.Response = api.Payload{
			Summary: "ERROR 1146: Table 'shop.nope' doesn't exist",
			MySQL:   &api.MySQLDetail{ErrorCode: 1146, ErrorMessage: "Table 'shop.nope' doesn't exist"},
		}
		e.Status, e.StatusCode = "error", 0
		return
	}
	rows := rnd.Intn(50)
	e.Response = api.Payload{Summary: strconv.Itoa(rows) + " rows", RowCount: rows}
	e.Status, e.StatusCode = "success", 0
}

// genMongo fills e with a synthetic MongoDB command interaction (DIS-11).
func genMongo(rnd *rand.Rand, e *api.Entry) {
	op := mongoOpsDemo[rnd.Intn(len(mongoOpsDemo))]
	summary := op.command + " " + op.collection
	e.Protocol = api.ProtocolMongo
	e.Destination = api.Endpoint{IP: "10.0.2.32", Port: 27017, Name: "mongodb", Namespace: "platform"}
	e.Request = api.Payload{
		Query: summary, Summary: summary,
		Mongo: &api.MongoDetail{Command: op.command, Collection: op.collection, Database: "shop"},
	}
	if rnd.Intn(20) == 0 {
		e.Response = api.Payload{
			Summary: "not authorized on shop to execute command",
			Mongo:   &api.MongoDetail{ErrMsg: "not authorized on shop to execute command"},
		}
		e.Status, e.StatusCode = "error", 0
		return
	}
	e.Response = api.Payload{Summary: "ok", Mongo: &api.MongoDetail{OK: true}}
	e.Status, e.StatusCode = "success", 0
}

// genKafka fills e with a synthetic Kafka request/response interaction (DIS-8).
func genKafka(rnd *rand.Rand, e *api.Entry) {
	op := kafkaOpsDemo[rnd.Intn(len(kafkaOpsDemo))]
	corrID := int32(rnd.Intn(1 << 20))
	e.Protocol = api.ProtocolKafka
	e.Destination = api.Endpoint{IP: "10.0.2.31", Port: 9092, Name: "kafka", Namespace: "platform"}
	e.Request = api.Payload{
		Summary: kafkaSummary(op.apiKey, op.apiVersion, op.topic),
		Kafka: &api.KafkaDetail{
			APIKey: op.apiKey, APIVersion: op.apiVersion, Topic: op.topic,
			ClientID: "demo-producer", CorrelationID: corrID,
		},
	}
	if rnd.Intn(20) == 0 {
		// UNKNOWN_TOPIC_OR_PARTITION (3)
		e.Response = api.Payload{Summary: "error 3", Kafka: &api.KafkaDetail{ErrorCode: 3}}
		e.Status, e.StatusCode = "error", 0
		return
	}
	e.Response = api.Payload{Summary: "ok"}
	e.Status, e.StatusCode = "success", 0
}

// pgDemoTag builds a plausible CommandComplete tag from a demo SQL statement.
func pgDemoTag(q string, rows int) string {
	verb := ""
	if f := strings.Fields(q); len(f) > 0 {
		verb = strings.ToUpper(f[0])
	}
	switch verb {
	case "SELECT":
		return "SELECT " + strconv.Itoa(rows) + " rows"
	case "INSERT":
		return "INSERT 0 1"
	case "UPDATE":
		return "UPDATE " + strconv.Itoa(rows)
	case "DELETE":
		return "DELETE " + strconv.Itoa(rows)
	default:
		return verb
	}
}

func classifyHTTP(code int) string {
	switch {
	case code >= 500:
		return "error"
	case code >= 400:
		return "warning"
	default:
		return "success"
	}
}

func statusText(code int) string {
	m := map[int]string{
		200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
		304: "Not Modified", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
		404: "Not Found", 500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
	}
	if t, ok := m[code]; ok {
		return t
	}
	return ""
}
