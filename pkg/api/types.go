// Package api defines the wire contract shared by the worker, the hub and the
// front-end. An Entry is a single reconstructed L7 interaction (a request paired
// with its response) captured on the wire.
package api

import "time"

// Protocol identifies the L7 protocol of an Entry.
type Protocol string

const (
	ProtocolHTTP     Protocol = "http"
	ProtocolDNS      Protocol = "dns"
	ProtocolRedis    Protocol = "redis"
	ProtocolValkey   Protocol = "valkey" // Redis-compatible RESP; distinguished only by config
	ProtocolPostgres Protocol = "postgres"
	ProtocolMySQL    Protocol = "mysql"   // MySQL / MariaDB client-server protocol
	ProtocolMongo    Protocol = "mongodb" // MongoDB wire protocol (label matches wellKnownPorts)
	ProtocolKafka    Protocol = "kafka"   // Kafka wire protocol (label matches wellKnownPorts)
	ProtocolAMQP     Protocol = "amqp"    // RabbitMQ / AMQP 0-9-1
	ProtocolWS       Protocol = "ws"      // WebSocket frames after an HTTP 101 Upgrade (RFC 6455)
	ProtocolTCP      Protocol = "tcp"     // generic L4 flow (undissected TCP)
	ProtocolUDP      Protocol = "udp"     // generic L4 flow (non-DNS UDP)
	ProtocolICMP     Protocol = "icmp"    // ICMP echo / errors
)

// Endpoint is one side of a captured conversation.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	// Name is a best-effort human label (k8s pod/service, or resolved host).
	Name string `json:"name,omitempty"`
	// Namespace is the k8s namespace when known.
	Namespace string `json:"namespace,omitempty"`
	// Workload is the owning controller (Deployment/StatefulSet/...) when known.
	// Unlike Name (a churning pod name), it is stable across pod restarts.
	Workload string `json:"workload,omitempty"`
}

// Payload holds the protocol-specific request or response details. Fields are
// populated per-protocol; unused ones stay empty so the same shape serialises
// cleanly to the front-end.
type Payload struct {
	// Common
	Summary string            `json:"summary,omitempty"` // one-line human description
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Size    int               `json:"size,omitempty"`

	// HTTP
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Host       string `json:"host,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`

	// DNS
	Question string `json:"question,omitempty"`
	Answer   string `json:"answer,omitempty"`

	// Redis
	Command string `json:"command,omitempty"`

	// Postgres / MySQL (both surface SQL text via Query and result rows via
	// RowCount, so those scalars are shared).
	Query    string `json:"query,omitempty"`
	RowCount int    `json:"rowCount,omitempty"`

	// AMQP (RabbitMQ 0-9-1). The AMQP method name (e.g. "Publish") reuses the
	// shared Method field above; Class (e.g. "Basic") is AMQP-only.
	Exchange    string `json:"exchange,omitempty"`
	RoutingKey  string `json:"routingKey,omitempty"`
	Queue       string `json:"queue,omitempty"`
	DeliveryTag uint64 `json:"deliveryTag,omitempty"`
	Class       string `json:"class,omitempty"`
	// Basic content-header properties (DIS-9). The content-type property
	// reuses the shared ContentType field below.
	CorrelationID string `json:"correlationId,omitempty"`
	ReplyTo       string `json:"replyTo,omitempty"`
	MessageID     string `json:"messageId,omitempty"`

	// L4 flows (tcp/udp/icmp)
	Packets int64  `json:"packets,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Flags   string `json:"flags,omitempty"` // e.g. "SYN,FIN" for TCP

	// WebSocket (DIS-6). Standalone post-Upgrade frames (Protocol "ws"): the
	// frame's descriptive fields go here (there is no request/response pairing
	// for an async frame). WSOpcode is the RFC 6455 opcode name
	// ("text"|"binary"|"close"|"ping"|"pong"|"continuation"); the bounded
	// payload preview reuses the shared Body/Summary/Size fields above.
	WSOpcode string `json:"wsOpcode,omitempty"`

	// Full-fidelity extras (additive; protocol-specific sub-objects). Old
	// front-ends ignore these; the canonical scalars above stay the values the
	// IFL filter reads.
	ContentType string       `json:"contentType,omitempty"`
	Truncated   bool         `json:"truncated,omitempty"` // Body was cut at the capture cap
	Raw         *RawView     `json:"raw,omitempty"`
	HTTP        *HTTPDetail  `json:"http,omitempty"`
	DNS         *DNSDetail   `json:"dns,omitempty"`
	Redis       *RedisDetail `json:"redis,omitempty"`
	Postgres    *PGDetail    `json:"postgres,omitempty"`
	MySQL       *MySQLDetail `json:"mysql,omitempty"`
	Mongo       *MongoDetail `json:"mongo,omitempty"`
	Kafka       *KafkaDetail `json:"kafka,omitempty"`
}

// L4Info is connection-level L2/L3/L4 metadata, captured from the packet
// headers at route() time (not available to the reassembled L7 stream).
type L4Info struct {
	SrcMAC    string `json:"srcMac,omitempty"`
	DstMAC    string `json:"dstMac,omitempty"`
	IPVersion int    `json:"ipVersion,omitempty"` // 4 or 6
	TTL       int    `json:"ttl,omitempty"`       // last client->server TTL/HopLimit
	IPFlags   string `json:"ipFlags,omitempty"`   // "DF"|"MF"|"DF,MF"
	// TCP (empty for udp/icmp)
	ClientTCPFlags string  `json:"clientTcpFlags,omitempty"` // union seen client->server, e.g. "SYN,ACK,FIN"
	ServerTCPFlags string  `json:"serverTcpFlags,omitempty"`
	SeqStart       uint32  `json:"seqStart,omitempty"` // client ISN (from SYN)
	AckStart       uint32  `json:"ackStart,omitempty"` // server ISN (from SYN-ACK)
	Window         int     `json:"window,omitempty"`   // last client advertised window
	MSS            int     `json:"mss,omitempty"`      // from SYN option
	Retransmits    int     `json:"retransmits,omitempty"`
	RTTMs          float64 `json:"rttMs,omitempty"`      // handshake SYN->SYN-ACK estimate
	DurationMs     int64   `json:"durationMs,omitempty"` // firstSeen..lastSeen
	// per-direction accounting (client = ephemeral/higher port heuristic)
	ClientBytes   int64 `json:"clientBytes,omitempty"`
	ServerBytes   int64 `json:"serverBytes,omitempty"`
	ClientPackets int64 `json:"clientPackets,omitempty"`
	ServerPackets int64 `json:"serverPackets,omitempty"`
	// Decoded header block, bounded hex+ascii dump of the first packet's L2/L3/L4.
	HeaderHex string   `json:"headerHex,omitempty"`
	TLS       *TLSInfo `json:"tls,omitempty"` // only when a TLS ClientHello/ServerHello is sniffable (or via eBPF later)
}

// TLSInfo carries best-effort TLS handshake metadata (SNI, ALPN, version).
type TLSInfo struct {
	SNI     string `json:"sni,omitempty"`
	ALPN    string `json:"alpn,omitempty"`
	Version string `json:"version,omitempty"` // "TLS1.2"|"TLS1.3"
	Cipher  string `json:"cipher,omitempty"`
}

// RawView is a bounded sample of one direction's application bytes.
//
// Data is the sample itself, base64 on the wire (Go marshals []byte that way).
// Hex is the legacy form: the same bytes pre-rendered as a `hexdump -C`-style
// text block by the worker. Hex is ~4.94x the size of the bytes it describes
// (79 characters per 16 bytes) against base64's 1.33x, and rendering it cost
// the worker more CPU than dissection did, so current workers populate Data and
// leave Hex empty — the dump is rendered in the browser, from Data, only for
// the one entry whose detail panel is open.
//
// Hex is retained, not removed: a worker older than its hub still sends it, so
// every consumer must read Data first and fall back to parsing Hex. See
// pcapPayloadBytes (internal/hub/pcap.go) and payloadBytes (ui/src/pcap.ts) for
// the two decoders that implement that order.
type RawView struct {
	Data      []byte `json:"data,omitempty"`  // captured bytes, base64-encoded on the wire
	Hex       string `json:"hex,omitempty"`   // legacy pre-rendered "0000  48 54 54 50 ...  HTTP..." block
	Bytes     int    `json:"bytes,omitempty"` // total bytes seen before truncation
	Truncated bool   `json:"truncated,omitempty"`
}

// HTTPDetail is the rich HTTP request/response extras.
type HTTPDetail struct {
	Version     string            `json:"version,omitempty"` // "HTTP/1.1"
	Query       map[string]string `json:"query,omitempty"`   // parsed query params (request side)
	ContentType string            `json:"contentType,omitempty"`
	TTFBMs      int64             `json:"ttfbMs,omitempty"` // response side: request-sent -> first response byte
}

// DNSQuestion is one question section entry.
type DNSQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // "A","AAAA","CNAME",...
	Class string `json:"class,omitempty"`
}

// DNSRecord is one resource record (answer/authority/additional).
type DNSRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl,omitempty"`
	Data string `json:"data"` // rendered rdata (IP, target, TXT, ...)
}

// DNSDetail is the fully decoded DNS message.
type DNSDetail struct {
	ID            int           `json:"id,omitempty"`
	Questions     []DNSQuestion `json:"questions,omitempty"`
	Answers       []DNSRecord   `json:"answers,omitempty"`
	Authority     []DNSRecord   `json:"authority,omitempty"`
	Additional    []DNSRecord   `json:"additional,omitempty"`
	Rcode         string        `json:"rcode,omitempty"`
	Authoritative bool          `json:"authoritative,omitempty"`
	RecursionAvl  bool          `json:"recursionAvailable,omitempty"`
}

// RedisDetail is the rich RESP request/response extras.
type RedisDetail struct {
	Args          []string          `json:"args,omitempty"`          // full command incl. every arg (request)
	Reply         string            `json:"reply,omitempty"`         // fully rendered reply (response)
	ReplyType     string            `json:"replyType,omitempty"`     // "string"|"array"|"error"|"integer"|"map"|"set"|"push"|"null"
	DBIndex       int               `json:"dbIndex,omitempty"`       // tracked from SELECT n
	PipelineDepth int               `json:"pipelineDepth,omitempty"` // outstanding pipelined requests when this one was queued
	Attributes    map[string]string `json:"attributes,omitempty"`    // RESP3 |attribute pairs
}

// PGColumn is one RowDescription column.
type PGColumn struct {
	Name    string `json:"name"`
	TypeOID int    `json:"typeOid,omitempty"`
	Type    string `json:"type,omitempty"` // resolved name for common OIDs
}

// PGError is a decoded ErrorResponse.
type PGError struct {
	Severity string `json:"severity,omitempty"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Hint     string `json:"hint,omitempty"`
	Where    string `json:"where,omitempty"`
}

// PGDetail is the rich Postgres request/response extras.
type PGDetail struct {
	StatementName string     `json:"statementName,omitempty"`
	Portal        string     `json:"portal,omitempty"`
	Params        []string   `json:"params,omitempty"`  // bind parameter values (request)
	Columns       []PGColumn `json:"columns,omitempty"` // RowDescription (response)
	Tag           string     `json:"tag,omitempty"`     // CommandComplete tag
	Error         *PGError   `json:"error,omitempty"`
	TxStatus      string     `json:"txStatus,omitempty"` // "I"|"T"|"E" from ReadyForQuery
}

// MySQLDetail is the rich MySQL request/response extras (DIS-11).
type MySQLDetail struct {
	// Command is the client command name on the request side
	// ("COM_QUERY"|"COM_STMT_PREPARE"|"COM_STMT_EXECUTE"|...); the SQL text
	// itself reuses the shared Payload.Query field.
	Command string `json:"command,omitempty"`
	// ErrorCode/ErrorMessage decode an ERR packet on the response side.
	ErrorCode    int    `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// MongoDetail is the rich MongoDB request/response extras (DIS-11). The command
// name + collection are extracted from the OP_MSG section-0 BSON document on the
// request side; ok/errmsg from the reply document on the response side.
type MongoDetail struct {
	Command    string `json:"command,omitempty"`    // "find"|"insert"|"update"|"delete"|"aggregate"|...
	Collection string `json:"collection,omitempty"` // target collection (filter field mongo.collection)
	Database   string `json:"database,omitempty"`   // $db
	OK         bool   `json:"ok,omitempty"`         // response ok:1 (false on error/ok:0)
	ErrMsg     string `json:"errmsg,omitempty"`     // response error message
}

// KafkaDetail is the rich Kafka request/response extras (DIS-8). The api_key
// name + api_version + client_id + topic are extracted from the request header
// and body; error_code from the response body where cheaply parseable. Requests
// and responses are paired exactly by CorrelationID (not FIFO).
type KafkaDetail struct {
	APIKey        string `json:"apiKey,omitempty"`        // request api_key name ("Produce"|"Fetch"|"Metadata"|"ApiVersions"|...) — filter field kafka.apikey
	APIVersion    int    `json:"apiVersion,omitempty"`    // request api_version
	Topic         string `json:"topic,omitempty"`         // first topic name for Produce/Fetch/Metadata on non-flexible versions — filter field kafka.topic
	ClientID      string `json:"clientId,omitempty"`      // request header client_id
	ErrorCode     int    `json:"errorCode,omitempty"`     // response error_code where surfaced (0 = none)
	CorrelationID int32  `json:"correlationId,omitempty"` // request/response correlation id used for pairing
}

// Entry is a single captured L7 interaction. It is the atomic unit streamed
// from worker -> hub -> front.
type Entry struct {
	ID          string    `json:"id"`
	Protocol    Protocol  `json:"protocol"`
	Timestamp   time.Time `json:"timestamp"`
	ElapsedMs   int64     `json:"elapsedMs"`        // request->response latency
	Node        string    `json:"node"`             // capturing node/worker
	NodeIP      string    `json:"nodeIp,omitempty"` // capturing node's host IP (status.hostIP; empty when not injected, e.g. demo mode)
	Source      Endpoint  `json:"src"`
	Destination Endpoint  `json:"dst"`
	Request     Payload   `json:"request"`
	Response    Payload   `json:"response"`
	// Status is a normalised outcome: "success" | "warning" | "error".
	Status string `json:"status"`
	// StatusCode is a protocol-agnostic numeric code (HTTP status, etc.) used
	// for quick colouring in the UI.
	StatusCode int `json:"statusCode"`
	// L4 is connection-level L2/L3/L4 metadata for TCP/UDP entries (nil for
	// entries captured mid-connection or without header context).
	L4 *L4Info `json:"l4,omitempty"`
	// Seq is a hub-assigned monotonic sequence number (see store.add),
	// usable as a pagination anchor that survives the anchored entry itself
	// aging out of the ring buffer (unlike an ID-based anchor). Zero on
	// entries from a hub that predates this field.
	Seq int64 `json:"seq,omitempty"`
	// TraceID is an end-to-end correlation id extracted from an HTTP request's
	// headers (EXT-3): the W3C traceparent trace-id, else x-request-id, else
	// x-correlation-id. It lets a single request be followed across the
	// front->api->db chain (filter field trace.id). Empty when no correlation
	// header was present; never fabricated.
	TraceID string `json:"traceId,omitempty"`
}

// --- Wire messages ---------------------------------------------------------

// MessageType tags a WebSocket frame on both the worker->hub and hub->front
// channels.
type MessageType string

const (
	// worker -> hub / hub -> front
	MsgEntry MessageType = "entry"
	// hub -> front: several entries in one frame (oldest first). The hub
	// coalesces the live feed and history replay into batches to cut
	// frame/syscall count under load; semantically identical to that many
	// MsgEntry frames in order.
	MsgEntryBatch MessageType = "entryBatch"
	// hub -> front: periodic aggregate metrics
	MsgStats MessageType = "stats"
	// worker -> hub: identifies the worker on connect
	MsgHello MessageType = "hello"
	// front -> hub: set/replace the active KFL filter
	MsgFilter MessageType = "filter"
	// hub -> front: a ?filter= or filter frame failed to compile
	MsgFilterError MessageType = "filterError"
	// worker -> hub: periodic worker self-report (drop counters, capture state)
	MsgWorkerStats MessageType = "workerStats"
	// hub -> worker: pause/resume capture (see WorkerCommand)
	MsgWorkerCommand MessageType = "workerCommand"
)

// Envelope wraps every WebSocket frame. Exactly one of the payload pointers is
// set, matching Type.
type Envelope struct {
	Type          MessageType    `json:"type"`
	Entry         *Entry         `json:"entry,omitempty"`
	Entries       []*Entry       `json:"entries,omitempty"`
	Stats         *Stats         `json:"stats,omitempty"`
	Hello         *Hello         `json:"hello,omitempty"`
	Filter        string         `json:"filter,omitempty"`
	Error         string         `json:"error,omitempty"`
	WorkerStats   *WorkerStats   `json:"workerStats,omitempty"`
	WorkerCommand *WorkerCommand `json:"workerCommand,omitempty"`
}

// WorkerCommand is a hub -> worker control message. Currently just the
// pause/resume toggle for /api/workers/capture; the worker keeps its
// AF_PACKET/eBPF sources open either way (this isn't a start/stop of the
// process) and just stops turning what it reads into entries while paused,
// so resuming is instant rather than needing a reconnect.
type WorkerCommand struct {
	Paused bool `json:"paused"`
}

// Hello is sent by a worker when it connects to the hub.
type Hello struct {
	Node    string `json:"node"`
	Version string `json:"version"`
}

// WorkerStats is a worker's periodic self-report, so the hub (and its API
// consumers) can tell a quiet node from a broken or dropping one.
type WorkerStats struct {
	Node          string `json:"node"`
	EntriesSent   uint64 `json:"entriesSent"`   // entries handed to the hub connection
	Dropped       uint64 `json:"dropped"`       // entries dropped on a full sink buffer
	CaptureLive   bool   `json:"captureLive"`   // AF_PACKET source currently active
	CaptureTLS    bool   `json:"captureTls"`    // eBPF TLS capture currently active
	CapturePaused bool   `json:"capturePaused"` // hub told this worker to stop turning capture into entries
	RingPackets   uint64 `json:"ringPackets"`   // AF_PACKET kernel ring: cumulative packets delivered
	RingDrops     uint64 `json:"ringDrops"`     // AF_PACKET kernel ring: cumulative packets dropped before userspace saw them
	FlowsEvicted  uint64 `json:"flowsEvicted"`  // generic L4 flows dropped by the worker's maxFlows cap
	// TLSLagDrops counts eBPF-decrypted TLS streams abandoned because
	// backpressure forced the drop of one of their interior chunks — the
	// stream is closed with a clean truncation instead of being misparsed.
	TLSLagDrops uint64 `json:"tlsLagDrops,omitempty"`
	// TLSBudgetDrops counts records rejected at the stream or payload budget.
	TLSBudgetDrops uint64 `json:"tlsBudgetDrops,omitempty"`
	// TCPLossEvents counts AF_PACKET TCP stream directions truncated after a
	// lost segment surfaced as tcpreader.DataLost (LossErrors): the
	// connection's pending requests are purged and the direction dropped,
	// rather than misparsing — and mispairing — across the hole. See
	// internal/worker/pipeline.go lossReader.
	TCPLossEvents uint64 `json:"tcpLossEvents,omitempty"`
}

// WindowStats is a trailing-window slice of traffic, for "current" rates as
// opposed to the cumulative since-start counters.
type WindowStats struct {
	Entries       int64   `json:"entries"`
	Errors        int64   `json:"errors"`
	Warnings      int64   `json:"warnings"`
	EntriesPerSec float64 `json:"entriesPerSec"`
}

// Stats is a rolling aggregate the hub pushes to the front for the header/graphs.
type Stats struct {
	TotalEntries  int64            `json:"totalEntries"`
	EntriesPerSec float64          `json:"entriesPerSec"`
	Workers       int              `json:"workers"`
	ByProtocol    map[string]int64 `json:"byProtocol"`
	ByStatus      map[string]int64 `json:"byStatus"`
	// BroadcastDropped counts entries dropped to slow front clients (send
	// buffer full) since the hub started — a degradation signal beyond the
	// binary connected/disconnected indicator.
	BroadcastDropped int64 `json:"broadcastDropped"`
	// Last1m/Last5m are trailing windows over *ingest*, NOT bounded by the
	// hub's in-memory buffer capacity: they tally every entry the hub observed
	// in the window, including ones already evicted from the ring. (nil on old
	// hubs; additive.)
	//
	// This changed meaning: hubs before the per-second bucket rewrite computed
	// these by walking the ring, so both were implicitly capped at buffer
	// capacity and under-reported whenever the window held more traffic than
	// the buffer. At capacity 10000 and ~2000 entries/s only ~5s of traffic
	// fits in the ring, so Last5m.Entries goes from ~10000 (EntriesPerSec ~33)
	// to ~600000 (EntriesPerSec ~2000) across that upgrade — same field, same
	// JSON, a genuinely different (and correct) number. Anything trending these
	// across a hub upgrade will see a step change; that is expected, and the
	// new value is the real ingest rate rather than a buffer-capacity artefact.
	// Do not clamp these back to the buffer.
	Last1m *WindowStats `json:"last1m,omitempty"`
	Last5m *WindowStats `json:"last5m,omitempty"`
}

// StatsPoint is one sample in the hub's rolling stats history (see
// GET /api/stats/history), used to chart throughput trends — e.g. a
// "entries/sec over the last few minutes" sparkline.
type StatsPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	EntriesPerSec float64   `json:"entriesPerSec"`
	TotalEntries  int64     `json:"totalEntries"`
}
