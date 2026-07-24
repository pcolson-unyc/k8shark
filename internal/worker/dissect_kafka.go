package worker

import (
	"bufio"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

// Kafka wire protocol (DIS-8).
//
// Every request and response is a 4-byte big-endian size prefix followed by a
// payload. A request payload begins with the request header — api_key (INT16),
// api_version (INT16), correlation_id (INT32), client_id (nullable STRING) —
// then an api-specific body. A response payload begins with the response header
// — correlation_id (INT32) — then the response body. Unlike the FIFO-paired
// protocols, Kafka carries an explicit correlation id: the response echoes the
// request's correlation_id, so pairing is exact (a per-connection map keyed by
// correlation_id, mirroring the MongoDB requestID pairing rather than the
// connState FIFO — more robust than head-of-line ordering).
//
// The MVP surfaces, for every request, the api_key name + api_version +
// client_id, and (for Produce/Fetch/Metadata on the common non-flexible
// versions) the first topic name; on the response side it surfaces the
// error_code where cheaply parseable.
//
// Versioning caveat: Kafka's "flexible versions" (KIP-482 — tagged fields plus
// varint/compact strings) start at a different api_version per api_key. This
// dissector best-effort decodes the older/common non-flexible versions and, for
// flexible or unknown ones, still pairs by correlation_id and still surfaces
// api_key/api_version/client_id, but cleanly SKIPS deep body parsing rather than
// misreading compact-encoded bytes. All reads are bounded and never panic on a
// truncated or garbled frame.

// Kafka api_keys the MVP deep-parses (topics / top-level error_code). All other
// keys are still surfaced by name, just without body extraction.
const (
	apiKeyProduce  = 0
	apiKeyFetch    = 1
	apiKeyMetadata = 3
)

// Per-api_key api_version at which the request/response body switches to the
// flexible (tagged-fields / compact) encoding. At or above these versions we
// don't deep-parse the body (topic / error_code), only the fixed-position
// header fields (which stay non-compact). See KIP-482.
const (
	kafkaProduceFlexible  = 9
	kafkaFetchFlexible    = 12
	kafkaMetadataFlexible = 9
)

const (
	// kafkaMaxFrame bounds a single request/response frame size we'll accept.
	// Kafka's broker default socket.request.max.bytes is 100 MiB; anything
	// larger is treated as a misframed / non-Kafka / TLS-wrapped stream and ends
	// the direction.
	kafkaMaxFrame = 100 << 20
	// kafkaScanBytes bounds how much of a frame body we materialize to read the
	// header + first topic name; the rest (bulk record batches on a Produce, the
	// fetched records on a Fetch) is discarded, not allocated, so a large frame
	// costs a bounded prefix.
	kafkaScanBytes = 1 << 20
)

// kafkaPending is a request awaiting its response, keyed by conn+correlation_id.
type kafkaPending struct {
	apiKey     string
	apiVersion int
	topic      string
	clientID   string
	corrID     int32
	summary    string
	src, dst   api.Endpoint
	ts         time.Time
	raw        *api.RawView
}

// consumeKafkaID dissects one direction of a Kafka connection. isRequest means
// client -> server (requests); the other direction carries responses. Both feed
// the same correlation_id-keyed pairing map.
func (p *pipeline) consumeKafkaID(c connID, r io.Reader, isRequest bool) {
	r, cr := p.capture(r)
	br := bufio.NewReader(r)
	key := c.key()
	if isRequest {
		src, dst := c.endpoints()
		p.kafkaRequests(br, cr, key, src, dst)
		return
	}
	p.kafkaResponses(br, cr, key)
}

// readKafkaFrame reads the 4-byte big-endian size prefix and materializes a
// bounded prefix (min(size, kafkaScanBytes)) of the payload, discarding the
// rest so the stream stays framed. A negative or oversized size is treated as a
// garbled / non-Kafka stream and ends the direction.
func readKafkaFrame(br *bufio.Reader) ([]byte, error) {
	var sz [4]byte
	if _, err := io.ReadFull(br, sz[:]); err != nil {
		return nil, err
	}
	n := int(int32(binary.BigEndian.Uint32(sz[:])))
	if n < 0 || n > kafkaMaxFrame {
		return nil, io.ErrUnexpectedEOF
	}
	take := n
	if take > kafkaScanBytes {
		take = kafkaScanBytes
	}
	buf := make([]byte, take)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	if n > take {
		if _, err := io.CopyN(io.Discard, br, int64(n-take)); err != nil {
			return buf, err
		}
	}
	return buf, nil
}

func (p *pipeline) kafkaRequests(br *bufio.Reader, cr *capReader, key string, src, dst api.Endpoint) {
	marked := false
	for {
		payload, err := readKafkaFrame(br)
		if err != nil {
			return
		}
		if len(payload) < 8 {
			return // too short for a Kafka request header — desynced / not Kafka
		}
		apiKey := int(int16(binary.BigEndian.Uint16(payload[0:2])))
		apiVersion := int(int16(binary.BigEndian.Uint16(payload[2:4])))
		corrID := int32(binary.BigEndian.Uint32(payload[4:8]))
		if !marked {
			p.markL7(key) // L7-dissected: don't also emit a generic L4 flow
			marked = true
		}
		clientID, body := kafkaClientIDAndBody(payload[8:])
		name := kafkaAPIKeyName(apiKey)
		topic := kafkaRequestTopic(apiKey, apiVersion, body)
		p.kafkaStore(key, corrID, &kafkaPending{
			apiKey:     name,
			apiVersion: apiVersion,
			topic:      topic,
			clientID:   clientID,
			corrID:     corrID,
			summary:    kafkaSummary(name, apiVersion, topic),
			src:        src,
			dst:        dst,
			ts:         time.Now(),
			raw:        rawOf(cr),
		})
	}
}

func (p *pipeline) kafkaResponses(br *bufio.Reader, cr *capReader, key string) {
	for {
		payload, err := readKafkaFrame(br)
		if err != nil {
			return
		}
		if len(payload) < 4 {
			return // too short for a response header (correlation_id) — desynced
		}
		corrID := int32(binary.BigEndian.Uint32(payload[0:4]))
		p.kafkaComplete(key, corrID, payload[4:], rawOf(cr))
	}
}

func (p *pipeline) kafkaStore(key string, corrID int32, pend *kafkaPending) {
	p.mu.Lock()
	p.kafka[kafkaKey(key, corrID)] = pend
	p.mu.Unlock()
}

func (p *pipeline) kafkaComplete(key string, corrID int32, body []byte, raw *api.RawView) {
	mk := kafkaKey(key, corrID)
	p.mu.Lock()
	pend := p.kafka[mk]
	delete(p.kafka, mk)
	p.mu.Unlock()
	if pend == nil {
		return // no matching request (capture started mid-connection)
	}
	errCode, haveErr := kafkaResponseError(pend.apiKey, pend.apiVersion, body)
	status, summary := "success", "ok"
	var respDetail *api.KafkaDetail
	if haveErr && errCode != 0 {
		status = "error"
		summary = "error " + strconv.Itoa(errCode)
		respDetail = &api.KafkaDetail{ErrorCode: errCode}
	}
	now := time.Now()
	p.sink.emit(&api.Entry{
		ID:          p.node + "-kafka-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    api.ProtocolKafka,
		Timestamp:   pend.ts,
		ElapsedMs:   now.Sub(pend.ts).Milliseconds(),
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      pend.src,
		Destination: pend.dst,
		Request: api.Payload{
			Summary: pend.summary,
			Raw:     pend.raw,
			Kafka: &api.KafkaDetail{
				APIKey:        pend.apiKey,
				APIVersion:    pend.apiVersion,
				Topic:         pend.topic,
				ClientID:      pend.clientID,
				CorrelationID: pend.corrID,
			},
		},
		Response: api.Payload{
			Summary: summary,
			Raw:     raw,
			Kafka:   respDetail,
		},
		Status: status,
	})
}

func kafkaKey(connKey string, corrID int32) string {
	return connKey + "/" + strconv.FormatInt(int64(corrID), 10)
}

// kafkaSummary renders the human one-line description, e.g.
// "PRODUCE topic=orders (v9)" or "APIVERSIONS (v3)".
func kafkaSummary(apiKey string, apiVersion int, topic string) string {
	s := strings.ToUpper(apiKey)
	if topic != "" {
		s += " topic=" + topic
	}
	return s + " (v" + strconv.Itoa(apiVersion) + ")"
}

// kafkaClientIDAndBody reads the request header's client_id (a NULLABLE_STRING:
// INT16 length, -1 = null) and returns it plus the remaining bytes (the request
// body for non-flexible versions; for flexible request headers the tagged
// fields sit between here and the body, but those versions aren't deep-parsed).
// A truncated length yields ("", nil) so the caller simply doesn't parse a
// topic — the header (api_key/version/correlation_id) was already captured.
func kafkaClientIDAndBody(rest []byte) (string, []byte) {
	if len(rest) < 2 {
		return "", nil
	}
	n := int(int16(binary.BigEndian.Uint16(rest[0:2])))
	rest = rest[2:]
	if n < 0 { // null client_id
		return "", rest
	}
	if n > len(rest) {
		return "", nil
	}
	return string(rest[:n]), rest[n:]
}

// kafkaReadNullableString decodes a Kafka NULLABLE_STRING (INT16 length + bytes,
// -1 = null) from the front of b, bounds-checked, returning the value, the
// remaining bytes and whether it could be safely read.
func kafkaReadNullableString(b []byte) (string, []byte, bool) {
	if len(b) < 2 {
		return "", nil, false
	}
	n := int(int16(binary.BigEndian.Uint16(b[0:2])))
	b = b[2:]
	if n < 0 { // null
		return "", b, true
	}
	if n > len(b) {
		return "", nil, false
	}
	return string(b[:n]), b[n:], true
}

// kafkaFirstTopicName reads a non-compact topics array (INT32 element count
// followed by elements whose first field is the topic name STRING) and returns
// the first topic name. A null/empty array (count <= 0) or an unreadable name
// yields "".
func kafkaFirstTopicName(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	count := int32(binary.BigEndian.Uint32(b[0:4]))
	b = b[4:]
	if count <= 0 {
		return ""
	}
	name, _, ok := kafkaReadNullableString(b)
	if !ok {
		return ""
	}
	return name
}

// kafkaRequestTopic best-effort extracts the first topic name from a
// Produce/Fetch/Metadata request body on the common non-flexible versions. For
// flexible (compact-encoded) versions, unknown api_keys, or a truncated body it
// returns "" — the request is still paired and surfaced, just without a topic.
func kafkaRequestTopic(apiKey, apiVersion int, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	switch apiKey {
	case apiKeyProduce:
		if apiVersion >= kafkaProduceFlexible {
			return "" // flexible encoding — don't misparse
		}
		b := body
		if apiVersion >= 3 { // transactional_id (nullable string) added at v3
			_, rest, ok := kafkaReadNullableString(b)
			if !ok {
				return ""
			}
			b = rest
		}
		if len(b) < 6 { // acks(INT16) + timeout_ms(INT32)
			return ""
		}
		return kafkaFirstTopicName(b[6:])
	case apiKeyFetch:
		if apiVersion >= kafkaFetchFlexible {
			return ""
		}
		// Fixed prefix before the topics array grows with the version:
		//   replica_id(4) + max_wait_ms(4) + min_bytes(4)
		//   + max_bytes(4, v3+) + isolation_level(1, v4+)
		//   + session_id(4) + session_epoch(4) (both v7+)
		prefix := 12
		if apiVersion >= 3 {
			prefix += 4
		}
		if apiVersion >= 4 {
			prefix += 1
		}
		if apiVersion >= 7 {
			prefix += 8
		}
		if len(body) < prefix {
			return ""
		}
		return kafkaFirstTopicName(body[prefix:])
	case apiKeyMetadata:
		if apiVersion >= kafkaMetadataFlexible {
			return ""
		}
		// Metadata request body starts with the topics array (each element is
		// just the topic name STRING on v0-v8).
		return kafkaFirstTopicName(body)
	default:
		return ""
	}
}

// kafkaResponseError best-effort extracts an error_code from a response body
// where it sits at a cheaply-reachable position: the top-level error_code of an
// ApiVersions response (its header is always v0, so this works on every
// version), or the first partition's error_code of a non-flexible Produce
// response. Other api_keys / flexible versions return (0, false) — the pairing
// still completes as a success.
func kafkaResponseError(apiKey string, apiVersion int, body []byte) (int, bool) {
	switch apiKey {
	case "ApiVersions":
		// error_code is the first field of the body (INT16).
		if len(body) >= 2 {
			return int(int16(binary.BigEndian.Uint16(body[0:2]))), true
		}
	case "Produce":
		if apiVersion < kafkaProduceFlexible {
			return kafkaProduceFirstError(body)
		}
	}
	return 0, false
}

// kafkaProduceFirstError reads the first partition's error_code from a
// non-flexible Produce response body: responses array (INT32 count) of
// {name: STRING, partition_responses: array (INT32 count) of
// {index: INT32, error_code: INT16, ...}}. Bounds-checked throughout.
func kafkaProduceFirstError(body []byte) (int, bool) {
	b := body
	if len(b) < 4 {
		return 0, false
	}
	respCount := int32(binary.BigEndian.Uint32(b[0:4]))
	b = b[4:]
	if respCount <= 0 {
		return 0, false
	}
	_, b, ok := kafkaReadNullableString(b) // topic name
	if !ok || len(b) < 4 {
		return 0, false
	}
	partCount := int32(binary.BigEndian.Uint32(b[0:4]))
	b = b[4:]
	if partCount <= 0 || len(b) < 6 { // partition index(INT32) + error_code(INT16)
		return 0, false
	}
	return int(int16(binary.BigEndian.Uint16(b[4:6]))), true
}

// kafkaAPIKeyName renders a Kafka api_key number as its protocol name. Unknown
// keys become "APIKEY_<n>" so an unmapped/new key still shows something useful.
func kafkaAPIKeyName(apiKey int) string {
	if name, ok := kafkaAPIKeyNames[apiKey]; ok {
		return name
	}
	return "APIKEY_" + strconv.Itoa(apiKey)
}

// kafkaAPIKeyNames maps the well-known api_key numbers to their protocol names
// (the request-side kafka.apikey field and the summary use these).
var kafkaAPIKeyNames = map[int]string{
	0:  "Produce",
	1:  "Fetch",
	2:  "ListOffsets",
	3:  "Metadata",
	8:  "OffsetCommit",
	9:  "OffsetFetch",
	10: "FindCoordinator",
	11: "JoinGroup",
	12: "Heartbeat",
	13: "LeaveGroup",
	14: "SyncGroup",
	15: "DescribeGroups",
	16: "ListGroups",
	17: "SaslHandshake",
	18: "ApiVersions",
	19: "CreateTopics",
	20: "DeleteTopics",
	21: "DeleteRecords",
	22: "InitProducerId",
	23: "OffsetForLeaderEpoch",
	24: "AddPartitionsToTxn",
	25: "AddOffsetsToTxn",
	26: "EndTxn",
	28: "TxnOffsetCommit",
	32: "DescribeConfigs",
	33: "AlterConfigs",
	36: "SaslAuthenticate",
	37: "CreatePartitions",
	42: "DeleteGroups",
	47: "OffsetDelete",
}
