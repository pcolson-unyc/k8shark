package worker

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/gopacket"
	"github.com/pablocolson/k8shark/pkg/api"
)

// Bounds so a garbled or TLS-encrypted stream misparsed as RESP can't drive a
// huge allocation or a stack overflow.
const (
	maxRESPBulk     = 512 << 20 // wire-sanity cap per bulk string (redis' own proto-max-bulk-len default)
	maxRESPCapture  = 1 << 20   // bulk bytes materialized in memory; the rest is discarded, not allocated
	maxRESPElements = 1 << 20   // aggregate elements per array/map
	maxRESPDepth    = 64        // nesting depth (guards unbounded recursion)
)

var errRESP = errors.New("redis: RESP value exceeds bounds")

// consumeRedis dissects one direction of an AF_PACKET-discovered RESP
// connection. Thin wrapper over consumeRedisID (see conn.go).
func (p *pipeline) consumeRedis(netFlow, transport gopacket.Flow, r io.Reader, isRequest bool, proto api.Protocol) {
	p.consumeRedisID(connIDFromFlows(netFlow, transport), r, isRequest, proto)
}

// consumeRedisID dissects one direction of a RESP connection (Redis or
// Valkey — the two speak the identical RESP2/RESP3 wire protocol, so proto is
// not detected here; it is resolved by the caller from operator config keyed
// on port, see pipeline.respPorts in pipeline.go). The client side carries
// commands (RESP arrays of bulk strings); the server side carries replies.
// Unsolicited server pushes (pub/sub messages, RESP3 push frames) are emitted
// standalone rather than paired, so they don't desync request/response
// correlation. Fed by both AF_PACKET and eBPF-decrypted TLS streams.
func (p *pipeline) consumeRedisID(c connID, r io.Reader, isRequest bool, proto api.Protocol) {
	r, cr := p.capture(r)
	br := bufio.NewReader(r)
	key := c.key()

	if isRequest {
		src, dst := c.endpoints()
		// The SELECTed DB is per-connection state, and this loop IS the
		// connection's client direction: one goroutine, one stream, read by
		// nobody else. So it lives here as a local instead of in a mutex-guarded
		// map keyed by conn — a map that also had to outlive the stream and be
		// swept by gc() to not leak on ephemeral-port churn.
		db := 0
		for {
			v, err := parseRESP(br)
			if err != nil {
				_, _ = io.Copy(io.Discard, br)
				return
			}
			args, argsCut := redisArgs(v)
			cmd, cmdCut := capQuery(redisCommandLine(v, args))
			if cmd == "" {
				continue
			}
			// Track the connection's selected DB from SELECT n so every
			// subsequent command reports the DB it ran against.
			if len(args) == 2 && strings.EqualFold(args[0], "SELECT") {
				if n, err := strconv.Atoi(args[1]); err == nil {
					db = n
				}
			}
			if p.redactHeaders {
				if redacted, ok := redactSensitiveRedisArgs(args); ok {
					args = redacted
					var cut bool
					cmd, cut = capQuery(strings.Join(redacted, " "))
					cmdCut = cmdCut || cut
				}
			}
			p.enqueueRequest(key, proto, api.Payload{
				Command:   cmd,
				Summary:   truncate(cmd, 160),
				Truncated: cmdCut || argsCut,
				Raw:       rawOf(cr),
				Redis:     &api.RedisDetail{Args: args, DBIndex: db},
			}, src, dst)
		}
	}

	// Response side: server -> client. On this flow Src is the server.
	srv, cli := c.endpoints()
	for {
		v, err := parseRESP(br)
		if err != nil {
			_, _ = io.Copy(io.Discard, br)
			return
		}
		if isRedisPush(v) {
			p.emitRedisPush(srv, cli, v, proto)
			continue
		}
		summary, body, isErr := renderRedisReply(v)
		status := "success"
		if isErr {
			status = "error"
		}
		reply := body
		if reply == "" {
			reply = summary
		}
		p.completeResponse(key, api.Payload{
			Summary: summary,
			Body:    body,
			Size:    len(body),
			Raw:     rawOf(cr),
			Redis:   &api.RedisDetail{Reply: reply, ReplyType: respTypeName(v.typ), Attributes: v.attrs},
		}, 0, status, time.Time{})
	}
}

// respVal is a parsed RESP2/RESP3 value. typ is the RESP type byte; 'i' marks an
// inline command.
type respVal struct {
	typ   byte
	str   string
	arr   []respVal
	null  bool
	attrs map[string]string // RESP3 |attribute pairs preceding this value
}

// parseRESP reads one complete RESP value (RESP2 and the common RESP3 types).
func parseRESP(br *bufio.Reader) (respVal, error) {
	return parseRESPDepth(br, 0)
}

func parseRESPDepth(br *bufio.Reader, depth int) (respVal, error) {
	if depth > maxRESPDepth {
		return respVal{}, errRESP
	}
	t, err := br.ReadByte()
	if err != nil {
		return respVal{}, err
	}
	switch t {
	case '+', '-', ':', ',', '(', '#':
		// simple string / error / integer / RESP3 double / big number / boolean
		line, err := readCRLF(br)
		return respVal{typ: t, str: line}, err
	case '_': // RESP3 null
		_, err := readCRLF(br)
		return respVal{typ: t, null: true}, err
	case '$', '=': // bulk string / RESP3 verbatim string (same framing)
		line, err := readCRLF(br)
		if err != nil {
			return respVal{}, err
		}
		n, err := strconv.Atoi(line)
		if err != nil {
			return respVal{}, err
		}
		if n < 0 {
			return respVal{typ: t, null: true}, nil
		}
		if n > maxRESPBulk {
			return respVal{}, errRESP
		}
		// Materialize at most maxRESPCapture bytes (display/filtering only
		// ever uses a bounded prefix) and discard the rest plus the trailing
		// CRLF, so a multi-MiB SET value can't drive a matching allocation.
		take := n
		if take > maxRESPCapture {
			take = maxRESPCapture
		}
		buf := make([]byte, take)
		if _, err := io.ReadFull(br, buf); err != nil {
			return respVal{}, err
		}
		if _, err := io.CopyN(io.Discard, br, int64(n-take)+2); err != nil {
			return respVal{}, err
		}
		return respVal{typ: t, str: string(buf)}, nil
	case '*', '~', '>': // array / RESP3 set / RESP3 push (n elements)
		return parseRESPAgg(br, t, depth, 1)
	case '%': // RESP3 map (n key/value pairs => 2n elements)
		return parseRESPAgg(br, t, depth, 2)
	case '|': // RESP3 attribute: 2n elements, then the actual value follows
		attr, err := parseRESPAgg(br, '|', depth, 2)
		if err != nil {
			return respVal{}, err
		}
		v, err := parseRESPDepth(br, depth)
		if err != nil {
			return respVal{}, err
		}
		v.attrs = respAttrMap(attr)
		return v, nil
	default:
		// Inline command, e.g. "PING\r\n" — t is the first char.
		line, err := readCRLF(br)
		return respVal{typ: 'i', str: string(t) + line}, err
	}
}

// parseRESPAgg parses an aggregate (array/set/push/map). mult is 2 for maps.
func parseRESPAgg(br *bufio.Reader, t byte, depth, mult int) (respVal, error) {
	line, err := readCRLF(br)
	if err != nil {
		return respVal{}, err
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return respVal{}, err
	}
	if n < 0 {
		return respVal{typ: t, null: true}, nil
	}
	count := n * mult
	if count < 0 || count > maxRESPElements {
		return respVal{}, errRESP
	}
	arr := make([]respVal, 0, min(count, 64)) // grow on demand; avoid huge prealloc
	for i := 0; i < count; i++ {
		el, err := parseRESPDepth(br, depth+1)
		if err != nil {
			return respVal{}, err
		}
		arr = append(arr, el)
	}
	return respVal{typ: t, arr: arr}, nil
}

func readCRLF(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// renderRedisCommand flattens a RESP command value to a printable line.
func renderRedisCommand(v respVal) string {
	switch v.typ {
	case '*', '~':
		parts := make([]string, 0, len(v.arr))
		for _, el := range v.arr {
			parts = append(parts, redisScalar(el))
		}
		return strings.Join(parts, " ")
	case 'i':
		return strings.TrimSpace(v.str)
	default:
		return redisScalar(v)
	}
}

func redisScalar(v respVal) string {
	if v.null {
		return "(nil)"
	}
	if v.typ == '*' || v.typ == '~' || v.typ == '%' || v.typ == '>' {
		parts := make([]string, 0, len(v.arr))
		for _, el := range v.arr {
			parts = append(parts, redisScalar(el))
		}
		return "[" + strings.Join(parts, " ") + "]"
	}
	return redisDisplay(v.str)
}

// redisMaxValueDisplay bounds how much of a printable Redis value we render,
// so a multi-KB value (a serialized session, a JSON doc, ...) doesn't bloat
// the entry or flood the UI.
const redisMaxValueDisplay = 256

// redisDisplay renders a Redis bulk value safely. Printable UTF-8 passes
// through (length-bounded); a binary value (a gzip/protobuf/serialized blob,
// common as a cache payload) is shown as a bounded \xHH hex preview plus its
// true byte length — e.g. "\x1f8b0800… (614 bytes)" — instead of dumping raw
// bytes that corrupt the terminal/UI. Mirrors how the Postgres dissector
// renders binary bind params.
func redisDisplay(s string) string {
	if isRedisPrintable(s) {
		return truncate(s, redisMaxValueDisplay)
	}
	return binaryPreview(s)
}

// binaryPreview renders s (assumed non-printable) as a bounded \xHH hex
// preview plus its true byte length — e.g. "\x1f8b0800… (614 bytes)" —
// shared by redisDisplay and safeBody (pipeline.go, for HTTP/AMQP bodies).
func binaryPreview(s string) string {
	const hexPreview = 32
	b := []byte(s)
	if len(b) > hexPreview {
		return fmt.Sprintf("\\x%x… (%d bytes)", b[:hexPreview], len(b))
	}
	return "\\x" + hex.EncodeToString(b)
}

// isRedisPrintable reports whether s is valid UTF-8 with no control runes
// other than ordinary whitespace (tab/newline/carriage-return).
func isRedisPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || (unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r') {
			return false
		}
	}
	return true
}

// redisArgs returns the command and its arguments as a flat string slice,
// bounded at redisMaxArgs elements (caps.go). The second result reports whether
// the tail was dropped, which the caller surfaces as Payload.Truncated. Only the
// element COUNT is bounded here — element VALUES are already bounded by
// redisScalar -> redisDisplay (redisMaxValueDisplay), so nothing is double-capped.
// The over-cap elements are never even rendered: for a 1M-element pipelined MSET
// that is the difference between 64 short strings and hundreds of MiB.
func redisArgs(v respVal) ([]string, bool) {
	switch v.typ {
	case '*', '~':
		n := min(len(v.arr), redisMaxArgs)
		out := make([]string, 0, n+1)
		for _, el := range v.arr[:n] {
			out = append(out, redisScalar(el))
		}
		if len(v.arr) > n {
			return append(out, redisMoreMarker(len(v.arr)-n)), true
		}
		return out, false
	case 'i':
		return capRedisArgs(strings.Fields(v.str))
	default:
		if s := redisScalar(v); s != "" {
			return []string{s}, false
		}
		return nil, false
	}
}

// capRedisArgs bounds an already-materialized argument slice at redisMaxArgs,
// replacing the dropped tail with the "… (N more)" marker.
func capRedisArgs(args []string) ([]string, bool) {
	if len(args) <= redisMaxArgs {
		return args, false
	}
	// Full slice expression: appending must allocate rather than overwrite
	// args[redisMaxArgs], which the caller may still be holding.
	return append(args[:redisMaxArgs:redisMaxArgs], redisMoreMarker(len(args)-redisMaxArgs)), true
}

// redisMoreMarker renders the synthetic trailing element standing in for the
// arguments dropped at redisMaxArgs.
func redisMoreMarker(n int) string {
	return fmt.Sprintf("… (%d more)", n)
}

// redisCommandLine renders the printable command line for an already-capped
// argument slice. For the aggregate shapes it joins args instead of re-rendering
// every element through renderRedisCommand — which both halves the rendering
// work on the hot path and keeps the line inside redisMaxArgs. Other shapes
// (inline, scalar) have no arg-level structure to reuse and fall back.
func redisCommandLine(v respVal, args []string) string {
	switch v.typ {
	case '*', '~':
		return strings.Join(args, " ")
	default:
		return renderRedisCommand(v)
	}
}

// redactSensitiveRedisArgs scrubs the credential VALUE positions in a RESP
// command's arguments — AUTH's password, HELLO's "... AUTH user pass"
// clause, and CONFIG SET requirepass/masterauth's new value — while keeping
// the command and any non-credential arguments visible, matching how header
// redaction keeps header names but scrubs values. Returns the original slice
// and ok=false when args isn't one of these shapes, so the caller can tell
// "nothing to redact" apart from "redacted to an empty/unchanged result".
func redactSensitiveRedisArgs(args []string) (out []string, ok bool) {
	if len(args) < 2 {
		return args, false
	}
	switch strings.ToUpper(args[0]) {
	case "AUTH":
		// AUTH password | AUTH username password (Redis 6+ ACL form).
		out = append([]string(nil), args...)
		for i := 1; i < len(out); i++ {
			out[i] = redactedValue
		}
		return out, true
	case "HELLO":
		// HELLO [protover [AUTH username password] [SETNAME name]]
		for i, a := range args {
			if !strings.EqualFold(a, "AUTH") {
				continue
			}
			out = append([]string(nil), args...)
			for j := i + 1; j < len(out) && j < i+3; j++ {
				out[j] = redactedValue
			}
			return out, true
		}
		return args, false
	case "CONFIG":
		if len(args) >= 4 && strings.EqualFold(args[1], "SET") &&
			(strings.EqualFold(args[2], "requirepass") || strings.EqualFold(args[2], "masterauth")) {
			out = append([]string(nil), args...)
			for i := 3; i < len(out); i++ {
				out[i] = redactedValue
			}
			return out, true
		}
	}
	return args, false
}

// respTypeName names a RESP type byte for the detail pane.
func respTypeName(t byte) string {
	switch t {
	case '+', '$', '=':
		return "string"
	case '-':
		return "error"
	case ':':
		return "integer"
	case ',':
		return "double"
	case '(':
		return "bignum"
	case '#':
		return "boolean"
	case '_':
		return "null"
	case '*':
		return "array"
	case '~':
		return "set"
	case '%':
		return "map"
	case '>':
		return "push"
	case 'i':
		return "inline"
	default:
		return ""
	}
}

// respAttrMap flattens a RESP3 attribute aggregate (alternating key/value) into
// a string map.
func respAttrMap(attr respVal) map[string]string {
	if len(attr.arr) < 2 {
		return nil
	}
	m := make(map[string]string, len(attr.arr)/2)
	for i := 0; i+1 < len(attr.arr); i += 2 {
		m[redisScalar(attr.arr[i])] = redisScalar(attr.arr[i+1])
	}
	return m
}

// renderRedisReply describes a RESP reply and reports whether it is an error.
func renderRedisReply(v respVal) (summary, body string, isErr bool) {
	switch v.typ {
	case '+':
		return v.str, "+" + v.str, false
	case '-':
		return v.str, "-" + v.str, true
	case ':':
		return "(integer) " + v.str, ":" + v.str, false
	case ',':
		return "(double) " + v.str, v.str, false
	case '(':
		return "(bignum) " + v.str, v.str, false
	case '#':
		if v.str == "t" {
			return "(boolean) true", "true", false
		}
		return "(boolean) false", "false", false
	case '$', '=':
		if v.null {
			return "(nil)", "", false
		}
		disp := redisDisplay(v.str)
		return truncate(disp, 120), disp, false
	case '_':
		return "(nil)", "", false
	case '*':
		if v.null {
			return "(nil)", "", false
		}
		return "(array, " + strconv.Itoa(len(v.arr)) + " elements)", "", false
	case '~':
		return "(set, " + strconv.Itoa(len(v.arr)) + " elements)", "", false
	case '%':
		return "(map, " + strconv.Itoa(len(v.arr)/2) + " pairs)", "", false
	case '>':
		return "(push, " + strconv.Itoa(len(v.arr)) + " elements)", "", false
	case 'i':
		return v.str, v.str, false
	}
	return "", "", false
}

// isRedisPush reports whether a reply is an unsolicited server push (a RESP3
// push frame, or a RESP2 pub/sub message delivery) that has no matching request.
func isRedisPush(v respVal) bool {
	if v.typ == '>' {
		return true
	}
	if v.typ == '*' && len(v.arr) > 0 {
		switch strings.ToLower(v.arr[0].str) {
		case "message", "pmessage", "smessage":
			return true
		}
	}
	return false
}

func (p *pipeline) emitRedisPush(src, dst api.Endpoint, v respVal, proto api.Protocol) {
	kind, payload := redisPushDesc(v)
	p.sink.emit(&api.Entry{
		ID:          p.node + "-push-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    proto,
		Timestamp:   time.Now(),
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      src,
		Destination: dst,
		Request:     api.Payload{Command: kind, Summary: kind},
		Response:    api.Payload{Summary: payload},
		Status:      "success",
	})
}

func redisPushDesc(v respVal) (kind, payload string) {
	if len(v.arr) == 0 {
		return "push", ""
	}
	parts := make([]string, len(v.arr))
	for i, e := range v.arr {
		parts[i] = redisScalar(e)
	}
	kind = strings.Join(parts[:min(len(parts), 2)], " ")
	if len(parts) > 2 {
		payload = truncate(strings.Join(parts[2:], " "), 160)
	}
	return kind, payload
}
