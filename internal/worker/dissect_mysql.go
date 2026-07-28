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

// MySQL / MariaDB client-server protocol (DIS-11).
//
// The wire protocol frames every message as a 4-byte header — a 3-byte
// little-endian payload length plus a 1-byte sequence id — followed by the
// payload. A fresh command from the client resets the sequence to 0, and the
// server's reply to it runs seq 1, 2, ...; the handshake greeting is the only
// server packet at seq 0. This dissector covers the plaintext command phase:
//
//   - Client (request): COM_QUERY / COM_STMT_PREPARE surface the SQL text;
//     COM_STMT_EXECUTE surfaces the statement id. Handshake-response and auth
//     packets (seq != 0) are skipped, and a CLIENT_SSL upgrade is detected and
//     the direction stopped cleanly rather than framing TLS ciphertext as
//     MySQL packets.
//   - Server (response): the initial handshake greeting + auth exchange are
//     skipped; OK / ERR / result-set replies are then paired FIFO with the
//     pending requests, exactly like the Postgres dissector.
//
// A TLS-wrapped connection can't be dissected by AF_PACKET; the decrypted
// stream reaches here via eBPF (tls_pipeline.go), same as HTTP/Postgres.

const (
	// mysqlMaxPayload bounds how much of one packet payload is materialized in
	// memory (the pgMaxPayload analog). A wire packet's length is inherently
	// capped at 0xFFFFFF (16 MiB-1) by the 3-byte length field, but we only
	// ever need the leading command byte + a bounded prefix of SQL text, so
	// anything past this cap is discarded rather than allocated.
	mysqlMaxPayload = 4 << 20
	// mysqlHandshakePeek is how many bytes of a handshake-phase (seq != 0)
	// client packet we materialize to test for the CLIENT_SSL capability.
	mysqlHandshakePeek = 36
	// mysqlMaxColumns / mysqlMaxRows bound result-set walking so a garbled
	// column count or an endless row stream can't spin unbounded.
	mysqlMaxColumns = 4096
	mysqlMaxRows    = 1 << 24
)

// MySQL client command bytes (first payload byte of a command-phase packet).
const (
	comQuit        = 0x01
	comInitDB      = 0x02
	comQuery       = 0x03
	comPing        = 0x0e
	comStmtPrepare = 0x16
	comStmtExecute = 0x17
	comStmtClose   = 0x19
)

// MySQL response first-payload-byte markers.
const (
	mysqlOK  = 0x00
	mysqlEOF = 0xfe
	mysqlERR = 0xff
)

// clientSSLCapability is CLIENT_SSL in the 4-byte little-endian capability
// flags a client sends in its (short) SSL-request packet before a TLS upgrade.
const clientSSLCapability = 0x00000800

// consumeMySQLID dissects one direction of a MySQL connection. isRequest means
// client -> server (commands); the other direction carries server replies.
func (p *pipeline) consumeMySQLID(c connID, r io.Reader, isRequest bool) {
	r, cr := p.capture(r)
	br := bufio.NewReader(r)
	key := c.key()
	if isRequest {
		src, dst := c.endpoints()
		p.mysqlRequests(br, cr, key, src, dst)
		return
	}
	p.mysqlResponses(br, cr, key)
}

// readMySQLHeader reads the 4-byte packet header, returning the payload length
// and sequence id. The length is inherently bounded to 0xFFFFFF by the 3-byte
// field.
func readMySQLHeader(br *bufio.Reader) (length int, seq byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(br, hdr[:]); err != nil {
		return 0, 0, err
	}
	length = int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	return length, hdr[3], nil
}

// readMySQLPayload materializes a bounded prefix (min(length, cap)) of a
// packet payload and discards the rest so the stream stays framed.
func readMySQLPayload(br *bufio.Reader, length, cap int) ([]byte, error) {
	take := length
	if take > cap {
		take = cap
	}
	if take < 0 {
		take = 0
	}
	buf := make([]byte, take)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	if length > take {
		if _, err := io.CopyN(io.Discard, br, int64(length-take)); err != nil {
			return buf, err
		}
	}
	return buf, nil
}

// discardN drops the next n bytes from br (a skipped packet's payload).
func discardN(br *bufio.Reader, n int) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, br, int64(n))
	return err
}

func (p *pipeline) mysqlRequests(br *bufio.Reader, cr *capReader, key string, src, dst api.Endpoint) {
	for {
		length, seq, err := readMySQLHeader(br)
		if err != nil {
			return
		}
		// Only command-phase packets carry a command: a fresh command resets the
		// sequence to 0, whereas the handshake response and every auth packet
		// carry seq >= 1. This also skips the continuation packets of a >16 MiB
		// command (seq > 0) — the command byte was already captured from seq 0.
		if seq != 0 {
			peek, err := readMySQLPayload(br, length, mysqlHandshakePeek)
			if err != nil {
				return
			}
			// A CLIENT_SSL short request means the rest of the connection is
			// TLS-encrypted; stop cleanly instead of misframing ciphertext.
			if isMySQLSSLRequest(peek, length) {
				_, _ = io.Copy(io.Discard, br)
				return
			}
			continue
		}
		payload, err := readMySQLPayload(br, length, mysqlMaxPayload)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			continue
		}
		switch cmd := payload[0]; cmd {
		case comQuery, comStmtPrepare:
			name := "COM_QUERY"
			if cmd == comStmtPrepare {
				name = "COM_STMT_PREPARE"
			}
			p.enqueueRequest(key, api.ProtocolMySQL, mysqlQueryPayload(payload[1:], name, rawOf(cr)), src, dst)
		case comStmtExecute:
			summary := "COM_STMT_EXECUTE"
			if len(payload) >= 5 {
				id := binary.LittleEndian.Uint32(payload[1:5])
				summary = "EXECUTE stmt " + strconv.FormatUint(uint64(id), 10)
			}
			pl := api.Payload{Summary: summary, Raw: rawOf(cr), MySQL: &api.MySQLDetail{Command: "COM_STMT_EXECUTE"}}
			p.enqueueRequest(key, api.ProtocolMySQL, pl, src, dst)
		case comInitDB, comPing:
			// These elicit a plain OK/ERR reply; enqueue a generic entry so the
			// FIFO pairing on the response side stays aligned.
			pl := api.Payload{Summary: mysqlCommandName(cmd), Raw: rawOf(cr), MySQL: &api.MySQLDetail{Command: mysqlCommandName(cmd)}}
			p.enqueueRequest(key, api.ProtocolMySQL, pl, src, dst)
		default:
			// COM_QUIT / COM_STMT_CLOSE (no server reply) and every other command
			// are not enqueued: enqueuing a request whose response we never pop
			// (or whose reply shape we don't model) would desync the FIFO. This is
			// the same documented head-of-line limitation the Postgres dissector
			// carries.
		}
	}
}

func (p *pipeline) mysqlResponses(br *bufio.Reader, cr *capReader, key string) {
	firstPacket, inHandshake := true, false
	for {
		length, seq, err := readMySQLHeader(br)
		if err != nil {
			return
		}
		payload, err := readMySQLPayload(br, length, mysqlMaxPayload)
		if err != nil {
			return
		}
		if firstPacket {
			firstPacket = false
			// A server greeting (protocol version 10 = 0x0a, or the legacy 9) at
			// seq 0 means capture began at connection start: skip the greeting
			// plus the auth exchange up to (and including) the OK/ERR that
			// concludes it. Absent a greeting we started mid-stream, already in
			// the command phase, so we fall straight through to pairing.
			if seq == 0 && len(payload) > 0 && (payload[0] == 0x0a || payload[0] == 0x09) {
				inHandshake = true
				continue
			}
		}
		if inHandshake {
			if len(payload) > 0 && (payload[0] == mysqlOK || payload[0] == mysqlERR) {
				inHandshake = false
			}
			continue
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case mysqlERR:
			code, msg := parseMySQLErr(payload)
			p.completeResponse(key, api.Payload{
				Summary: mysqlErrSummary(code, msg),
				Raw:     rawOf(cr),
				MySQL:   &api.MySQLDetail{ErrorCode: code, ErrorMessage: msg},
			}, 0, "error", time.Time{})
		case mysqlOK:
			rows := mysqlOKRows(payload)
			summary := "OK"
			if rows > 0 {
				summary = "OK (" + strconv.Itoa(rows) + " rows affected)"
			}
			p.completeResponse(key, api.Payload{
				Summary:  summary,
				RowCount: rows,
				Raw:      rawOf(cr),
			}, 0, "success", time.Time{})
		default:
			// Result set: the first packet is a length-encoded column count,
			// followed by column definitions, an optional EOF, then the rows.
			rows, err := readMySQLResultSet(br, payload)
			p.completeResponse(key, api.Payload{
				Summary:  strconv.Itoa(rows) + " rows",
				RowCount: rows,
				Raw:      rawOf(cr),
			}, 0, "success", time.Time{})
			if err != nil {
				return // stream ended mid-result-set
			}
		}
	}
}

// readMySQLResultSet consumes a text-protocol result set given its already-read
// first packet (the column-count packet). It discards the column-definition
// packets, then counts row packets up to the terminating EOF/OK. It never
// materializes a row payload and never panics on a short/garbled stream.
//
// It handles both wire dialects: pre-CLIENT_DEPRECATE_EOF servers send a 5-byte
// EOF packet after the column definitions and another after the rows, whereas
// modern (DEPRECATE_EOF) servers omit both and terminate the rows with an
// OK-shaped packet that (for backward compatibility) also starts with 0xfe but
// is >=7 bytes. The 5-byte column-section EOF is recognized and consumed once so
// it isn't mistaken for an empty (zero-row) result.
func readMySQLResultSet(br *bufio.Reader, first []byte) (int, error) {
	ncols, ok := mysqlLenEncInt(first)
	if !ok || ncols == 0 || ncols > mysqlMaxColumns {
		return 0, nil // not a result set we can walk — nothing counted
	}
	for i := uint64(0); i < ncols; i++ {
		length, _, err := readMySQLHeader(br)
		if err != nil {
			return 0, err
		}
		if err := discardN(br, length); err != nil {
			return 0, err
		}
	}
	rows, consumedColEOF := 0, false
	for rows <= mysqlMaxRows {
		length, _, err := readMySQLHeader(br)
		if err != nil {
			return rows, err
		}
		var b [1]byte
		if length > 0 {
			if _, err := io.ReadFull(br, b[:]); err != nil {
				return rows, err
			}
			if err := discardN(br, length-1); err != nil {
				return rows, err
			}
		}
		// Terminator: 0xfe with a short packet (a real row starting with 0xfe
		// carries an 8-byte length and is far larger). A 5-byte EOF before any
		// rows is the column-section terminator (old protocol) — consume it and
		// keep reading rows; anything else terminates the result set.
		if length > 0 && b[0] == mysqlEOF && length < 9 {
			if !consumedColEOF && length == 5 {
				consumedColEOF = true
				continue
			}
			return rows, nil
		}
		if length == 0 {
			continue
		}
		rows++
	}
	return rows, nil
}

// mysqlLenEncInt decodes a MySQL length-encoded integer from the front of b,
// bounds-checked. Used for the result-set column count.
func mysqlLenEncInt(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	switch c := b[0]; {
	case c < 0xfb:
		return uint64(c), true
	case c == 0xfc:
		if len(b) < 3 {
			return 0, false
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), true
	case c == 0xfd:
		if len(b) < 4 {
			return 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, true
	case c == 0xfe:
		if len(b) < 9 {
			return 0, false
		}
		return binary.LittleEndian.Uint64(b[1:9]), true
	default: // 0xfb (NULL) / 0xff — not a valid length here
		return 0, false
	}
}

// isMySQLSSLRequest reports whether a handshake-phase client packet is the
// short CLIENT_SSL request that precedes a TLS upgrade (capability flags with
// the CLIENT_SSL bit set and no username payload).
func isMySQLSSLRequest(payload []byte, length int) bool {
	if len(payload) < 4 || length > mysqlHandshakePeek {
		return false
	}
	caps := binary.LittleEndian.Uint32(payload[:4])
	return caps&clientSSLCapability != 0
}

// parseMySQLErr decodes an ERR packet: 0xff + error-code(2 LE) + optional
// '#' + 5-char SQL state + message.
func parseMySQLErr(b []byte) (int, string) {
	if len(b) < 3 {
		return 0, ""
	}
	code := int(binary.LittleEndian.Uint16(b[1:3]))
	rest := b[3:]
	if len(rest) >= 6 && rest[0] == '#' {
		rest = rest[6:]
	}
	return code, string(rest)
}

// mysqlOKRows extracts the affected-row count (a length-encoded int) from an OK
// packet, or 0 if it can't be read.
func mysqlOKRows(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	n, ok := mysqlLenEncInt(b[1:])
	if !ok {
		return 0
	}
	return int(n)
}

func mysqlErrSummary(code int, msg string) string {
	if msg == "" {
		return "ERROR " + strconv.Itoa(code)
	}
	return "ERROR " + strconv.Itoa(code) + ": " + truncate(collapseWS(msg), 160)
}

// mysqlQueryPayload builds the request payload for a COM_QUERY /
// COM_STMT_PREPARE. It takes the raw payload bytes rather than a string so the
// queryCap cut (caps.go) happens BEFORE the copy: a command packet is
// materialized up to mysqlMaxPayload (4 MiB), and stringifying all of it just
// to keep the first 8 KiB would both copy and retain megabytes per entry.
func mysqlQueryPayload(q []byte, cmd string, raw *api.RawView) api.Payload {
	text, truncated := capQueryBytes(q)
	text = strings.TrimSpace(text)
	return api.Payload{
		Query:     text,
		Summary:   truncate(collapseWS(text), 160),
		Truncated: truncated,
		Raw:       raw,
		MySQL:     &api.MySQLDetail{Command: cmd},
	}
}

// mysqlCommandName renders a command byte as its wire name for the summary /
// mysql.command filter field.
func mysqlCommandName(cmd byte) string {
	switch cmd {
	case comQuit:
		return "COM_QUIT"
	case comInitDB:
		return "COM_INIT_DB"
	case comQuery:
		return "COM_QUERY"
	case comPing:
		return "COM_PING"
	case comStmtPrepare:
		return "COM_STMT_PREPARE"
	case comStmtExecute:
		return "COM_STMT_EXECUTE"
	case comStmtClose:
		return "COM_STMT_CLOSE"
	default:
		return "COM_0x" + strconv.FormatInt(int64(cmd), 16)
	}
}
