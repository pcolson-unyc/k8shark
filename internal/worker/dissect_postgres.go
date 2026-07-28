package worker

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/pablocolson/k8shark/pkg/api"
)

// pgMaxPayload bounds how much of one message payload is materialized in
// memory; anything beyond it — and every message type the dissector only
// counts or skips, like DataRow or CopyData — is discarded via io.CopyN
// rather than allocated, so a large resultset or COPY can't drive multi-MiB
// allocations against the worker's memory limit.
const pgMaxPayload = 4 << 20

// pgMaxFrame is a wire-sanity bound on the declared message length itself
// (the PostgreSQL protocol caps messages at 1 GiB): a bigger length means a
// misframed/encrypted stream (e.g. TLS), so we bail instead of discarding
// garbage forever.
const pgMaxFrame = 1 << 30

// pgMaxStmtQueries bounds the per-connection prepared-statement cache so a
// connection that churns through many uniquely-named statements can't grow it
// without limit. On overflow the cache is cleared (statements named afterward
// simply won't resolve to their SQL text — a graceful degradation).
const pgMaxStmtQueries = 256

var errPGFrame = errors.New("postgres: bad frame length")

// consumePostgres dissects one direction of an AF_PACKET-discovered
// PostgreSQL connection. Thin wrapper over consumePostgresID (see conn.go).
func (p *pipeline) consumePostgres(netFlow, transport gopacket.Flow, r io.Reader, isRequest bool) {
	p.consumePostgresID(connIDFromFlows(netFlow, transport), r, isRequest)
}

// consumePostgresID dissects one direction of a PostgreSQL connection.
//
// This covers the plaintext protocol: the frontend Simple Query ('Q') and the
// extended-query Parse/Execute ('P'/'E'), paired FIFO with the backend's
// CommandComplete ('C') / ErrorResponse ('E') / EmptyQueryResponse ('I').
// A TLS-wrapped connection can't be dissected by AF_PACKET and is dropped on
// the first misframe; the decrypted stream reaches here instead via eBPF (see
// tls_pipeline.go), same as HTTP.
func (p *pipeline) consumePostgresID(c connID, r io.Reader, isRequest bool) {
	r, cr := p.capture(r)
	br := bufio.NewReader(r)
	key := c.key()
	if isRequest {
		src, dst := c.endpoints()
		p.pgRequests(br, cr, key, src, dst)
		return
	}
	p.pgResponses(br, cr, key)
}

func (p *pipeline) pgRequests(br *bufio.Reader, cr *capReader, key string, src, dst api.Endpoint) {
	// Drain leading untyped messages. These have no type byte: StartupMessage,
	// SSLRequest, CancelRequest — and with sslmode=prefer (libpq's default)
	// against a non-TLS server the client sends an SSLRequest AND then a
	// plaintext StartupMessage, i.e. TWO untyped messages before any typed one.
	if err := skipLeadingUntyped(br); err != nil {
		return
	}
	// Extended-query state carried from Parse -> Bind -> Execute.
	lastQuery, lastStmt, lastPortal := "", "", ""
	var lastParams []string
	stmtQueries := map[string]string{} // prepared statement name -> query text
	for {
		// Only Query/Parse/Bind payloads are inspected; Execute and Terminate
		// dispatch on the type byte alone, and CopyData etc. are skipped — so
		// their payloads are discarded, never allocated.
		typ, payload, err := readPGMessage(br, "QPB")
		if err != nil {
			return
		}
		switch typ {
		case 'Q': // Simple Query
			q := pgCStr(payload)
			p.enqueueRequest(key, api.ProtocolPostgres, pgQueryPayload(q, rawOf(cr)), src, dst)
		case 'P': // Parse (extended): stmtName\0 query\0 int16 nparams [oids...]
			name, rest := pgSplitCStr(payload)
			q, _ := pgSplitCStr(rest)
			lastQuery, lastStmt = q, name
			if name != "" {
				if _, ok := stmtQueries[name]; !ok && len(stmtQueries) >= pgMaxStmtQueries {
					stmtQueries = map[string]string{} // bounded cache: clear rather than grow unbounded
				}
				stmtQueries[name] = q
			}
		case 'B': // Bind: portal\0 stmt\0 param-formats param-values result-formats
			portal, stmt, params := pgParseBind(payload)
			lastPortal, lastParams = portal, params
			if stmt != "" {
				lastStmt = stmt
				if q, ok := stmtQueries[stmt]; ok {
					lastQuery = q
				}
			}
		case 'E': // Execute (extended)
			q := lastQuery
			if q == "" {
				q = "EXECUTE"
			}
			params := lastParams
			if p.redactPGParams {
				params = redactedParams(len(params))
			}
			pl := pgQueryPayload(q, rawOf(cr))
			pl.Postgres = &api.PGDetail{StatementName: lastStmt, Portal: lastPortal, Params: params}
			p.enqueueRequest(key, api.ProtocolPostgres, pl, src, dst)
			lastParams = nil // params belong to one execution
		case 'X': // Terminate
			return
		}
	}
}

func (p *pipeline) pgResponses(br *bufio.Reader, cr *capReader, key string) {
	if err := skipLeadingUntyped(br); err != nil {
		return
	}
	rows := 0
	var cols []api.PGColumn
	txStatus := ""
	for {
		// DataRow ('D') is only counted, so its payload — the bulk of a big
		// resultset — is discarded without allocating.
		typ, payload, err := readPGMessage(br, "TZCE")
		if err != nil {
			return
		}
		switch typ {
		case 'T': // RowDescription
			cols = pgParseRowDescription(payload)
		case 'D': // DataRow
			rows++
		case 'Z': // ReadyForQuery: 1-byte transaction status (I|T|E)
			if len(payload) >= 1 {
				txStatus = string(payload[0])
			}
		case 'C': // CommandComplete: tag\0 e.g. "SELECT 5"
			tag := pgCStr(payload)
			summary := tag
			if rows > 0 {
				summary = tag + " (" + strconv.Itoa(rows) + " rows)"
			}
			p.completeResponse(key, api.Payload{
				Summary:  summary,
				RowCount: rows,
				Raw:      rawOf(cr),
				Postgres: &api.PGDetail{Tag: tag, Columns: cols, TxStatus: txStatus},
			}, 0, "success", time.Time{})
			rows, cols = 0, nil
		case 'E': // ErrorResponse
			p.completeResponse(key, api.Payload{
				Summary:  pgErrorMessage(payload),
				Raw:      rawOf(cr),
				Postgres: &api.PGDetail{Error: pgParseError(payload), TxStatus: txStatus},
			}, 0, "error", time.Time{})
			rows, cols = 0, nil
		case 'I': // EmptyQueryResponse
			p.completeResponse(key, api.Payload{
				Summary:  "empty query",
				Raw:      rawOf(cr),
				Postgres: &api.PGDetail{TxStatus: txStatus},
			}, 0, "success", time.Time{})
			rows, cols = 0, nil
		}
	}
}

// readPGMessage reads one typed message: 1 type byte + int32 length (incl. the
// length field) + payload. Only messages whose type byte appears in want get
// their payload materialized (bounded at pgMaxPayload, remainder discarded);
// any other type returns a nil payload after discarding it, so a huge DataRow
// or CopyData never allocates.
func readPGMessage(br *bufio.Reader, want string) (byte, []byte, error) {
	typ, err := br.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 4 || length-4 > pgMaxFrame {
		return 0, nil, errPGFrame
	}
	n := int64(length - 4)
	if !strings.ContainsRune(want, rune(typ)) {
		if _, err := io.CopyN(io.Discard, br, n); err != nil {
			return 0, nil, err
		}
		return typ, nil, nil
	}
	take := n
	if take > pgMaxPayload {
		take = pgMaxPayload
	}
	payload := make([]byte, take)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	if _, err := io.CopyN(io.Discard, br, n-take); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// peekUntyped reports whether the next message is an untyped (startup-class)
// message. Those begin with a 4-byte length whose high byte is 0 for any
// realistic size; typed messages begin with an ASCII letter.
func peekUntyped(br *bufio.Reader) (bool, error) {
	b, err := br.Peek(1)
	if err != nil {
		return false, err
	}
	return b[0] == 0, nil
}

func skipUntyped(br *bufio.Reader) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 4 || length-4 > pgMaxFrame {
		return errPGFrame
	}
	_, err := io.CopyN(io.Discard, br, int64(length-4))
	return err
}

// skipLeadingUntyped consumes every consecutive untyped (startup-class) message
// at the head of the stream, stopping at the first typed message.
func skipLeadingUntyped(br *bufio.Reader) error {
	for {
		untyped, err := peekUntyped(br)
		if err != nil {
			return err
		}
		if !untyped {
			return nil
		}
		if err := skipUntyped(br); err != nil {
			return err
		}
	}
}

// pgQueryPayload builds the request payload for one Query/Execute. The query
// text is capped at queryCap (caps.go) BEFORE it is retained or whitespace-
// collapsed: readPGMessage materializes up to pgMaxPayload (4 MiB) of a
// Query/Parse message, and without this cap all of it would stay alive in the
// hub's ring buffer — and be walked again by collapseWS — for a statement whose
// interesting part is its first line.
func pgQueryPayload(q string, raw *api.RawView) api.Payload {
	q, truncated := capQuery(strings.TrimSpace(q))
	return api.Payload{Query: q, Summary: truncate(collapseWS(q), 160), Raw: raw, Truncated: truncated}
}

// pgMaxBindParams caps how many bind parameters we parse from one Bind message,
// so a misframed/garbled length can't drive a huge allocation.
const pgMaxBindParams = 1 << 16

// pgParseBind extracts the portal name, prepared-statement name and rendered
// parameter values from a Bind message payload. Text params are rendered as-is,
// binary params as "\x<hex>"; NULL params as "(null)". It is fully
// bounds-checked and never panics on a short/garbled payload.
// redactedParams returns n placeholder values, used in place of a Bind
// message's actual parameter values when redactPGParams is on. Bind params
// are positional (no name attached at the wire level, unlike an HTTP header
// or query param), so there is no way to redact only the sensitive ones —
// this is deliberately all-or-nothing. The count is preserved rather than
// collapsing to a single marker so "this call bound 3 params" stays visible.
func redactedParams(n int) []string {
	if n == 0 {
		return nil
	}
	out := make([]string, n)
	for i := range out {
		out[i] = redactedValue
	}
	return out
}

func pgParseBind(b []byte) (portal, stmt string, params []string) {
	portal, b = pgSplitCStr(b)
	stmt, b = pgSplitCStr(b)
	// Parameter format codes (int16 count, then that many int16 codes).
	if len(b) < 2 {
		return
	}
	nfmt := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	formats := make([]int, 0, nfmt)
	for i := 0; i < nfmt; i++ {
		if len(b) < 2 {
			return
		}
		formats = append(formats, int(binary.BigEndian.Uint16(b[:2])))
		b = b[2:]
	}
	// Parameter values.
	if len(b) < 2 {
		return
	}
	nparams := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if nparams > pgMaxBindParams {
		return
	}
	params = make([]string, 0, nparams)
	for i := 0; i < nparams; i++ {
		if len(b) < 4 {
			return portal, stmt, params
		}
		plen := int32(binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
		if plen < 0 { // -1 = SQL NULL
			params = append(params, "(null)")
			continue
		}
		if int(plen) > len(b) {
			return portal, stmt, params
		}
		val := b[:plen]
		b = b[plen:]
		isBinary := false
		switch {
		case nfmt == 1:
			isBinary = formats[0] == 1
		case i < nfmt:
			isBinary = formats[i] == 1
		}
		if isBinary {
			params = append(params, truncate("\\x"+hex.EncodeToString(val), 256))
		} else {
			params = append(params, truncate(string(val), 256))
		}
	}
	return portal, stmt, params
}

// pgParseRowDescription decodes a RowDescription ('T') into typed columns.
func pgParseRowDescription(b []byte) []api.PGColumn {
	if len(b) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if n <= 0 {
		return nil
	}
	cols := make([]api.PGColumn, 0, n)
	for i := 0; i < n; i++ {
		name, rest := pgSplitCStr(b)
		b = rest
		// tableOID(4) colAttr(2) typeOID(4) typeSize(2) typeMod(4) format(2)
		if len(b) < 18 {
			return cols
		}
		typeOID := int(binary.BigEndian.Uint32(b[6:10]))
		b = b[18:]
		cols = append(cols, api.PGColumn{Name: name, TypeOID: typeOID, Type: pgTypeName(typeOID)})
	}
	return cols
}

// pgParseError decodes an ErrorResponse payload into typed fields (a superset of
// pgErrorMessage, which stays for the human-readable summary).
func pgParseError(b []byte) *api.PGError {
	e := &api.PGError{}
	rest := b
	for len(rest) > 0 && rest[0] != 0 {
		ft := rest[0]
		val, r := pgSplitCStr(rest[1:])
		rest = r
		switch ft {
		case 'S', 'V': // Severity (V is the non-localized form)
			if e.Severity == "" {
				e.Severity = val
			}
		case 'C':
			e.Code = val
		case 'M':
			e.Message = val
		case 'D':
			e.Detail = val
		case 'H':
			e.Hint = val
		case 'W':
			e.Where = val
		}
	}
	return e
}

// pgTypeName resolves common PostgreSQL type OIDs to names.
func pgTypeName(oid int) string {
	switch oid {
	case 16:
		return "bool"
	case 17:
		return "bytea"
	case 18:
		return "char"
	case 19:
		return "name"
	case 20:
		return "int8"
	case 21:
		return "int2"
	case 23:
		return "int4"
	case 25:
		return "text"
	case 26:
		return "oid"
	case 114:
		return "json"
	case 700:
		return "float4"
	case 701:
		return "float8"
	case 1042:
		return "bpchar"
	case 1043:
		return "varchar"
	case 1082:
		return "date"
	case 1083:
		return "time"
	case 1114:
		return "timestamp"
	case 1184:
		return "timestamptz"
	case 1700:
		return "numeric"
	case 2950:
		return "uuid"
	case 3802:
		return "jsonb"
	default:
		return ""
	}
}

// pgCStr returns the first null-terminated string in b (or all of b).
func pgCStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// pgSplitCStr splits b at the first NUL into (string, remainder-after-NUL).
func pgSplitCStr(b []byte) (string, []byte) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b), nil
	}
	return string(b[:i]), b[i+1:]
}

// pgErrorMessage extracts a readable message from an ErrorResponse payload,
// which is a series of {type byte, cstr} fields terminated by a 0 byte.
func pgErrorMessage(b []byte) string {
	var msg, code, sev string
	rest := b
	for len(rest) > 0 && rest[0] != 0 {
		ft := rest[0]
		val, r := pgSplitCStr(rest[1:])
		rest = r
		switch ft {
		case 'M':
			msg = val
		case 'C':
			code = val
		case 'S':
			sev = val
		}
	}
	out := msg
	if sev != "" {
		out = sev + ": " + out
	}
	if code != "" {
		out += " (" + code + ")"
	}
	if out == "" {
		return "error"
	}
	return out
}

func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
