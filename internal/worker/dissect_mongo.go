package worker

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

// MongoDB wire protocol (DIS-11).
//
// Every message starts with a 16-byte MsgHeader — messageLength, requestID,
// responseTo, opCode (all int32 little-endian) — followed by an opcode-specific
// body. Unlike the FIFO-paired protocols, MongoDB carries an explicit
// request/response correlation: a request has responseTo == 0 and the reply
// echoes the request's id in its responseTo, so pairing is exact (a
// per-connection map keyed by requestID, mirroring the DNS pending map rather
// than the connState FIFO).
//
// Coverage is the modern OP_MSG (2013) with its section-0 BSON command
// document, plus the legacy OP_QUERY (2004) / OP_REPLY (1) still used by the
// initial handshake. A small, strictly bounded BSON scanner extracts just the
// command name + collection ($db, and the first document key) on the request
// side and ok / errmsg on the response side; it never recurses and never
// panics on truncated or garbled input.

const (
	opReply = 1    // OP_REPLY (legacy, response to OP_QUERY)
	opQuery = 2004 // OP_QUERY (legacy)
	opMsg   = 2013 // OP_MSG (modern)

	// mongoMaxMessage bounds a message length we'll accept (mongod's default
	// maxMessageSizeBytes is 48 MiB); anything larger is treated as a misframed
	// or TLS-wrapped stream and ends the direction.
	mongoMaxMessage = 48 << 20
	// mongoScanBytes bounds how much of a message body we materialize to find
	// and scan the section-0 command document (which is always the first
	// section); bulk document sequences past it are discarded, not allocated.
	//
	// 64 KiB: the command document is the command name + its options + $db,
	// i.e. kilobytes, because the drivers put bulk payloads (the documents of
	// an insert/update/delete) in the kind-1 document sequences that FOLLOW it,
	// not inside it. The rare command document that does exceed this — a
	// hand-built inline insert, a huge $in list — is no longer dropped either:
	// opMsgBodyDoc hands back the materialized prefix, and the command name is
	// the document's first key, so only trailing fields like $db are lost.
	mongoScanBytes = 64 << 10
)

// mongoPending is a request awaiting its reply, keyed by conn+requestID.
type mongoPending struct {
	command, collection, database string
	summary                       string
	src, dst                      api.Endpoint
	ts                            time.Time
	raw                           *api.RawView
}

// consumeMongoID dissects one direction of a MongoDB connection. Direction
// (isRequest) is only a hint for endpoint labelling; request vs. response is
// decided from the header's responseTo (0 = request), so both directions feed
// the same requestID-keyed pairing map correctly.
func (p *pipeline) consumeMongoID(c connID, r io.Reader, isRequest bool) {
	r, cr := p.capture(r)
	br := bufio.NewReader(r)
	key := c.key()
	src, dst := c.endpoints()
	marked := false
	for {
		var hdr [16]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		msgLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
		requestID := int32(binary.LittleEndian.Uint32(hdr[4:8]))
		responseTo := int32(binary.LittleEndian.Uint32(hdr[8:12]))
		opCode := int32(binary.LittleEndian.Uint32(hdr[12:16]))
		if msgLen < 16 || int64(msgLen) > mongoMaxMessage {
			return // garbled / not MongoDB / TLS ciphertext
		}
		body, err := readMongoBody(br, int(msgLen)-16, mongoScanBytes)
		if err != nil {
			return
		}
		if !marked {
			p.markL7(key) // L7-dissected: don't also emit a generic L4 flow
			marked = true
		}
		switch opCode {
		case opMsg:
			p.mongoOpMsg(key, src, dst, requestID, responseTo, body, rawOf(cr))
		case opQuery:
			p.mongoOpQuery(key, src, dst, requestID, body, rawOf(cr))
		case opReply:
			p.mongoOpReply(key, responseTo, body, rawOf(cr))
		default:
			// OP_COMPRESSED (2012) and others — skip cleanly (body consumed).
		}
	}
}

// readMongoBody materializes a bounded prefix of a message body and discards
// the rest so the stream stays framed.
func readMongoBody(br *bufio.Reader, length, cap int) ([]byte, error) {
	if length < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	take := length
	if take > cap {
		take = cap
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

// mongoOpMsg handles an OP_MSG in either direction, pairing on responseTo.
func (p *pipeline) mongoOpMsg(key string, src, dst api.Endpoint, requestID, responseTo int32, body []byte, raw *api.RawView) {
	doc := opMsgBodyDoc(body)
	if doc == nil {
		return
	}
	if responseTo == 0 {
		command, collection, database := mongoParseCommand(doc)
		if command == "" {
			return
		}
		p.mongoStore(key, requestID, mongoPendingFor(command, collection, database, src, dst, raw))
		return
	}
	ok, hasOK, errmsg := mongoParseReply(doc)
	if !hasOK {
		ok = true
	}
	p.mongoComplete(key, responseTo, ok, errmsg, raw)
}

// mongoOpQuery handles a legacy OP_QUERY request. Layout after the header:
// flags(4) + fullCollectionName(cstring) + numberToSkip(4) + numberToReturn(4)
// + query(BSON). For a command query on "<db>.$cmd" the command name is the
// query document's first key; otherwise it's a plain find on the named
// collection.
func (p *pipeline) mongoOpQuery(key string, src, dst api.Endpoint, requestID int32, body []byte, raw *api.RawView) {
	if len(body) < 4 {
		return
	}
	b := body[4:] // skip flags
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return
	}
	fullName := string(b[:i])
	b = b[i+1:]
	if len(b) < 8 {
		return
	}
	b = b[8:] // skip numberToSkip + numberToReturn

	database, collection := "", fullName
	if dot := strings.IndexByte(fullName, '.'); dot >= 0 {
		database, collection = fullName[:dot], fullName[dot+1:]
	}
	command := "find"
	if strings.HasSuffix(fullName, ".$cmd") {
		if cmd, coll, db := mongoParseCommand(b); cmd != "" {
			command = cmd
			if coll != "" {
				collection = coll
			}
			if db != "" {
				database = db
			}
		}
	}
	p.mongoStore(key, requestID, mongoPendingFor(command, collection, database, src, dst, raw))
}

// mongoOpReply handles a legacy OP_REPLY. Layout after the header:
// responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + docs.
// The first document, for a command query, carries ok/errmsg; a plain query
// result has neither, so it defaults to success.
func (p *pipeline) mongoOpReply(key string, responseTo int32, body []byte, raw *api.RawView) {
	ok, errmsg := true, ""
	if len(body) >= 20 {
		if doc := body[20:]; len(doc) >= 5 {
			if o, hasOK, msg := mongoParseReply(doc); hasOK || msg != "" {
				ok, errmsg = o, msg
			}
		}
	}
	p.mongoComplete(key, responseTo, ok, errmsg, raw)
}

func mongoPendingFor(command, collection, database string, src, dst api.Endpoint, raw *api.RawView) *mongoPending {
	summary := command
	if collection != "" {
		summary = command + " " + collection
	}
	return &mongoPending{
		command: command, collection: collection, database: database,
		summary: summary, src: src, dst: dst, ts: time.Now(), raw: raw,
	}
}

func (p *pipeline) mongoStore(key string, id int32, pend *mongoPending) {
	p.mu.Lock()
	p.mongo[mongoKey(key, id)] = pend
	p.mu.Unlock()
}

func (p *pipeline) mongoComplete(key string, respTo int32, ok bool, errmsg string, raw *api.RawView) {
	mk := mongoKey(key, respTo)
	p.mu.Lock()
	pend := p.mongo[mk]
	delete(p.mongo, mk)
	p.mu.Unlock()
	if pend == nil {
		return // no matching request (capture started mid-connection)
	}
	status, summary := "success", "ok"
	if !ok || errmsg != "" {
		status = "error"
		summary = errmsg
		if summary == "" {
			summary = "error"
		}
	}
	now := time.Now()
	p.sink.emit(&api.Entry{
		ID:          p.node + "-mongo-" + strconv.FormatUint(p.seq.Add(1), 36),
		Protocol:    api.ProtocolMongo,
		Timestamp:   pend.ts,
		ElapsedMs:   now.Sub(pend.ts).Milliseconds(),
		Node:        p.node,
		NodeIP:      p.nodeIP,
		Source:      pend.src,
		Destination: pend.dst,
		Request: api.Payload{
			Query:   pend.summary,
			Summary: pend.summary,
			Raw:     pend.raw,
			Mongo:   &api.MongoDetail{Command: pend.command, Collection: pend.collection, Database: pend.database},
		},
		Response: api.Payload{
			Summary: summary,
			Raw:     raw,
			Mongo:   &api.MongoDetail{OK: ok, ErrMsg: errmsg},
		},
		Status: status,
	})
}

func mongoKey(connKey string, id int32) string {
	return connKey + "/" + strconv.FormatInt(int64(id), 10)
}

// opMsgBodyDoc returns the section-0 (body) BSON document of an OP_MSG body
// (flagBits(4) + sections). It skips any kind-1 document sequences to find the
// single kind-0 body document, bounds-checked throughout.
func opMsgBodyDoc(body []byte) []byte {
	if len(body) < 4 {
		return nil
	}
	b := body[4:] // skip flagBits
	for len(b) > 0 {
		kind := b[0]
		b = b[1:]
		switch kind {
		case 0: // body: a single BSON document
			if len(b) < 4 {
				return nil
			}
			n := int(int32(binary.LittleEndian.Uint32(b[:4])))
			if n < 5 {
				return nil
			}
			if n > len(b) {
				// The document runs past what readMongoBody materialized
				// (mongoScanBytes). Hand back the prefix instead of dropping the
				// whole message: scanBSON is bounds-checked, and the command name
				// is the document's FIRST key, so a prefix still identifies the
				// operation (only trailing fields like $db are missed). Garbled
				// input takes this path too, but then the prefix yields no
				// parseable element and the caller drops it anyway.
				return b
			}
			return b[:n]
		case 1: // document sequence: size(4, incl itself) + identifier + docs
			if len(b) < 4 {
				return nil
			}
			n := int(int32(binary.LittleEndian.Uint32(b[:4])))
			if n < 4 || n > len(b) {
				return nil
			}
			b = b[n:]
		default:
			return nil
		}
	}
	return nil
}

// mongoParseCommand extracts (command, collection, database) from a command
// document: the first element's key is the command name and, when its value is
// a string, the target collection; "$db" gives the database.
func mongoParseCommand(doc []byte) (command, collection, database string) {
	first := true
	scanBSON(doc, func(key string, typ byte, val []byte) bool {
		if first {
			first = false
			command = key
			if typ == bsonString {
				if s, ok := bsonStringVal(val); ok {
					collection = s
				}
			}
		}
		if key == "$db" && typ == bsonString {
			if s, ok := bsonStringVal(val); ok {
				database = s
			}
		}
		return true
	})
	return
}

// mongoParseReply extracts ok / errmsg from a reply document. hasOK reports
// whether an "ok" field was actually present (so callers can default a legacy
// query result — which has neither — to success).
func mongoParseReply(doc []byte) (ok, hasOK bool, errmsg string) {
	scanBSON(doc, func(key string, typ byte, val []byte) bool {
		switch key {
		case "ok":
			hasOK = true
			switch typ {
			case bsonDouble:
				if d, o := bsonDoubleVal(val); o {
					ok = d != 0
				}
			case bsonInt32:
				if len(val) >= 4 {
					ok = int32(binary.LittleEndian.Uint32(val[:4])) != 0
				}
			case bsonInt64:
				if len(val) >= 8 {
					ok = int64(binary.LittleEndian.Uint64(val[:8])) != 0
				}
			case bsonBool:
				if len(val) >= 1 {
					ok = val[0] != 0
				}
			}
		case "errmsg":
			if typ == bsonString {
				if s, o := bsonStringVal(val); o {
					errmsg = s
				}
			}
		}
		return true
	})
	return
}

// --- minimal bounded BSON scanner ------------------------------------------

// BSON element type bytes we key on.
const (
	bsonDouble = 0x01
	bsonString = 0x02
	bsonBool   = 0x08
	bsonInt32  = 0x10
	bsonInt64  = 0x12
)

// scanBSON walks the top-level elements of a BSON document, invoking visit for
// each until it returns false or the document ends. It never recurses (nested
// documents/arrays are skipped by their declared length) and never reads out of
// bounds — any inconsistency ends the scan, so truncated/garbled input can't
// panic it. Depth is therefore inherently 1; total bytes are bounded by the
// (already capped) input slice.
func scanBSON(doc []byte, visit func(key string, typ byte, val []byte) bool) {
	if len(doc) < 5 {
		return
	}
	total := int(int32(binary.LittleEndian.Uint32(doc[:4])))
	if total < 5 || total > len(doc) {
		total = len(doc)
	}
	b := doc[4:total]
	for len(b) > 0 {
		typ := b[0]
		if typ == 0x00 { // document terminator
			return
		}
		b = b[1:]
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return
		}
		key := string(b[:i])
		b = b[i+1:]
		vlen, ok := bsonValueLen(typ, b)
		if !ok || vlen > len(b) {
			return
		}
		if !visit(key, typ, b[:vlen]) {
			return
		}
		b = b[vlen:]
	}
}

// bsonValueLen returns the byte length of a BSON value of type typ at the start
// of b, and whether it could be safely determined within b. Unknown types
// return ok=false so the scan stops rather than guessing.
func bsonValueLen(typ byte, b []byte) (int, bool) {
	switch typ {
	case 0x0A, 0x06, 0xFF, 0x7F: // null, undefined, min-key, max-key
		return 0, true
	case 0x08: // bool
		return 1, true
	case 0x10: // int32
		return 4, true
	case 0x01, 0x12, 0x09, 0x11: // double, int64, datetime, timestamp
		return 8, true
	case 0x07: // objectId
		return 12, true
	case 0x13: // decimal128
		return 16, true
	case 0x02, 0x0D, 0x0E: // string, javascript, symbol
		if len(b) < 4 {
			return 0, false
		}
		n := int(int32(binary.LittleEndian.Uint32(b[:4])))
		if n < 0 || 4+n > len(b) {
			return 0, false
		}
		return 4 + n, true
	case 0x03, 0x04: // embedded document / array (length includes itself)
		if len(b) < 4 {
			return 0, false
		}
		n := int(int32(binary.LittleEndian.Uint32(b[:4])))
		if n < 5 || n > len(b) {
			return 0, false
		}
		return n, true
	case 0x05: // binary: int32 len + subtype(1) + bytes
		if len(b) < 4 {
			return 0, false
		}
		n := int(int32(binary.LittleEndian.Uint32(b[:4])))
		if n < 0 || 5+n > len(b) {
			return 0, false
		}
		return 5 + n, true
	case 0x0B: // regex: two cstrings
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return 0, false
		}
		j := bytes.IndexByte(b[i+1:], 0)
		if j < 0 {
			return 0, false
		}
		return i + 1 + j + 1, true
	default:
		return 0, false
	}
}

// bsonStringVal decodes a BSON string value (int32 length incl. trailing NUL +
// bytes), dropping the trailing NUL.
func bsonStringVal(val []byte) (string, bool) {
	if len(val) < 4 {
		return "", false
	}
	n := int(int32(binary.LittleEndian.Uint32(val[:4])))
	if n < 1 || 4+n > len(val) {
		return "", false
	}
	return string(val[4 : 4+n-1]), true
}

// bsonDoubleVal decodes a BSON double value.
func bsonDoubleVal(val []byte) (float64, bool) {
	if len(val) < 8 {
		return 0, false
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(val[:8])), true
}
