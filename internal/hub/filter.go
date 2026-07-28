package hub

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pablocolson/k8shark/pkg/api"
)

// Predicate reports whether an entry matches a compiled filter.
type Predicate func(*api.Entry) bool

const (
	// maxFilterLen bounds the raw expression length accepted by CompileFilter.
	// The filter endpoint (?filter=) is reachable unauthenticated, so cap the
	// input up front rather than lexing an arbitrarily large string.
	maxFilterLen = 4096
	// maxFilterDepth bounds parser recursion (nested parens / chained "not") so
	// a pathological expression can't overflow the goroutine stack and crash the
	// hub.
	maxFilterDepth = 64
	// maxInListLen bounds how many literals an "in (...)" list may hold.
	maxInListLen = 64
	// maxRegexLen bounds a "matches" operator's pattern length. RE2 (Go's
	// regexp package) has no catastrophic backtracking, but an unbounded
	// pattern could still compile into an expensive automaton (e.g. deeply
	// nested repetition counts), so bound the source text as cheap defense.
	maxRegexLen = 256
)

// CompileFilter parses an IFL (k8shark filter language) expression into a
// Predicate. IFL is a small but real query language inspired by Kubeshark's
// KFL:
//
//	http.method == "GET" and response.status >= 500
//	protocol == "dns" or dst.namespace == "kube-system"
//	not (src.name contains "canary")
//	dst.ip == "10.0.0.0/8"          # CIDR range containment, not string equality
//	"checkout"                      # bare token = full-text substring match
//
// Supported operators: == != contains matches startswith > < >= <= ; a list
// membership test, field in ("a", "b", "c"); boolean and/or/not with
// parentheses. == and != against a CIDR literal (either IP family) test range
// containment rather than string equality. An empty expression matches
// everything.
func CompileFilter(expr string) (Predicate, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return func(*api.Entry) bool { return true }, nil
	}
	if len(expr) > maxFilterLen {
		return nil, fmt.Errorf("filter too long (%d bytes, max %d)", len(expr), maxFilterLen)
	}
	toks, err := lex(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	pred, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected token %q", p.cur().val)
	}
	return pred, nil
}

// --- lexer -----------------------------------------------------------------

type tokKind int

const (
	tIdent tokKind = iota
	tString
	tNumber
	tOp
	tLParen
	tRParen
	tComma
	tAnd
	tOr
	tNot
)

type token struct {
	kind tokKind
	val  string
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(':
			toks = append(toks, token{tLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")"})
			i++
		case c == ',':
			toks = append(toks, token{tComma, ","})
			i++
		case c == '"' || c == '\'':
			quote := c
			j := i + 1
			var sb strings.Builder
			for j < len(s) && s[j] != quote {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				sb.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string")
			}
			toks = append(toks, token{tString, sb.String()})
			i = j + 1
		case strings.HasPrefix(s[i:], "=="), strings.HasPrefix(s[i:], "!="),
			strings.HasPrefix(s[i:], ">="), strings.HasPrefix(s[i:], "<="):
			toks = append(toks, token{tOp, s[i : i+2]})
			i += 2
		case c == '>' || c == '<':
			toks = append(toks, token{tOp, string(c)})
			i++
		default:
			// identifier / number / keyword run
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\n()=!<>\"',", rune(s[j])) {
				j++
			}
			word := s[i:j]
			if word == "" {
				return nil, fmt.Errorf("unexpected char %q", string(c))
			}
			switch strings.ToLower(word) {
			case "and":
				toks = append(toks, token{tAnd, word})
			case "or":
				toks = append(toks, token{tOr, word})
			case "not":
				toks = append(toks, token{tNot, word})
			case "contains", "matches", "startswith", "in":
				toks = append(toks, token{tOp, strings.ToLower(word)})
			default:
				if _, err := strconv.ParseFloat(word, 64); err == nil {
					toks = append(toks, token{tNumber, word})
				} else {
					toks = append(toks, token{tIdent, word})
				}
			}
			i = j
		}
	}
	return toks, nil
}

// --- parser (recursive descent) --------------------------------------------

type parser struct {
	toks  []token
	pos   int
	depth int // recursion depth guard (nested parens / chained "not")
}

func (p *parser) cur() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{tOp, ""}
}

func (p *parser) parseOr() (Predicate, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tOr {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(e *api.Entry) bool { return l(e) || r(e) }
	}
	return left, nil
}

func (p *parser) parseAnd() (Predicate, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.cur().kind == tAnd {
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(e *api.Entry) bool { return l(e) && r(e) }
	}
	return left, nil
}

func (p *parser) parseUnary() (Predicate, error) {
	if p.cur().kind == tNot {
		p.pos++
		p.depth++
		if p.depth > maxFilterDepth {
			return nil, fmt.Errorf("filter nesting too deep")
		}
		inner, err := p.parseUnary()
		p.depth--
		if err != nil {
			return nil, err
		}
		return func(e *api.Entry) bool { return !inner(e) }, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Predicate, error) {
	t := p.cur()
	switch t.kind {
	case tLParen:
		p.pos++
		p.depth++
		if p.depth > maxFilterDepth {
			return nil, fmt.Errorf("filter nesting too deep")
		}
		inner, err := p.parseOr()
		p.depth--
		if err != nil {
			return nil, err
		}
		if p.cur().kind != tRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.pos++
		return inner, nil
	case tString, tNumber:
		// bare literal -> full-text match
		p.pos++
		needle := strings.ToLower(t.val)
		return func(e *api.Entry) bool { return strings.Contains(fulltext(e), needle) }, nil
	case tIdent:
		// Either "field op value" or a bare token (full-text).
		if p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == tOp {
			return p.parseComparison()
		}
		p.pos++
		needle := strings.ToLower(t.val)
		return func(e *api.Entry) bool { return strings.Contains(fulltext(e), needle) }, nil
	default:
		return nil, fmt.Errorf("unexpected token %q", t.val)
	}
}

func (p *parser) parseComparison() (Predicate, error) {
	field := p.cur().val
	p.pos++
	op := p.cur().val
	p.pos++

	// "in" takes a parenthesized value list instead of a single value token,
	// and (unlike ==/!=) has no negation duality to worry about for the
	// namespace/ns either-side pseudo-field, so it's built directly here
	// rather than falling through to compare()'s single-value shape.
	if op == "in" {
		values, err := p.parseInList()
		if err != nil {
			return nil, err
		}
		match := func(actual string) bool {
			for _, v := range values {
				if strings.EqualFold(actual, v) {
					return true
				}
			}
			return false
		}
		return buildFieldPredicate(field, match)
	}

	if p.pos >= len(p.toks) {
		return nil, fmt.Errorf("expected value after %q", op)
	}
	valTok := p.cur()
	p.pos++
	val := valTok.val

	switch op {
	case "matches":
		if len(val) > maxRegexLen {
			return nil, fmt.Errorf("field %q: pattern too long (%d bytes, max %d)", field, len(val), maxRegexLen)
		}
		re, err := regexp.Compile(val)
		if err != nil {
			return nil, fmt.Errorf("field %q: invalid regex %q: %w", field, val, err)
		}
		return buildFieldPredicate(field, re.MatchString)
	case "startswith":
		// Case-fold just the first len(val) bytes instead of lowercasing the
		// whole field value: `response.body startswith "{"` used to copy an
		// entire 100 KB body to look at one byte, once per entry, per client,
		// per ring slot. EqualFold folds rune by rune over that window, the same
		// rule == already uses. The one behavioural corner is a value whose
		// prefix case-folds to a *different byte length* than the needle (a
		// handful of runes, e.g. "ẞ"/"ß") — no field the dissectors produce
		// carries those, and matching a fixed window is what makes this O(len
		// needle) instead of O(len body).
		return buildFieldPredicate(field, func(actual string) bool {
			return len(actual) >= len(val) && strings.EqualFold(actual[:len(val)], val)
		})
	}

	// namespace/ns matches either side (src or dst) rather than a single
	// struct field, so it can't go through the single-getter path below. == and
	// contains are true if EITHER side matches (inclusion, "show me shop
	// traffic wherever it touches shop"); != is true only if NEITHER side
	// matches (exclusion, "hide kube-system noise") — the useful reading, not
	// the De Morgan-literal "either side differs" (which would be true for
	// nearly every entry). != is therefore built from the "==" matcher and
	// negated as a whole.
	fieldLower := strings.ToLower(field)
	if fieldLower == "namespace" || fieldLower == "ns" {
		matchOp := op
		if op == "!=" {
			matchOp = "=="
		}
		// Compiled once here, not per side and not per entry: this path applies
		// the matcher twice per evaluation, so deriving it from val inside the
		// closure would pay the constant cost twice over.
		match, err := valueMatcher(field, matchOp, val)
		if err != nil {
			return nil, err
		}
		if op == "!=" {
			return func(e *api.Entry) bool {
				return !match(e.Source.Namespace) && !match(e.Destination.Namespace)
			}, nil
		}
		return func(e *api.Entry) bool {
			return match(e.Source.Namespace) || match(e.Destination.Namespace)
		}, nil
	}

	// An unknown field must be a compile error, not a silent match-nothing: a
	// typo like `http.status_code == 500` returning zero entries reads as "no
	// errors" to whoever wrote it. Resolved before the value matcher so a typo'd
	// field reports as such even when the literal is also bad.
	getter := fieldGetter(field)
	if getter == nil {
		return nil, fmt.Errorf("unknown filter field %q (GET /api/fields lists the catalog)", field)
	}
	match, err := valueMatcher(field, op, val)
	if err != nil {
		return nil, err
	}
	return func(e *api.Entry) bool { return match(getter(e)) }, nil
}

// parseInList parses a parenthesized, comma-separated literal list after
// "in": ("prod", "staging") or (500, 502, 503). Values may be quoted strings
// or bare identifiers/numbers.
func (p *parser) parseInList() ([]string, error) {
	if p.cur().kind != tLParen {
		return nil, fmt.Errorf(`expected "(" after "in"`)
	}
	p.pos++
	var values []string
	for {
		t := p.cur()
		switch t.kind {
		case tString, tNumber, tIdent:
			values = append(values, t.val)
			p.pos++
		default:
			return nil, fmt.Errorf(`expected a value in "in (...)" list, got %q`, t.val)
		}
		if len(values) > maxInListLen {
			return nil, fmt.Errorf(`"in (...)" list too long (max %d values)`, maxInListLen)
		}
		if p.cur().kind == tRParen {
			p.pos++
			return values, nil
		}
		if p.cur().kind != tComma {
			return nil, fmt.Errorf(`expected "," or ")" in "in (...)" list, got %q`, p.cur().val)
		}
		p.pos++
	}
}

// buildFieldPredicate resolves field to its value(s) and applies match: the
// namespace/ns either-side pseudo-field checks both endpoints (OR-combined —
// "true if either side satisfies it", the same inclusion reading == and
// contains already use above), any other field its single resolved value.
func buildFieldPredicate(field string, match func(actual string) bool) (Predicate, error) {
	fieldLower := strings.ToLower(field)
	if fieldLower == "namespace" || fieldLower == "ns" {
		return func(e *api.Entry) bool {
			return match(e.Source.Namespace) || match(e.Destination.Namespace)
		}, nil
	}
	getter := fieldGetter(field)
	if getter == nil {
		return nil, fmt.Errorf("unknown filter field %q (GET /api/fields lists the catalog)", field)
	}
	return func(e *api.Entry) bool { return match(getter(e)) }, nil
}

// valueMatcher compiles "<field value> op want" into a closure that tests one
// resolved field value. Everything derivable from want — which is a *constant*
// of the expression — is done here, once, at compile time: the returned closure
// runs per entry × per connected client × per ring slot on every REST scan, so
// a net.ParseCIDR (allocating a *net.ParseError on the normal non-CIDR path)
// or a strconv.ParseFloat of the same literal inside it is pure waste repeated
// millions of times.
//
// want in CIDR form (e.g. "10.0.0.0/8") makes == / != a range-containment test
// against the value as an IP (either family), instead of the literal string
// compare they'd otherwise fall to — no *.ip field's real value is ever itself
// a CIDR literal, so this can't misfire against a legitimate exact-match use.
// Ordering comparisons need a numeric want; anything else is a compile error
// (see below). Everything else compares case-insensitively as a string.
func valueMatcher(field, op, want string) (func(actual string) bool, error) {
	switch op {
	case "==", "!=":
		if _, ipnet, err := net.ParseCIDR(want); err == nil {
			if op == "!=" {
				return func(actual string) bool {
					ip := net.ParseIP(actual)
					return ip == nil || !ipnet.Contains(ip)
				}, nil
			}
			return func(actual string) bool {
				ip := net.ParseIP(actual)
				return ip != nil && ipnet.Contains(ip)
			}, nil
		}
		if op == "!=" {
			return func(actual string) bool { return !strings.EqualFold(actual, want) }, nil
		}
		return func(actual string) bool { return strings.EqualFold(actual, want) }, nil

	case "contains":
		lowWant := strings.ToLower(want)
		return func(actual string) bool {
			// Try the needle against the raw value first: payload text (paths,
			// queries, hostnames) is usually already lowercase, so this hits
			// without allocating the lowercased copy of a potentially large
			// field. A hit here is never a false positive — lowWant is already
			// folded, so any literal occurrence survives ToLower too.
			if strings.Contains(actual, lowWant) {
				return true
			}
			return strings.Contains(strings.ToLower(actual), lowWant)
		}, nil

	case ">", "<", ">=", "<=":
		// A non-numeric literal used to make the whole comparison silently
		// match nothing (`elapsedMs > "abc"` returned zero entries, reading as
		// "no slow traffic"). Same stance as an unknown field name: reject it at
		// compile time so the mistake is visible to whoever typed it.
		wf, err := strconv.ParseFloat(want, 64)
		if err != nil {
			return nil, fmt.Errorf("field %q: operator %q needs a numeric value, got %q", field, op, want)
		}
		switch op {
		case ">":
			return func(actual string) bool {
				af, err := strconv.ParseFloat(actual, 64)
				return err == nil && af > wf
			}, nil
		case "<":
			return func(actual string) bool {
				af, err := strconv.ParseFloat(actual, 64)
				return err == nil && af < wf
			}, nil
		case ">=":
			return func(actual string) bool {
				af, err := strconv.ParseFloat(actual, 64)
				return err == nil && af >= wf
			}, nil
		default: // "<="
			return func(actual string) bool {
				af, err := strconv.ParseFloat(actual, 64)
				return err == nil && af <= wf
			}, nil
		}
	}
	// Unreachable via the lexer (it only ever emits the operators handled above
	// plus in/matches/startswith, which parseComparison peels off first), but an
	// error beats a predicate that silently matches nothing.
	return nil, fmt.Errorf("field %q: unsupported operator %q", field, op)
}

// fieldGetter resolves a dotted field path to an accessor. Unknown fields
// return nil (rejected at filter compile; skipped by the facet index).
func fieldGetter(field string) func(*api.Entry) string {
	lower := strings.ToLower(field)

	// request.header.<name> / response.header.<name>: headers are already
	// captured (Payload.Headers, keys lowercased by flattenHeaders) but had no
	// filter field of their own. Prefix-resolved rather than a fixed switch
	// case since the header name is open-ended; an empty name after the
	// prefix (e.g. bare "request.header.") falls through to the unknown-field
	// error below instead of matching on an empty key.
	if name, ok := strings.CutPrefix(lower, "request.header."); ok && name != "" {
		return func(e *api.Entry) string { return e.Request.Headers[name] }
	}
	if name, ok := strings.CutPrefix(lower, "response.header."); ok && name != "" {
		return func(e *api.Entry) string { return e.Response.Headers[name] }
	}

	switch lower {
	case "namespace", "ns":
		// The real either-side match/exclude logic lives in parseComparison
		// (which intercepts "namespace"/"ns" before ever calling this), so
		// this getter is never used for actual comparisons — it exists only
		// so the facet index has something to sample for tracked-value
		// autocomplete. Falls back to dst so a namespace that's only ever a
		// destination (e.g. one that solely receives traffic) still shows up.
		return func(e *api.Entry) string {
			if e.Source.Namespace != "" {
				return e.Source.Namespace
			}
			return e.Destination.Namespace
		}
	case "protocol":
		return func(e *api.Entry) string { return string(e.Protocol) }
	case "node":
		return func(e *api.Entry) string { return e.Node }
	case "status":
		return func(e *api.Entry) string { return e.Status }
	case "elapsedms", "elapsed", "latency":
		return func(e *api.Entry) string { return strconv.FormatInt(e.ElapsedMs, 10) }
	case "src.ip":
		return func(e *api.Entry) string { return e.Source.IP }
	case "src.port":
		return func(e *api.Entry) string { return strconv.Itoa(e.Source.Port) }
	case "src.name":
		return func(e *api.Entry) string { return e.Source.Name }
	case "src.namespace", "src.ns":
		return func(e *api.Entry) string { return e.Source.Namespace }
	case "src.workload":
		return func(e *api.Entry) string { return e.Source.Workload }
	case "dst.ip":
		return func(e *api.Entry) string { return e.Destination.IP }
	case "dst.port":
		return func(e *api.Entry) string { return strconv.Itoa(e.Destination.Port) }
	case "dst.name":
		return func(e *api.Entry) string { return e.Destination.Name }
	case "dst.namespace", "dst.ns":
		return func(e *api.Entry) string { return e.Destination.Namespace }
	case "dst.workload":
		return func(e *api.Entry) string { return e.Destination.Workload }
	case "http.method", "request.method", "method":
		return func(e *api.Entry) string { return e.Request.Method }
	case "http.path", "request.path", "path":
		return func(e *api.Entry) string { return e.Request.Path }
	case "http.host", "request.host", "host":
		return func(e *api.Entry) string { return e.Request.Host }
	case "http.status", "response.status", "status.code", "statuscode":
		return func(e *api.Entry) string { return strconv.Itoa(e.StatusCode) }
	case "request.body":
		return func(e *api.Entry) string { return e.Request.Body }
	case "response.body":
		return func(e *api.Entry) string { return e.Response.Body }
	case "dns.question", "question":
		return func(e *api.Entry) string { return e.Request.Question }
	case "dns.answer", "answer":
		return func(e *api.Entry) string { return e.Response.Answer }
	case "redis.command", "command":
		return func(e *api.Entry) string { return e.Request.Command }
	case "postgres.query", "query", "sql":
		return func(e *api.Entry) string { return e.Request.Query }
	case "bytes":
		return func(e *api.Entry) string { return strconv.FormatInt(e.Request.Bytes, 10) }
	case "packets":
		return func(e *api.Entry) string { return strconv.FormatInt(e.Request.Packets, 10) }
	case "flags":
		return func(e *api.Entry) string { return e.Request.Flags }
	case "summary":
		return func(e *api.Entry) string { return e.Request.Summary + " " + e.Response.Summary }
	case "trace.id", "traceid":
		// EXT-3: end-to-end correlation id (traceparent trace-id / x-request-id
		// / x-correlation-id) extracted into the top-level Entry.TraceID.
		return func(e *api.Entry) string { return e.TraceID }

	// --- richer sub-object fields (WS3) — all nil-guarded ------------------
	case "http.version":
		return func(e *api.Entry) string {
			if e.Request.HTTP != nil {
				return e.Request.HTTP.Version
			}
			return ""
		}
	case "response.contenttype", "content-type", "contenttype":
		return func(e *api.Entry) string {
			if e.Response.ContentType != "" {
				return e.Response.ContentType
			}
			return e.Request.ContentType
		}
	case "dns.rcode":
		return func(e *api.Entry) string {
			if e.Response.DNS != nil {
				return e.Response.DNS.Rcode
			}
			return ""
		}
	case "dns.type":
		return func(e *api.Entry) string {
			if e.Request.DNS != nil && len(e.Request.DNS.Questions) > 0 {
				return e.Request.DNS.Questions[0].Type
			}
			return ""
		}
	case "redis.db":
		return func(e *api.Entry) string {
			if e.Request.Redis != nil {
				return strconv.Itoa(e.Request.Redis.DBIndex)
			}
			return ""
		}
	case "redis.reply":
		return func(e *api.Entry) string {
			if e.Response.Redis != nil {
				return e.Response.Redis.Reply
			}
			return ""
		}
	case "postgres.error", "pg.code":
		return func(e *api.Entry) string {
			if e.Response.Postgres != nil && e.Response.Postgres.Error != nil {
				return e.Response.Postgres.Error.Code
			}
			return ""
		}
	case "postgres.statement":
		return func(e *api.Entry) string {
			if e.Request.Postgres != nil {
				return e.Request.Postgres.StatementName
			}
			return ""
		}
	case "postgres.txstatus":
		return func(e *api.Entry) string {
			if e.Response.Postgres != nil {
				return e.Response.Postgres.TxStatus
			}
			return ""
		}

	// --- MySQL / MongoDB (DIS-11) -----------------------------------------
	// MySQL SQL text reuses the shared query/sql getter above (Request.Query).
	case "mysql.command":
		return func(e *api.Entry) string {
			if e.Request.MySQL != nil {
				return e.Request.MySQL.Command
			}
			return ""
		}
	case "mysql.error":
		return func(e *api.Entry) string {
			if e.Response.MySQL != nil && e.Response.MySQL.ErrorCode != 0 {
				return strconv.Itoa(e.Response.MySQL.ErrorCode)
			}
			return ""
		}
	case "mongo.collection":
		return func(e *api.Entry) string {
			if e.Request.Mongo != nil {
				return e.Request.Mongo.Collection
			}
			return ""
		}
	case "mongo.command":
		return func(e *api.Entry) string {
			if e.Request.Mongo != nil {
				return e.Request.Mongo.Command
			}
			return ""
		}

	// --- Kafka (DIS-8) ----------------------------------------------------
	case "kafka.topic":
		return func(e *api.Entry) string {
			if e.Request.Kafka != nil {
				return e.Request.Kafka.Topic
			}
			return ""
		}
	case "kafka.apikey":
		return func(e *api.Entry) string {
			if e.Request.Kafka != nil {
				return e.Request.Kafka.APIKey
			}
			return ""
		}
	case "l4.ttl":
		return func(e *api.Entry) string { return l4Int(e, func(l *api.L4Info) int { return l.TTL }) }
	case "l4.retransmits":
		return func(e *api.Entry) string { return l4Int(e, func(l *api.L4Info) int { return l.Retransmits }) }
	case "l4.window":
		return func(e *api.Entry) string { return l4Int(e, func(l *api.L4Info) int { return l.Window }) }
	case "l4.mss":
		return func(e *api.Entry) string { return l4Int(e, func(l *api.L4Info) int { return l.MSS }) }
	case "l4.rttms":
		return func(e *api.Entry) string {
			if e.L4 != nil {
				return strconv.FormatFloat(e.L4.RTTMs, 'f', -1, 64)
			}
			return ""
		}
	case "l4.durationms":
		return func(e *api.Entry) string {
			if e.L4 != nil {
				return strconv.FormatInt(e.L4.DurationMs, 10)
			}
			return ""
		}
	case "l4.clientbytes":
		return func(e *api.Entry) string {
			if e.L4 != nil {
				return strconv.FormatInt(e.L4.ClientBytes, 10)
			}
			return ""
		}
	case "l4.serverbytes":
		return func(e *api.Entry) string {
			if e.L4 != nil {
				return strconv.FormatInt(e.L4.ServerBytes, 10)
			}
			return ""
		}
	case "tls.sni":
		return func(e *api.Entry) string {
			if e.L4 != nil && e.L4.TLS != nil {
				return e.L4.TLS.SNI
			}
			return ""
		}

	// --- AMQP (WS5) -------------------------------------------------------
	case "amqp.exchange", "exchange":
		return func(e *api.Entry) string { return e.Request.Exchange }
	case "amqp.routingkey", "amqp.routing-key", "routingkey", "routing-key":
		return func(e *api.Entry) string { return e.Request.RoutingKey }
	case "amqp.queue", "queue":
		return func(e *api.Entry) string { return e.Request.Queue }
	case "amqp.deliverytag", "deliverytag":
		return func(e *api.Entry) string { return strconv.FormatUint(e.Request.DeliveryTag, 10) }
	case "amqp.correlationid", "amqp.correlation-id":
		return func(e *api.Entry) string { return e.Request.CorrelationID }
	case "amqp.replyto", "amqp.reply-to":
		return func(e *api.Entry) string { return e.Request.ReplyTo }
	case "amqp.class":
		return func(e *api.Entry) string { return e.Request.Class }

	// --- WebSocket (DIS-6) ------------------------------------------------
	case "ws.opcode":
		return func(e *api.Entry) string { return e.Request.WSOpcode }
	case "amqp.method":
		// Method is shared with HTTP; scope this to AMQP so the facet/filter
		// isn't polluted by HTTP verbs.
		return func(e *api.Entry) string {
			if e.Protocol == api.ProtocolAMQP {
				return e.Request.Method
			}
			return ""
		}

	// --- previously display-only fields, now filterable too ----------------
	case "redis.pipelinedepth":
		return func(e *api.Entry) string {
			if e.Request.Redis != nil {
				return strconv.Itoa(e.Request.Redis.PipelineDepth)
			}
			return ""
		}
	case "postgres.portal":
		return func(e *api.Entry) string {
			if e.Request.Postgres != nil {
				return e.Request.Postgres.Portal
			}
			return ""
		}
	case "dns.authoritative":
		return func(e *api.Entry) string {
			if e.Response.DNS != nil {
				return strconv.FormatBool(e.Response.DNS.Authoritative)
			}
			return ""
		}
	case "dns.recursionavailable", "dns.recursionavl":
		return func(e *api.Entry) string {
			if e.Response.DNS != nil {
				return strconv.FormatBool(e.Response.DNS.RecursionAvl)
			}
			return ""
		}
	case "request.size":
		return func(e *api.Entry) string { return strconv.Itoa(e.Request.Size) }
	case "response.size", "size":
		return func(e *api.Entry) string { return strconv.Itoa(e.Response.Size) }
	case "postgres.rowcount", "rowcount":
		return func(e *api.Entry) string { return strconv.Itoa(e.Response.RowCount) }
	case "http.ttfbms":
		return func(e *api.Entry) string {
			if e.Response.HTTP != nil {
				return strconv.FormatInt(e.Response.HTTP.TTFBMs, 10)
			}
			return ""
		}

	// --- remaining L4Info fields (previously view-only) ---------------------
	case "l4.srcmac":
		return func(e *api.Entry) string { return l4Str(e, func(l *api.L4Info) string { return l.SrcMAC }) }
	case "l4.dstmac":
		return func(e *api.Entry) string { return l4Str(e, func(l *api.L4Info) string { return l.DstMAC }) }
	case "l4.ipversion":
		return func(e *api.Entry) string { return l4Int(e, func(l *api.L4Info) int { return l.IPVersion }) }
	case "l4.ipflags":
		return func(e *api.Entry) string { return l4Str(e, func(l *api.L4Info) string { return l.IPFlags }) }
	case "l4.clienttcpflags":
		return func(e *api.Entry) string { return l4Str(e, func(l *api.L4Info) string { return l.ClientTCPFlags }) }
	case "l4.servertcpflags":
		return func(e *api.Entry) string { return l4Str(e, func(l *api.L4Info) string { return l.ServerTCPFlags }) }
	case "l4.seqstart":
		return func(e *api.Entry) string {
			if e.L4 == nil {
				return ""
			}
			return strconv.FormatUint(uint64(e.L4.SeqStart), 10)
		}
	case "l4.ackstart":
		return func(e *api.Entry) string {
			if e.L4 == nil {
				return ""
			}
			return strconv.FormatUint(uint64(e.L4.AckStart), 10)
		}
	case "l4.clientpackets":
		return func(e *api.Entry) string {
			if e.L4 == nil {
				return ""
			}
			return strconv.FormatInt(e.L4.ClientPackets, 10)
		}
	case "l4.serverpackets":
		return func(e *api.Entry) string {
			if e.L4 == nil {
				return ""
			}
			return strconv.FormatInt(e.L4.ServerPackets, 10)
		}

	default:
		return nil
	}
}

// l4Int reads an int field off e.L4, returning "" (not "0") when L4 is absent so
// numeric comparisons don't spuriously match on missing data.
func l4Int(e *api.Entry, get func(*api.L4Info) int) string {
	if e.L4 == nil {
		return ""
	}
	return strconv.Itoa(get(e.L4))
}

// l4Str reads a string field off e.L4, returning "" when L4 is absent.
func l4Str(e *api.Entry, get func(*api.L4Info) string) string {
	if e.L4 == nil {
		return ""
	}
	return get(e.L4)
}

// fulltext builds a lowercase haystack of an entry's salient fields for bare
// full-text matching.
//
// Each part is lowercased *while* it is written rather than by a
// strings.ToLower(sb.String()) at the end: the trailing form materialised the
// haystack twice (once assembled, once folded), so a bare-token filter paid two
// allocations and a full extra copy per entry, per client, per ring slot.
func fulltext(e *api.Entry) string {
	var sb strings.Builder
	writeLower(&sb, string(e.Protocol))
	sb.WriteByte(' ')
	writeLower(&sb, e.Node)
	sb.WriteByte(' ')
	writeLower(&sb, e.Source.IP)
	sb.WriteByte(' ')
	writeLower(&sb, e.Source.Name)
	sb.WriteByte(' ')
	writeLower(&sb, e.Destination.IP)
	sb.WriteByte(' ')
	writeLower(&sb, e.Destination.Name)
	sb.WriteByte(' ')
	writeLower(&sb, e.Request.Summary)
	sb.WriteByte(' ')
	writeLower(&sb, e.Request.Method)
	sb.WriteByte(' ')
	writeLower(&sb, e.Request.Path)
	sb.WriteByte(' ')
	writeLower(&sb, e.Request.Host)
	sb.WriteByte(' ')
	writeLower(&sb, e.Request.Question)
	sb.WriteByte(' ')
	writeLower(&sb, e.Request.Command)
	sb.WriteByte(' ')
	writeLower(&sb, e.Request.Query)
	sb.WriteByte(' ')
	writeLower(&sb, e.Response.Summary)
	// Richer sub-object text (WS3), nil-guarded.
	if e.Request.HTTP != nil && e.Request.HTTP.ContentType != "" {
		sb.WriteByte(' ')
		writeLower(&sb, e.Request.HTTP.ContentType)
	}
	if e.Response.DNS != nil {
		for _, a := range e.Response.DNS.Answers {
			sb.WriteByte(' ')
			writeLower(&sb, a.Data)
		}
	}
	if e.Request.Postgres != nil && e.Request.Postgres.StatementName != "" {
		sb.WriteByte(' ')
		writeLower(&sb, e.Request.Postgres.StatementName)
	}
	if e.Request.Exchange != "" || e.Request.RoutingKey != "" || e.Request.Queue != "" {
		sb.WriteByte(' ')
		writeLower(&sb, e.Request.Exchange)
		sb.WriteByte(' ')
		writeLower(&sb, e.Request.RoutingKey)
		sb.WriteByte(' ')
		writeLower(&sb, e.Request.Queue)
	}
	if e.L4 != nil && e.L4.TLS != nil && e.L4.TLS.SNI != "" {
		sb.WriteByte(' ')
		writeLower(&sb, e.L4.TLS.SNI)
	}
	if e.Request.Kafka != nil && e.Request.Kafka.Topic != "" {
		sb.WriteByte(' ')
		writeLower(&sb, e.Request.Kafka.Topic)
	}
	return sb.String()
}

// writeLower appends s to sb lowercased, producing exactly what
// strings.ToLower(s) would — ASCII is folded byte-wise in place, and the first
// non-ASCII byte hands the remainder to strings.ToLower, whose Unicode folding
// can change the encoded length (so a byte-wise loop cannot handle it).
func writeLower(sb *strings.Builder, s string) {
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= utf8.RuneSelf:
			sb.WriteString(s[start:i])
			sb.WriteString(strings.ToLower(s[i:]))
			return
		case c >= 'A' && c <= 'Z':
			sb.WriteString(s[start:i])
			sb.WriteByte(c + ('a' - 'A'))
			start = i + 1
		}
	}
	sb.WriteString(s[start:])
}
