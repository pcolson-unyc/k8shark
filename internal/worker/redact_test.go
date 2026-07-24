package worker

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

// Redaction scrubs credential-bearing header values while keeping the keys
// (so their presence stays observable) and leaving everything else intact.
func TestFlattenHeadersRedaction(t *testing.T) {
	h := http.Header{
		"Authorization": {"Bearer abc123"},
		"Cookie":        {"session=deadbeef"},
		"X-Api-Key":     {"k-42"},
		"Content-Type":  {"application/json"},
	}

	p := newPipeline(newSink("", "", "n", discardLogger()), "n", "1.2.3.4", discardLogger())
	p.redactHeaders = true
	out := p.flattenHeaders(h)
	for _, k := range []string{"authorization", "cookie", "x-api-key"} {
		if out[k] != redactedValue {
			t.Errorf("%s = %q, want %q", k, out[k], redactedValue)
		}
	}
	if out["content-type"] != "application/json" {
		t.Errorf("content-type = %q, want the original value", out["content-type"])
	}

	// Redaction off: values pass through untouched.
	p.redactHeaders = false
	out = p.flattenHeaders(h)
	if out["authorization"] != "Bearer abc123" {
		t.Errorf("with redaction off, authorization = %q, want the original", out["authorization"])
	}
}

// Query param redaction scrubs sensitive values (name kept) both in the
// parsed HTTP.Query map and in Path/Summary's raw query string — the two are
// separate code paths (parseQuery vs redactedRequestURI) and both leaked the
// value before this.
func TestQueryParamRedaction(t *testing.T) {
	u, err := url.Parse("/login?user=alice&api_key=sk-secret&next=/home")
	if err != nil {
		t.Fatal(err)
	}

	q := parseQuery(u, true)
	if q["api_key"] != redactedValue {
		t.Errorf("api_key = %q, want %q", q["api_key"], redactedValue)
	}
	if q["user"] != "alice" || q["next"] != "/home" {
		t.Errorf("non-sensitive params altered: %+v", q)
	}

	uri := redactedRequestURI(u, true)
	if want := "/login?api_key=%5BREDACTED%5D&next=%2Fhome&user=alice"; uri != want {
		t.Errorf("redactedRequestURI = %q, want %q", uri, want)
	}

	// Redaction off: original RequestURI, byte for byte.
	if got, want := redactedRequestURI(u, false), u.RequestURI(); got != want {
		t.Errorf("redaction off: redactedRequestURI = %q, want %q", got, want)
	}

	// Nothing sensitive present: the original RequestURI is returned
	// untouched rather than re-encoded (key order/escaping preserved).
	plain, _ := url.Parse("/search?q=a+b&sort=desc")
	if got, want := redactedRequestURI(plain, true), plain.RequestURI(); got != want {
		t.Errorf("no sensitive params: redactedRequestURI = %q, want unchanged %q", got, want)
	}
}

// Redis AUTH/HELLO/CONFIG SET requirepass carry credentials as plain command
// arguments (there's no separate "value" field like an HTTP header) —
// redactSensitiveRedisArgs must scrub exactly the credential positions and
// leave everything else (including non-matching commands) alone.
func TestRedactSensitiveRedisArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
		ok   bool
	}{
		{"AUTH password", []string{"AUTH", "hunter2"}, []string{"AUTH", redactedValue}, true},
		{"AUTH user+password (ACL form)", []string{"AUTH", "alice", "hunter2"}, []string{"AUTH", redactedValue, redactedValue}, true},
		{"HELLO with AUTH clause", []string{"HELLO", "3", "AUTH", "alice", "hunter2"}, []string{"HELLO", "3", "AUTH", redactedValue, redactedValue}, true},
		{"HELLO without AUTH", []string{"HELLO", "3"}, []string{"HELLO", "3"}, false},
		{"CONFIG SET requirepass", []string{"CONFIG", "SET", "requirepass", "newpass"}, []string{"CONFIG", "SET", "requirepass", redactedValue}, true},
		{"CONFIG SET masterauth", []string{"CONFIG", "SET", "masterauth", "newpass"}, []string{"CONFIG", "SET", "masterauth", redactedValue}, true},
		{"CONFIG GET requirepass (not a credential write)", []string{"CONFIG", "GET", "requirepass"}, []string{"CONFIG", "GET", "requirepass"}, false},
		{"unrelated command", []string{"GET", "foo"}, []string{"GET", "foo"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := redactSensitiveRedisArgs(c.args)
			if ok != c.ok {
				t.Errorf("ok = %v, want %v", ok, c.ok)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("args = %v, want %v", got, c.want)
			}
		})
	}
}

// End-to-end through consumeRedis: Command/Summary/RedisDetail.Args must all
// reflect the redacted form when redaction is on, and the original when it's
// off (mirrors TestFlattenHeadersRedaction's shape for HTTP).
func TestConsumeRedisRedactsAuth(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	p.redactHeaders = true
	rNet, rTr, sNet, sTr := flows(40001, redisPort)

	req := "*2\r\n$4\r\nAUTH\r\n$7\r\nhunter2\r\n"
	resp := "+OK\r\n"
	p.consumeRedis(rNet, rTr, strings.NewReader(req), true, api.ProtocolRedis)
	p.consumeRedis(sNet, sTr, strings.NewReader(resp), false, api.ProtocolRedis)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	want := "AUTH " + redactedValue
	if got[0].Request.Command != want {
		t.Errorf("Command = %q, want %q", got[0].Request.Command, want)
	}
	if args := got[0].Request.Redis.Args; !reflect.DeepEqual(args, []string{"AUTH", redactedValue}) {
		t.Errorf("Redis.Args = %v, want [AUTH %s]", args, redactedValue)
	}

	// Redaction off: the password passes through untouched.
	p.redactHeaders = false
	rNet, rTr, sNet, sTr = flows(40002, redisPort)
	p.consumeRedis(rNet, rTr, strings.NewReader(req), true, api.ProtocolRedis)
	p.consumeRedis(sNet, sTr, strings.NewReader(resp), false, api.ProtocolRedis)
	got = drain(s)
	if len(got) != 1 || got[0].Request.Command != "AUTH hunter2" {
		t.Fatalf("with redaction off, got %+v, want Command \"AUTH hunter2\"", got)
	}
}

// Postgres Bind params carry no name at the wire level (positional only), so
// redactPGParams is all-or-nothing: every value becomes [REDACTED] while the
// count (a real debugging signal — "this call bound 2 params") is preserved.
func TestConsumePostgresRedactsBindParams(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	p.redactPGParams = true
	rNet, rTr, sNet, sTr := flows(40031, pgPort)

	var req []byte
	req = append(req, pgStartup()...)
	req = append(req, pgMsg('P', []byte("s1\x00SELECT * FROM users WHERE email=$1 AND password=$2\x00\x00\x00"))...)
	req = append(req, pgMsg('B', pgBindPayload("", "s1", []string{"alice@example.com", "hunter2"}))...)
	req = append(req, pgMsg('E', []byte("\x00\x00\x00\x00\x00"))...)
	resp := pgMsg('C', []byte("SELECT 1\x00"))

	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)

	got := drain(s)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	params := got[0].Request.Postgres.Params
	if want := []string{redactedValue, redactedValue}; !reflect.DeepEqual(params, want) {
		t.Errorf("params = %v, want %v (count preserved, values redacted)", params, want)
	}

	// Redaction off: values pass through untouched.
	p.redactPGParams = false
	rNet, rTr, sNet, sTr = flows(40032, pgPort)
	req = nil
	req = append(req, pgStartup()...)
	req = append(req, pgMsg('P', []byte("s1\x00SELECT * FROM users WHERE email=$1\x00\x00\x00"))...)
	req = append(req, pgMsg('B', pgBindPayload("", "s1", []string{"alice@example.com"}))...)
	req = append(req, pgMsg('E', []byte("\x00\x00\x00\x00\x00"))...)
	p.consumePostgres(rNet, rTr, strings.NewReader(string(req)), true)
	p.consumePostgres(sNet, sTr, strings.NewReader(string(resp)), false)
	got = drain(s)
	if len(got) != 1 || len(got[0].Request.Postgres.Params) != 1 || got[0].Request.Postgres.Params[0] != "alice@example.com" {
		t.Fatalf("with redaction off, got params %v, want [alice@example.com]", got[0].Request.Postgres.Params)
	}
}
