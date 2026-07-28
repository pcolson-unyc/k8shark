package worker

import "unicode/utf8"

// Retention caps shared by the L7 dissectors.
//
// Every dissector already bounds how much of a frame it MATERIALIZES (the
// per-protocol scan caps in dissect_*.go: pgMaxPayload, mysqlMaxPayload,
// kafkaScanBytes, mongoScanBytes, amqpMaxCapture, maxRESPCapture). Those bound
// a transient buffer that is garbage a few microseconds later. The caps below
// bound what is RETAINED — the strings that end up inside an api.Entry and stay
// alive for the whole lifetime of the hub's ring buffer, multiplied by its
// depth. Retention therefore needs a far tighter bound than materialization,
// which is why these are separate numbers and not the scan caps.
const (
	// queryCap bounds the SQL / command text kept in Payload.Query (Postgres,
	// MySQL) and in Payload.Command (Redis). 8 KiB is well past any
	// hand-written statement and past the ORM-generated ones too (a wide
	// INSERT ... VALUES with a few hundred columns lands around 4 KiB), so
	// `postgres.query contains ...` keeps matching what operators actually
	// search for — while a machine-generated multi-MiB statement (a bulk
	// INSERT, a giant IN list) now costs 8 KiB per entry instead of up to
	// pgMaxPayload (4 MiB) / mysqlMaxPayload (4 MiB).
	//
	// Deliberately NOT config.DefaultBodyCaptureBytes: the body cap is
	// operator-tunable (--body-bytes) and governs opaque payloads, whereas the
	// query text is the primary FILTERABLE field of a SQL entry. Reusing
	// bodyCap would make lowering the body capture silently degrade
	// `postgres.query`/`mysql`/`redis.command` filtering, which is not a
	// trade-off an operator tuning body capture is asking for.
	queryCap = 8192

	// redisMaxArgs bounds how many arguments of a RESP command are kept in
	// RedisDetail.Args. Individual element VALUES are already bounded at
	// redisMaxValueDisplay (256 B) by redisDisplay; the unbounded dimension is
	// the element COUNT — parseRESP accepts up to maxRESPElements (1<<20)
	// elements per array, so one MSET/HSET/DEL could retain hundreds of MiB of
	// rendered strings. 64 keeps every realistic command whole (an MSET of a
	// few dozen keys, an EVAL with its KEYS/ARGV) and the dropped tail is
	// replaced by a synthetic "… (N more)" element so the loss is visible in
	// the detail pane instead of the list just ending short.
	redisMaxArgs = 64
)

// capQuery bounds retained query/command text at queryCap, reporting whether it
// was cut so the caller can set Payload.Truncated. The cut backs off to a rune
// boundary: a mid-rune cut would serialize as U+FFFD and break a `contains`
// filter on the last visible word.
func capQuery(s string) (string, bool) {
	if len(s) <= queryCap {
		return s, false
	}
	cut := queryCap
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…", true
}

// capQueryBytes is capQuery over a not-yet-stringified payload. It converts at
// most queryCap+utf8.UTFMax bytes (the slack lets capQuery back off to a rune
// boundary), so a multi-MiB COM_QUERY payload is never copied into a string
// just to be thrown away.
func capQueryBytes(b []byte) (string, bool) {
	if len(b) <= queryCap {
		return string(b), false
	}
	return capQuery(string(b[:min(len(b), queryCap+utf8.UTFMax)]))
}
