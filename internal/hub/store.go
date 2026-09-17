package hub

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

// store is a bounded, thread-safe ring buffer of the most recent entries plus
// rolling aggregate counters. It is the hub's only source of truth for the REST
// API and for replaying history to newly-connected front clients.
type store struct {
	mu            sync.RWMutex
	buf           []*api.Entry
	capacity      int
	next          int // write cursor into buf
	live          int
	byteBudget    int64
	retainedBytes int64

	// raw mirrors buf slot-for-slot with each entry's JSON, marshaled once in
	// add (an entry is immutable after add — enrichment happens before). It
	// feeds the WS fan-out and history replay so neither ever re-marshals.
	raw [][]byte

	// byID indexes live buffer entries for O(1) get(). Kept in sync with buf:
	// an entry is added on write and removed when its slot is overwritten.
	byID map[string]*api.Entry

	// total is the lifetime ingest count and the source of every entry's Seq.
	// It is atomic rather than mu-guarded so add() can assign Seq — and
	// therefore marshal the entry — *before* taking the ring lock. See add.
	// Readers that also read the mu-guarded aggregates must still load it
	// under the lock so the two agree; see stats().
	total atomic.Int64

	byProtocol map[string]int64
	byStatus   map[string]int64

	// rate holds the per-second ingest tallies behind Stats.EntriesPerSec and
	// the trailing 1m/5m windows, advanced lazily in add (see observeRate).
	// Guarded by mu.
	rate [rateWindowSeconds]rateBucket

	// now is the clock, injectable so tests can drive the rate windows without
	// sleeping. Defaults to time.Now.
	now func() time.Time

	// facets tracks observed field values for IFL autocomplete. It owns its
	// own mutex, fully decoupled from s.mu.
	facets *facetIndex
}

// rateWindowSeconds is the span the per-second buckets cover: 5 minutes, the
// widest window stats() reports (Last5m).
const rateWindowSeconds = 300

// liveRateSeconds is the trailing window behind Stats.EntriesPerSec.
const liveRateSeconds = 5

// rateBucket tallies one wall-clock second of ingest. sec is the unix second
// the bucket currently represents; a bucket whose sec doesn't match the second
// being written belongs to a window that has already scrolled past, so it is
// reset in place — that lazy advance is what keeps the window bounded without
// a sweeper goroutine or a slice whose head is forever re-sliced.
type rateBucket struct {
	sec      int64
	entries  int64
	errors   int64
	warnings int64
}

// resultPrealloc caps the up-front allocation of a query result slice. Most
// callers pass limit == capacity (the whole ring) while matching only a
// fraction of it, so sizing the result at limit would burn ~80KB per
// /api/summary poll for nothing; append grows past 512 cheaply in the rare
// case a query really does return more.
const resultPrealloc = 512

func newStore(capacity int, budgets ...int64) *store {
	budget := int64(64 << 20)
	if len(budgets) > 0 && budgets[0] > 0 {
		budget = budgets[0]
	}
	return &store{
		buf:        make([]*api.Entry, capacity),
		raw:        make([][]byte, capacity),
		capacity:   capacity,
		byteBudget: budget,
		byID:       map[string]*api.Entry{},
		byProtocol: map[string]int64{},
		byStatus:   map[string]int64{},
		now:        time.Now,
		facets:     newFacetIndex(),
	}
}

// add records an entry, updates aggregates, and returns the entry's cached
// JSON (marshaled exactly once, after Seq is assigned; nil on a marshal
// failure). The bytes are immutable — callers hand them straight to the WS
// fan-out.
func (s *store) add(e *api.Entry) []byte {
	// Seq comes from an atomic counter and the entry is marshaled *outside*
	// s.mu: reflection-based marshaling dominated the old critical section
	// (~2.4us of 3.3us), and this lock is the funnel every worker
	// connection's ingest goroutine passes through. The entry isn't published
	// anywhere until the Lock() below, so no reader can observe it half-built.
	//
	// The one thing this gives up is that Seq order and ring order are no
	// longer assigned atomically together: two concurrent adds can take seq
	// N and N+1 and then land in the ring in the opposite order. Nothing
	// depends on the two agreeing — recentBeforeSeq compares Seq per entry
	// rather than trusting position, and the ring has only ever been in
	// *arrival* order, which already only approximates capture time.
	e.Seq = s.total.Add(1)
	raw, _ := json.Marshal(e)

	now := s.now()

	s.mu.Lock()
	if int64(len(raw)) > s.byteBudget {
		s.byProtocol[string(e.Protocol)]++
		if e.Status != "" {
			s.byStatus[e.Status]++
		}
		s.observeRate(e, now)
		s.mu.Unlock()
		s.facets.observe(e)
		return raw
	}

	// Invariant: the slot index is chosen and *both* mirrors (buf and raw) are
	// written within this single lock hold, so buf[i] and raw[i] can never
	// come from two different adds. Readers walking the ring therefore always
	// see an entry together with its own JSON — which is what lets the
	// snapshot helpers below copy the pair out and filter off-lock.
	if old := s.buf[s.next]; old != nil {
		// Evict the entry currently in this slot from the id index before
		// overwriting it (guarding against a same-id re-add having already
		// replaced the mapping).
		if s.byID[old.ID] == old {
			delete(s.byID, old.ID)
		}
		s.retainedBytes -= int64(len(s.raw[s.next]))
	} else {
		s.live++
	}
	s.buf[s.next] = e
	s.raw[s.next] = raw
	s.retainedBytes += int64(len(raw))
	s.byID[e.ID] = e

	s.next = (s.next + 1) % s.capacity
	for s.retainedBytes > s.byteBudget && s.live > 0 {
		oldest := (s.next - s.live + s.capacity) % s.capacity
		old := s.buf[oldest]
		if old != nil && s.byID[old.ID] == old {
			delete(s.byID, old.ID)
		}
		s.retainedBytes -= int64(len(s.raw[oldest]))
		s.buf[oldest] = nil
		s.raw[oldest] = nil
		s.live--
	}

	s.byProtocol[string(e.Protocol)]++
	if e.Status != "" {
		s.byStatus[e.Status]++
	}
	s.observeRate(e, now)

	s.mu.Unlock()

	// Facet observation uses its own mutex and must run outside store's
	// critical section, so it never extends store.mu's hold time.
	s.facets.observe(e)
	return raw
}

// observeRate folds e into the per-second buckets. Caller holds the lock.
//
// Bucketing is by the entry's own timestamp — as the old full-ring walk was —
// clamped to now: an entry older than the whole window contributes to nothing,
// and one dated in the future (clock skew between nodes) is counted as current
// rather than being allowed to reset a bucket the window still needs.
func (s *store) observeRate(e *api.Entry, now time.Time) {
	nowSec := now.Unix()
	sec := e.Timestamp.Unix()
	if sec > nowSec {
		sec = nowSec
	}
	if nowSec-sec >= rateWindowSeconds {
		return
	}
	// sec is now within rateWindowSeconds of now, so it is safely positive and
	// the modulo needs no negative-value guard.
	b := &s.rate[sec%rateWindowSeconds]
	if b.sec != sec {
		*b = rateBucket{sec: sec}
	}
	b.entries++
	switch e.Status {
	case "error":
		b.errors++
	case "warning":
		b.warnings++
	}
}

// liveLen is how many ring slots currently hold an entry. Caller holds at
// least RLock.
func (s *store) liveLen() int {
	return s.live
}

// snapshotEntries copies up to depth of the live ring's entry pointers,
// newest first, under RLock.
//
// Callers evaluate their match predicate on the returned slice *after* the
// lock is released. That is safe because an entry is immutable once add() has
// published it (see the raw field's comment — enrichment happens before add),
// so a pointer copied out of the ring keeps describing the same entry even
// after its slot has been recycled by a later add. The trade is deliberate:
// running an IFL predicate over a full ring costs milliseconds and megabytes
// of garbage, copying the same number of pointers costs tens of microseconds,
// and only the copy needs to hold the lock every ingest goroutine contends on.
func (s *store) snapshotEntries(depth int) []*api.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := min(depth, s.liveLen())
	if n < 0 {
		n = 0
	}
	out := make([]*api.Entry, 0, n)
	for i := 0; i < n; i++ {
		if e := s.buf[(s.next-1-i+s.capacity)%s.capacity]; e != nil {
			out = append(out, e)
		}
	}
	return out
}

// snapshotRaw is snapshotEntries plus each entry's cached JSON, as parallel
// slices. Slots whose JSON is missing (a marshal failure in add) are skipped
// entirely so the two slices always line up. See add's invariant for why an
// entry and the raw bytes taken from the same slot always belong together.
func (s *store) snapshotRaw(depth int) ([]*api.Entry, [][]byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := min(depth, s.liveLen())
	if n < 0 {
		n = 0
	}
	entries := make([]*api.Entry, 0, n)
	raws := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		idx := (s.next - 1 - i + s.capacity) % s.capacity
		e, r := s.buf[idx], s.raw[idx]
		if e == nil || r == nil {
			continue
		}
		entries = append(entries, e)
		raws = append(raws, r)
	}
	return entries, raws
}

// scanDepth is how far into the ring a limit-bounded query has to look: with
// no predicate the newest limit entries *are* the answer, so the snapshot can
// stop there; with one, any entry in the ring might match.
func (s *store) scanDepth(limit int, match func(*api.Entry) bool) int {
	if match == nil {
		return limit
	}
	return s.capacity
}

// page walks a newest-first snapshot and returns the indices of up to limit
// entries that satisfy the query.
//
// Whether each cursor applies is carried by its own bool rather than inferred
// from the value being non-zero, because for both cursors the zero value is a
// *legal* cursor, not an absent one: before_seq=0 means "everything strictly
// older than seq 0", i.e. nothing (Seq is 1-indexed — see add), and before=""
// means "older than an anchor that isn't in the ring", i.e. also nothing. An
// `if beforeSeq != 0` style guard silently turns both of those into "no
// constraint at all" and hands the caller the newest full page instead — which
// makes a client paging backwards past the start of the buffer wrap to the head
// and loop forever. useAnchor/useSeq keep the sentinel out of the value space
// so that inversion cannot come back.
//
// When useAnchor is set, everything up to and including anchorID is skipped
// (and nothing is yielded when it isn't present — see recentBefore); when
// useSeq is set, only entries with a strictly smaller Seq than beforeSeq are
// kept; match, when non-nil, is the IFL predicate, evaluated here — off the
// store lock — for the reason given on snapshotEntries.
//
// Indices (rather than entries) are returned so the struct-returning and
// cached-JSON variants of each query share one implementation and can never
// disagree about what a page contains.
func page(entries []*api.Entry, useAnchor bool, anchorID string, useSeq bool, beforeSeq int64, limit int, match func(*api.Entry) bool) []int {
	out := make([]int, 0, min(limit, resultPrealloc))
	skipping := useAnchor
	for i, e := range entries {
		if skipping {
			if e.ID == anchorID {
				skipping = false
			}
			continue
		}
		if useSeq && e.Seq >= beforeSeq {
			continue
		}
		if match != nil && !match(e) {
			continue
		}
		out = append(out, i)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// pick materialises page's indices as entries.
func pick(entries []*api.Entry, idx []int) []*api.Entry {
	out := make([]*api.Entry, len(idx))
	for i, j := range idx {
		out[i] = entries[j]
	}
	return out
}

// pickRaw materialises page's indices as the entries' cached JSON.
func pickRaw(raws [][]byte, idx []int) [][]byte {
	out := make([][]byte, len(idx))
	for i, j := range idx {
		out[i] = raws[j]
	}
	return out
}

// recent returns up to limit of the most recent entries, newest first, that
// satisfy match. A nil match accepts everything.
func (s *store) recent(limit int, match func(*api.Entry) bool) []*api.Entry {
	cand := s.snapshotEntries(s.scanDepth(limit, match))
	if match == nil {
		return cand // the snapshot is already capped at limit
	}
	return pick(cand, page(cand, false, "", false, 0, limit, match))
}

// recentRaw returns the cached JSON of up to limit of the most recent entries
// matching match, newest first — the zero-marshal path behind history replay
// and the /api/entries REST pages.
func (s *store) recentRaw(limit int, match func(*api.Entry) bool) [][]byte {
	entries, raws := s.snapshotRaw(s.scanDepth(limit, match))
	if match == nil {
		return raws // the snapshot is already capped at limit
	}
	return pickRaw(raws, page(entries, false, "", false, 0, limit, match))
}

// recentBefore returns up to limit entries strictly older than beforeID,
// newest first, satisfying match — the walk-back that powers "load older"
// pagination beyond what the WS replay/live buffer already surfaced. If
// beforeID isn't found in the ring buffer (aged out), it returns no results
// rather than guessing, since there's no reliable anchor for "older than".
//
// The snapshot is always taken at full depth regardless of limit: the anchor
// can sit anywhere in the ring, and only the entries behind it count.
func (s *store) recentBefore(beforeID string, limit int, match func(*api.Entry) bool) []*api.Entry {
	cand := s.snapshotEntries(s.capacity)
	return pick(cand, page(cand, true, beforeID, false, 0, limit, match))
}

// recentBeforeRaw is recentBefore returning the entries' cached JSON.
func (s *store) recentBeforeRaw(beforeID string, limit int, match func(*api.Entry) bool) [][]byte {
	entries, raws := s.snapshotRaw(s.capacity)
	return pickRaw(raws, page(entries, true, beforeID, false, 0, limit, match))
}

// recentBeforeSeq returns up to limit entries with Seq strictly less than
// beforeSeq, newest first, satisfying match. Unlike recentBefore (anchored on
// an entry ID that must still be present in the ring to find the starting
// point), this needs no such lookup: Seq is a hub-assigned monotonic counter
// (see add), so "older than this point" is a plain comparison that keeps
// working even once the entry a client is paging from has aged out of the
// buffer.
//
// Seq is 1-indexed, so beforeSeq <= 1 legitimately matches nothing — that is
// how a client paging backwards learns it has reached the start of the stream.
// See page for why that is expressed with a flag instead of a zero sentinel.
func (s *store) recentBeforeSeq(beforeSeq int64, limit int, match func(*api.Entry) bool) []*api.Entry {
	cand := s.snapshotEntries(s.capacity)
	return pick(cand, page(cand, false, "", true, beforeSeq, limit, match))
}

// recentBeforeSeqRaw is recentBeforeSeq returning the entries' cached JSON.
func (s *store) recentBeforeSeqRaw(beforeSeq int64, limit int, match func(*api.Entry) bool) [][]byte {
	entries, raws := s.snapshotRaw(s.capacity)
	return pickRaw(raws, page(entries, false, "", true, beforeSeq, limit, match))
}

// get returns the entry with the given id, or nil. O(1) via the byID index.
func (s *store) get(id string) *api.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id]
}

// size returns how many ring buffer slots are currently filled (0..capacity)
// -- the buffer's fill level, exposed via /metrics so an operator can tell how
// much history depth the buffer is actually holding under the current load.
func (s *store) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveLen()
}

// stats snapshots the current aggregates. workers is supplied by the caller
// since worker connections are tracked by the server, not the store.
func (s *store) stats(workers int) api.Stats {
	now := s.now()

	s.mu.RLock()
	// total is atomic and add() bumps it *before* taking the lock, so it is
	// read here inside the critical section rather than before it: an add that
	// has already incremented total but not yet reached its Lock() will land in
	// byProtocol/byStatus/rate only after this RLock is released, so sampling
	// total first would let those aggregates come from a strictly later moment
	// than the counter and exceed it. Reading it under RLock pins the direction
	// consumers depend on — total >= sum(byProtocol), never the reverse, so a
	// per-protocol share can't come out above 100%. This costs nothing on
	// add()'s hot path: it never takes RLock, and total stays atomic precisely
	// so add() can assign Seq and marshal off-lock.
	total := s.total.Load()
	byProto := make(map[string]int64, len(s.byProtocol))
	for k, v := range s.byProtocol {
		byProto[k] = v
	}
	byStatus := make(map[string]int64, len(s.byStatus))
	for k, v := range s.byStatus {
		byStatus[k] = v
	}
	perSec, w1, w5 := s.windows(now)
	s.mu.RUnlock()

	return api.Stats{
		TotalEntries:  total,
		EntriesPerSec: perSec,
		Workers:       workers,
		ByProtocol:    byProto,
		ByStatus:      byStatus,
		Last1m:        w1,
		Last5m:        w5,
	}
}

// windows tallies the trailing live/1m/5m rates from the per-second buckets.
// It is O(rateWindowSeconds) regardless of buffer size and of how much traffic
// the hub has seen; the previous implementation walked the ring and stopped at
// the first entry older than 5m, which at any real ingest rate meant walking
// all `capacity` entries on every /api/stats, every /metrics scrape, every
// statsLoop tick and every front-client connect.
//
// The buckets are fed by add(), so these tallies cover *everything ingested*
// in the window rather than only what still fits in the ring — deliberately
// different from (and larger than) what the old ring walk reported, since the
// ring holds only a few seconds of traffic at any real rate. That is the
// documented contract on api.Stats.Last1m/Last5m; do not clamp it back to the
// buffer, which would resurrect a number that silently under-reports load
// exactly when load is highest.
//
// A bucket counts toward a window only while its second is less than the
// window's width away from now, so all three rates decay to zero on their own
// once traffic stops rather than freezing at the last observed value.
// Caller holds at least RLock.
func (s *store) windows(now time.Time) (perSec float64, last1m, last5m *api.WindowStats) {
	nowSec := now.Unix()
	w1, w5 := &api.WindowStats{}, &api.WindowStats{}
	var live int64
	for i := range s.rate {
		b := &s.rate[i]
		age := nowSec - b.sec
		if age < 0 || age >= rateWindowSeconds {
			continue // stale bucket (or one never written), outside every window
		}
		w5.Entries += b.entries
		w5.Errors += b.errors
		w5.Warnings += b.warnings
		if age < 60 {
			w1.Entries += b.entries
			w1.Errors += b.errors
			w1.Warnings += b.warnings
		}
		if age < liveRateSeconds {
			live += b.entries
		}
	}
	w1.EntriesPerSec = float64(w1.Entries) / 60.0
	w5.EntriesPerSec = float64(w5.Entries) / float64(rateWindowSeconds)
	return float64(live) / liveRateSeconds, w1, w5
}
