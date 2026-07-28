package hub

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

func TestStoreGetByID(t *testing.T) {
	s := newStore(4)
	e := &api.Entry{ID: "abc", Protocol: api.ProtocolHTTP, Timestamp: time.Now()}
	s.add(e)

	if got := s.get("abc"); got != e {
		t.Fatalf("get(abc) = %v, want the added entry", got)
	}
	if got := s.get("missing"); got != nil {
		t.Fatalf("get(missing) = %v, want nil", got)
	}

	// Overwrite the whole ring so the first entry is evicted; its id must no
	// longer resolve (the index is kept in sync with the buffer).
	for i := 0; i < 4; i++ {
		s.add(&api.Entry{ID: fmt.Sprintf("e%d", i), Protocol: api.ProtocolHTTP, Timestamp: time.Now()})
	}
	if got := s.get("abc"); got != nil {
		t.Fatalf("get(abc) after eviction = %v, want nil", got)
	}
	if got := s.get("e3"); got == nil || got.ID != "e3" {
		t.Fatalf("get(e3) = %v, want the live entry", got)
	}
}

func TestStoreRecentBefore(t *testing.T) {
	s := newStore(10)
	for i := 0; i < 5; i++ {
		s.add(&api.Entry{ID: fmt.Sprintf("e%d", i), Protocol: api.ProtocolHTTP, Timestamp: time.Now()})
	}
	// Buffer holds e0..e4, newest (e4) first. Paging before e2 should yield
	// e1 then e0 — the entries strictly older than the anchor.
	got := s.recentBefore("e2", 10, nil)
	if len(got) != 2 || got[0].ID != "e1" || got[1].ID != "e0" {
		t.Fatalf("recentBefore(e2) = %v, want [e1 e0]", ids(got))
	}

	// Paging before the oldest entry yields nothing.
	if got := s.recentBefore("e0", 10, nil); len(got) != 0 {
		t.Fatalf("recentBefore(e0) = %v, want empty", ids(got))
	}

	// An anchor that isn't in the buffer (aged out or never existed) is a
	// safe no-op rather than a guess.
	if got := s.recentBefore("missing", 10, nil); len(got) != 0 {
		t.Fatalf("recentBefore(missing) = %v, want empty", ids(got))
	}

	// limit is respected.
	if got := s.recentBefore("e4", 1, nil); len(got) != 1 || got[0].ID != "e3" {
		t.Fatalf("recentBefore(e4, limit=1) = %v, want [e3]", ids(got))
	}

	// match filters the paged results too.
	onlyE0 := func(e *api.Entry) bool { return e.ID == "e0" }
	if got := s.recentBefore("e2", 10, onlyE0); len(got) != 1 || got[0].ID != "e0" {
		t.Fatalf("recentBefore(e2, match=e0) = %v, want [e0]", ids(got))
	}
}

// recentBeforeSeq (HUB-3) offers the same "strictly older than" pagination as
// recentBefore, but by numeric comparison instead of first locating an
// anchor entry by ID -- so it works even for a seq that isn't (or is no
// longer) any live entry's, unlike recentBefore which requires the exact
// anchor ID to still be present in the ring.
func TestStoreRecentBeforeSeq(t *testing.T) {
	s := newStore(10)
	for i := 0; i < 5; i++ {
		s.add(&api.Entry{ID: fmt.Sprintf("e%d", i), Protocol: api.ProtocolHTTP, Timestamp: time.Now()})
	}
	if s.buf[2].Seq != 3 {
		t.Fatalf("e2.Seq = %d, want 3 (1-indexed ingestion order)", s.buf[2].Seq)
	}

	// Paging before e2's seq (3) yields e1, e0 -- same result recentBefore("e2", ...) gives.
	if got := s.recentBeforeSeq(3, 10, nil); len(got) != 2 || got[0].ID != "e1" || got[1].ID != "e0" {
		t.Fatalf("recentBeforeSeq(3) = %v, want [e1 e0]", ids(got))
	}

	// A seq beyond any assigned value still works -- no anchor lookup needed,
	// just a comparison, unlike recentBefore("missing", ...) which must give up.
	if got := s.recentBeforeSeq(1000, 10, nil); len(got) != 5 {
		t.Fatalf("recentBeforeSeq(1000) = %v, want all 5 entries", ids(got))
	}

	// At or below the oldest entry's seq yields nothing.
	if got := s.recentBeforeSeq(1, 10, nil); len(got) != 0 {
		t.Fatalf("recentBeforeSeq(1) = %v, want empty", ids(got))
	}

	// limit is respected.
	if got := s.recentBeforeSeq(5, 1, nil); len(got) != 1 || got[0].ID != "e3" {
		t.Fatalf("recentBeforeSeq(5, limit=1) = %v, want [e3]", ids(got))
	}

	// match filters the paged results too.
	onlyE0 := func(e *api.Entry) bool { return e.ID == "e0" }
	if got := s.recentBeforeSeq(3, 10, onlyE0); len(got) != 1 || got[0].ID != "e0" {
		t.Fatalf("recentBeforeSeq(3, match=e0) = %v, want [e0]", ids(got))
	}
}

// The zero value of either pagination cursor is a legal cursor meaning "match
// nothing", not an absent one meaning "no constraint" — a shared page() walker
// that infers "unset" from the zero value inverts both into "return the newest
// full page", which makes a client paging backwards past the start of the
// buffer wrap to the head and loop forever.
func TestStorePagingZeroCursorMatchesNothing(t *testing.T) {
	s := newStore(10)
	for i := 0; i < 5; i++ {
		s.add(&api.Entry{ID: fmt.Sprintf("e%d", i), Protocol: api.ProtocolHTTP, Timestamp: time.Now()})
	}

	// Seq is 1-indexed, so nothing is ever strictly older than seq 0.
	if got := s.recentBeforeSeq(0, 10, nil); len(got) != 0 {
		t.Errorf("recentBeforeSeq(0) = %v, want empty (0 is a cursor, not 'unfiltered')", ids(got))
	}
	if got := s.recentBeforeSeqRaw(0, 10, nil); len(got) != 0 {
		t.Errorf("recentBeforeSeqRaw(0) = %d entries, want empty", len(got))
	}

	// An empty anchor id is no more findable in the ring than any other absent
	// id, so it must behave like recentBefore("missing"): no results.
	if got := s.recentBefore("", 10, nil); len(got) != 0 {
		t.Errorf(`recentBefore("") = %v, want empty (an absent anchor, not 'unanchored')`, ids(got))
	}
	if got := s.recentBeforeRaw("", 10, nil); len(got) != 0 {
		t.Errorf(`recentBeforeRaw("") = %d entries, want empty`, len(got))
	}

	// The unanchored queries are unaffected — they really do mean "no cursor".
	if got := s.recent(10, nil); len(got) != 5 {
		t.Errorf("recent(10) = %v, want all 5", ids(got))
	}
}

func ids(es []*api.Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

// Trailing windows: only entries inside 1m/5m count, and errors are tallied.
func TestStoreWindowStats(t *testing.T) {
	s := newStore(16)
	now := time.Now()
	add := func(id string, age time.Duration, status string) {
		s.add(&api.Entry{ID: id, Protocol: api.ProtocolHTTP, Timestamp: now.Add(-age), Status: status})
	}
	add("old", 10*time.Minute, "error") // outside both windows
	add("w5", 3*time.Minute, "error")   // 5m only
	add("w1a", 30*time.Second, "success")
	add("w1b", 5*time.Second, "error")

	st := s.stats(1)
	if st.Last1m == nil || st.Last5m == nil {
		t.Fatal("windows missing from stats")
	}
	if st.Last1m.Entries != 2 || st.Last1m.Errors != 1 {
		t.Errorf("last1m = %d entries %d errors, want 2/1", st.Last1m.Entries, st.Last1m.Errors)
	}
	if st.Last5m.Entries != 3 || st.Last5m.Errors != 2 {
		t.Errorf("last5m = %d entries %d errors, want 3/2", st.Last5m.Entries, st.Last5m.Errors)
	}
}

// The rate windows are per-second buckets advanced lazily in add() rather than
// a walk over the ring, so their two easy-to-break properties are pinned here
// against a fake clock: the trailing tallies must decay to zero once traffic
// stops (never freeze at the last observed value), and a bucket reused a full
// window later must be reset rather than accumulate on top of the traffic it
// held 300s ago.
func TestStoreRateWindowsDecayWithClock(t *testing.T) {
	s := newStore(64)
	base := time.Unix(1_800_000_000, 0)
	clock := base
	s.now = func() time.Time { return clock }

	addAt := func(n int, status string) {
		for i := 0; i < n; i++ {
			s.add(&api.Entry{
				ID:        fmt.Sprintf("e-%d-%d", clock.Unix(), i),
				Protocol:  api.ProtocolHTTP,
				Timestamp: clock,
				Status:    status,
			})
		}
	}

	addAt(10, "success")
	clock = base.Add(3 * time.Second)
	addAt(2, "error")

	st := s.stats(0)
	if st.EntriesPerSec != 12.0/liveRateSeconds {
		t.Errorf("entriesPerSec at +3s = %v, want %v", st.EntriesPerSec, 12.0/liveRateSeconds)
	}
	if st.Last1m.Entries != 12 || st.Last1m.Errors != 2 {
		t.Errorf("last1m at +3s = %d/%d, want 12/2", st.Last1m.Entries, st.Last1m.Errors)
	}
	if st.Last5m.Entries != 12 || st.Last5m.Errors != 2 {
		t.Errorf("last5m at +3s = %d/%d, want 12/2", st.Last5m.Entries, st.Last5m.Errors)
	}

	// Traffic stops. The live rate falls out of its 5s window first...
	clock = base.Add(10 * time.Second)
	if st := s.stats(0); st.EntriesPerSec != 0 {
		t.Errorf("entriesPerSec at +10s = %v, want 0 (decayed, not frozen)", st.EntriesPerSec)
	} else if st.Last1m.Entries != 12 {
		t.Errorf("last1m at +10s = %d, want 12 (still inside the minute)", st.Last1m.Entries)
	}

	// ...then the 1m window...
	clock = base.Add(70 * time.Second)
	if st := s.stats(0); st.Last1m.Entries != 0 || st.Last1m.Errors != 0 || st.Last1m.EntriesPerSec != 0 {
		t.Errorf("last1m at +70s = %+v, want all zero", st.Last1m)
	} else if st.Last5m.Entries != 12 {
		t.Errorf("last5m at +70s = %d, want 12 (still inside the 5 minutes)", st.Last5m.Entries)
	}

	// ...and finally the 5m one, without any of it being swept by a ticker.
	clock = base.Add(6 * time.Minute)
	if st := s.stats(0); st.Last5m.Entries != 0 || st.Last5m.Errors != 0 || st.Last5m.EntriesPerSec != 0 {
		t.Errorf("last5m at +6m = %+v, want all zero", st.Last5m)
	}

	// TotalEntries is a lifetime counter and must not decay with the windows.
	if st := s.stats(0); st.TotalEntries != 12 {
		t.Errorf("totalEntries = %d, want 12", st.TotalEntries)
	}

	// Bucket reuse: base+300s lands on the same bucket index as base. Its 10
	// old entries must be discarded, not added to — while base+3s (297s old,
	// still inside the window) keeps its 2.
	clock = base.Add(rateWindowSeconds * time.Second)
	addAt(1, "success")
	if st := s.stats(0); st.Last5m.Entries != 3 {
		t.Errorf("last5m after bucket reuse = %d, want 3 (1 new + 2 still in window, the 10 at base evicted)", st.Last5m.Entries)
	}
}

// The windows are fed by add(), not by walking the ring, so they deliberately
// count every entry ingested in the window — including ones already evicted
// from the buffer. This pins that contract (documented on api.Stats.Last1m/
// Last5m): a hub whose ring holds 4 slots but that ingested 40 entries in the
// last minute must report 40, not 4. Clamping back to buffer capacity would
// under-report exactly when the hub is busiest.
func TestStoreWindowsNotBoundedByBufferCapacity(t *testing.T) {
	const capacity, ingested = 4, 40
	s := newStore(capacity)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }

	for i := 0; i < ingested; i++ {
		s.add(&api.Entry{
			ID:        fmt.Sprintf("e%d", i),
			Protocol:  api.ProtocolHTTP,
			Timestamp: now,
			Status:    "error",
		})
	}
	if got := s.size(); got != capacity {
		t.Fatalf("buffer holds %d entries, want it saturated at %d", got, capacity)
	}

	st := s.stats(0)
	if st.Last1m.Entries != ingested || st.Last1m.Errors != ingested {
		t.Errorf("last1m = %d entries/%d errors, want %d/%d (ingest, not buffer capacity)",
			st.Last1m.Entries, st.Last1m.Errors, ingested, ingested)
	}
	if st.Last5m.Entries != ingested || st.Last5m.Errors != ingested {
		t.Errorf("last5m = %d entries/%d errors, want %d/%d (ingest, not buffer capacity)",
			st.Last5m.Entries, st.Last5m.Errors, ingested, ingested)
	}
	if st.Last1m.EntriesPerSec != float64(ingested)/60.0 {
		t.Errorf("last1m entriesPerSec = %v, want %v", st.Last1m.EntriesPerSec, float64(ingested)/60.0)
	}
}

// add() bumps the lifetime total *before* taking the ring lock and folds the
// entry into byProtocol/byStatus/rate *inside* it, so stats() must sample the
// total under the same lock as those aggregates. Sampling it first lets adds
// that already incremented total land in the maps afterwards, and the snapshot
// comes back with sum(byProtocol) > TotalEntries — a Prometheus consumer
// computing a per-protocol share then sees >100%.
// The interleaving is driven rather than raced for: the window a hot loop would
// have to hit is a couple of instructions wide, so a stress test passes on the
// broken ordering just as happily as on the correct one. Here the ring lock is
// held for the duration, which pins the probing stats() call at its RLock while
// a whole add is landed behind it.
func TestStoreStatsTotalNeverBelowAggregates(t *testing.T) {
	s := newStore(16)

	// s.now runs at the top of stats(), before it samples anything, so it
	// doubles as a "stats() has entered" signal. Buffered + non-blocking so the
	// hook never depends on the test being parked on the receive.
	entered := make(chan struct{}, 1)
	s.now = func() time.Time {
		select {
		case entered <- struct{}{}:
		default:
		}
		return time.Now()
	}

	s.mu.Lock()
	done := make(chan api.Stats, 1)
	go func() { done <- s.stats(0) }()

	<-entered
	// stats() is now a few instructions from its RLock and cannot get past it
	// while the write lock is held; the sleep only has to cover those few
	// instructions, the lock does the real synchronising.
	time.Sleep(50 * time.Millisecond)

	// Emulate an add that completes entirely inside that window, in add()'s own
	// order: the lifetime counter is bumped *before* the lock is taken (so the
	// entry can be marshaled off-lock) and the aggregates are updated *inside*
	// it.
	s.total.Add(1)
	s.byProtocol[string(api.ProtocolHTTP)]++
	s.mu.Unlock()

	st := <-done
	var summed int64
	for _, v := range st.ByProtocol {
		summed += v
	}
	if summed > st.TotalEntries {
		t.Fatalf("sum(byProtocol) = %d exceeds totalEntries = %d; stats() sampled the counter before taking the lock, so an add landed in the aggregates after the total was read",
			summed, st.TotalEntries)
	}
}

// add() marshals outside the ring lock and takes its Seq from an atomic, so
// two concurrent adds can be interleaved between assigning a slot and filling
// it. This pins the invariant that makes that safe: buf[i] and raw[i] always
// come from the same add, and every entry gets a distinct Seq.
func TestStoreConcurrentAddSlotIntegrity(t *testing.T) {
	const writers, perWriter = 8, 200
	s := newStore(writers * perWriter) // large enough that nothing is evicted

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				s.add(&api.Entry{
					ID:        fmt.Sprintf("w%d-%d", w, i),
					Protocol:  api.ProtocolHTTP,
					Timestamp: time.Now(),
				})
			}
		}(w)
	}
	wg.Wait()

	if got := s.total.Load(); got != writers*perWriter {
		t.Fatalf("total = %d, want %d", got, writers*perWriter)
	}
	seqs := map[int64]bool{}
	entries, raws := s.snapshotRaw(s.capacity)
	if len(entries) != writers*perWriter {
		t.Fatalf("snapshot has %d entries, want %d", len(entries), writers*perWriter)
	}
	for i, e := range entries {
		var decoded api.Entry
		if err := json.Unmarshal(raws[i], &decoded); err != nil {
			t.Fatalf("slot %d raw is not valid JSON: %v", i, err)
		}
		if decoded.ID != e.ID || decoded.Seq != e.Seq {
			t.Fatalf("slot %d holds entry %s/seq %d but JSON for %s/seq %d",
				i, e.ID, e.Seq, decoded.ID, decoded.Seq)
		}
		if seqs[e.Seq] {
			t.Fatalf("duplicate Seq %d", e.Seq)
		}
		seqs[e.Seq] = true
	}
}
