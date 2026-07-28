package hub

// TST-7: benchmarks for the hub's hot paths — the code that absorbs the whole
// cluster's throughput. Without these there is no way to objectify a perf
// regression on ingest (store.add), fan-out (broadcast to N filtered clients),
// or per-entry filter evaluation (run for every entry × every client). Run
// with `make bench`; b.ReportAllocs surfaces per-entry allocations, the thing
// that bites at scale.

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pablocolson/k8shark/internal/config"
	"github.com/pablocolson/k8shark/pkg/api"
)

// benchEntry is a representative HTTP entry reused across the hub benchmarks.
func benchEntry() *api.Entry {
	return &api.Entry{
		ID:          "bench-1",
		Protocol:    api.ProtocolHTTP,
		Timestamp:   time.Unix(1_700_000_000, 0),
		ElapsedMs:   42,
		Node:        "node-a",
		Source:      api.Endpoint{IP: "10.0.0.1", Port: 40000, Namespace: "shop", Workload: "web"},
		Destination: api.Endpoint{IP: "10.0.0.2", Port: 80, Namespace: "prod", Workload: "api"},
		Request:     api.Payload{Method: "GET", Path: "/api/v1/users", Host: "api", Summary: "GET /api/v1/users"},
		Response:    api.Payload{StatusCode: 200, Summary: "200 OK"},
		Status:      "success",
		StatusCode:  200,
	}
}

const benchFilter = `protocol == "http" and response.status < 500`

func BenchmarkCompileFilter(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := CompileFilter(benchFilter); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPredicate(b *testing.B) {
	pred, err := CompileFilter(benchFilter)
	if err != nil {
		b.Fatal(err)
	}
	e := benchEntry()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pred(e)
	}
}

func BenchmarkStoreAdd(b *testing.B) {
	st := newStore(config.EntryBufferSize)
	e := benchEntry()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.add(e)
	}
}

// BenchmarkStoreAddParallel is the one that matters for ingest: store.add is
// the funnel every worker connection's read goroutine passes through, so the
// interesting number is throughput under contention, not the single-threaded
// cost of one call. Each goroutine owns its entry, as a real worker connection
// does.
func BenchmarkStoreAddParallel(b *testing.B) {
	st := newStore(config.EntryBufferSize)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		e := benchEntry()
		for pb.Next() {
			st.add(e)
		}
	})
}

// BenchmarkBroadcast measures the fan-out cost — queueing entries into the
// pending window plus the batched, cached-JSON dispatch to each connected
// client — at a few client counts, the hub's main point of contention. Each
// iteration queues one entry; the flush is forced explicitly so the benchmark
// captures the full path deterministically instead of timer-dependent.
func BenchmarkBroadcast(b *testing.B) {
	for _, n := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("clients=%d", n), func(b *testing.B) {
			benchmarkBroadcast(b, n, false)
		})
	}
	// Every dashboard tab normally carries the same filter, which is what the
	// cases above model (one predicate pass and one assembled frame shared by
	// the whole group). This case is the pessimistic opposite — every client
	// on its own filter — so a regression in the ungrouped path stays visible.
	b.Run("clients=50/distinct-filters", func(b *testing.B) {
		benchmarkBroadcast(b, 50, true)
	})
}

func benchmarkBroadcast(b *testing.B, n int, distinctFilters bool) {
	s := New(discardLogger(), Options{})
	stop := make(chan struct{})
	for i := 0; i < n; i++ {
		filter := benchFilter
		if distinctFilters {
			// Same selectivity, different source: a distinct filter key means
			// a distinct group in flushBroadcast.
			filter = fmt.Sprintf(`protocol == "http" and response.status < %d`, 500+i)
		}
		pred, err := CompileFilter(filter)
		if err != nil {
			b.Fatal(err)
		}
		c := &frontClient{send: make(chan []byte, 8), pred: pred, filterKey: filterKeySource(filter)}
		s.frontClients[c] = struct{}{}
		go func(ch chan []byte) {
			for {
				select {
				case <-ch:
				case <-stop:
					return
				}
			}
		}(c.send)
	}
	s.frontCount.Store(int32(len(s.frontClients)))
	b.Cleanup(func() { close(stop) })

	e := benchEntry()
	raw, err := json.Marshal(e)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.broadcast(e, raw)
		if i%64 == 63 {
			s.flushBroadcast()
		}
	}
	s.flushBroadcast()
}

// BenchmarkStoreRecent measures the read path behind /api/summary,
// /api/timeline, /api/graph and /api/pcap — a full-ring predicate scan, which
// the front polls unconditionally every few seconds. What matters here is not
// only the total but how much of it used to run while holding the store lock
// every ingest goroutine needs.
func BenchmarkStoreRecent(b *testing.B) {
	st := newStore(config.EntryBufferSize)
	for i := 0; i < config.EntryBufferSize; i++ {
		e := benchEntry()
		e.ID = fmt.Sprintf("e%d", i)
		st.add(e)
	}
	pred, err := CompileFilter(benchFilter)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = st.recent(st.capacity, pred)
	}
}

// BenchmarkStoreAddUnderScan is the number that matters for the read path:
// ingest throughput while a reader does what /api/summary does every 5s (and
// /api/timeline every 10s) — a full-ring predicate scan. Evaluating the
// predicate while holding the store's read lock stalls every ingest goroutine
// for the duration of the scan, so this measures the coupling between the two,
// not the scan itself.
func BenchmarkStoreAddUnderScan(b *testing.B) {
	st := newStore(config.EntryBufferSize)
	for i := 0; i < config.EntryBufferSize; i++ {
		e := benchEntry()
		e.ID = fmt.Sprintf("e%d", i)
		st.add(e)
	}
	pred, err := CompileFilter(benchFilter)
	if err != nil {
		b.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = st.recent(st.capacity, pred)
			}
		}
	}()
	b.Cleanup(func() { close(stop) })

	e := benchEntry()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.add(e)
	}
}

// BenchmarkStoreStats covers the aggregate snapshot taken by statsLoop (2s
// ticker), every /api/stats, every /metrics scrape and every front connect.
func BenchmarkStoreStats(b *testing.B) {
	st := newStore(config.EntryBufferSize)
	for i := 0; i < config.EntryBufferSize; i++ {
		e := benchEntry()
		e.ID = fmt.Sprintf("e%d", i)
		e.Timestamp = time.Now()
		st.add(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = st.stats(1)
	}
}
