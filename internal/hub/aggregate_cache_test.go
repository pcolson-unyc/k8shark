package hub

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedAggCoalescesAndExpires(t *testing.T) {
	s := &Server{}
	var calls atomic.Int32
	build := func() ([]byte, error) { calls.Add(1); return []byte("ok"), nil }
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			b, err := s.cachedAgg("same", build)
			if err != nil || string(b) != "ok" {
				t.Errorf("body=%q error=%v", b, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("builds=%d", calls.Load())
	}
	for i := 0; i < 5; i++ {
		entry := s.aggCache["same"]
		entry.at = time.Now().Add(-2 * aggCacheTTL)
		s.aggCache["same"] = entry
		if _, err := s.cachedAgg("same", build); err != nil {
			t.Fatal(err)
		}
		if s.aggCacheBytes != 2 {
			t.Fatalf("expired replacement bytes=%d", s.aggCacheBytes)
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("expiry builds=%d", calls.Load())
	}
}

func TestCachedAggEntryAndByteBounds(t *testing.T) {
	s := &Server{}
	check := func() {
		t.Helper()
		bytes := 0
		for _, entry := range s.aggCache {
			bytes += len(entry.body)
		}
		if bytes != s.aggCacheBytes || bytes > 4<<20 || len(s.aggCache) > 32 {
			t.Fatalf("bytes=%d accounted=%d keys=%d", bytes, s.aggCacheBytes, len(s.aggCache))
		}
	}
	for i := 0; i < 40; i++ {
		_, _ = s.cachedAgg(fmt.Sprint(i), func() ([]byte, error) { return []byte("x"), nil })
		check()
	}
	for i := 0; i < 8; i++ {
		_, _ = s.cachedAgg(fmt.Sprint("large", i), func() ([]byte, error) { return make([]byte, 1<<20), nil })
		check()
	}
	for i := 0; i < 2; i++ {
		_, err := s.cachedAgg("error", func() ([]byte, error) { return nil, errors.New("bad") })
		if err == nil {
			t.Fatal("missing error")
		}
		_, _ = s.cachedAgg("huge", func() ([]byte, error) { return make([]byte, (4<<20)+1), nil })
		if _, ok := s.aggCache["error"]; ok {
			t.Fatal("error cached")
		}
		if _, ok := s.aggCache["huge"]; ok {
			t.Fatal("oversized cached")
		}
		check()
	}
}

func TestAggregateCacheHandlerQueryIsolation(t *testing.T) {
	s := &Server{store: newStore(10)}
	queries := []string{"", "?groupBy=protocol", "?limit=1", "?filter=protocol%20%3D%3D%20http", "?since=2026-01-01T00:00:00Z", "?until=2026-12-31T00:00:00Z"}
	for _, q := range queries {
		r := httptest.NewRequest("GET", "/api/summary"+q, nil)
		w := httptest.NewRecorder()
		s.handleSummary(w, r)
		if w.Code != 200 {
			t.Fatalf("query=%q code=%d body=%s", q, w.Code, w.Body.String())
		}
		if _, ok := s.aggCache["summary:"+r.URL.RequestURI()]; !ok {
			t.Fatalf("missing key for %q", q)
		}
	}
	for _, q := range []string{"", "?focus=foo", "?filter=protocol%20%3D%3D%20http"} {
		r := httptest.NewRequest("GET", "/api/graph"+q, nil)
		w := httptest.NewRecorder()
		s.handleGraph(w, r)
		if w.Code != 200 {
			t.Fatalf("graph query=%q code=%d", q, w.Code)
		}
		if _, ok := s.aggCache["graph:"+r.URL.RequestURI()]; !ok {
			t.Fatalf("missing graph key for %q", q)
		}
	}
	if len(s.aggCache) != len(queries)+3 {
		t.Fatal("distinct queries shared keys")
	}
}
