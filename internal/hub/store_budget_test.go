package hub

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

func TestStoreByteBudgetMatchesFIFOModel(t *testing.T) {
	for _, budget := range []int64{900, 2000, 100000} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			s := newStore(5, budget)
			var want []*api.Entry
			var sizes []int64
			var totalBytes int64
			for i := 0; i < 60; i++ {
				e := &api.Entry{ID: fmt.Sprintf("id%d", i%3), Protocol: api.ProtocolHTTP, Timestamp: time.Now(), Request: api.Payload{Body: strings.Repeat("x", (i%7)*150)}}
				raw := s.add(e)
				if int64(len(raw)) <= budget {
					want = append(want, e)
					sizes = append(sizes, int64(len(raw)))
					totalBytes += int64(len(raw))
					for len(want) > 5 || totalBytes > budget {
						totalBytes -= sizes[0]
						want = want[1:]
						sizes = sizes[1:]
					}
				}
				got, raws := s.snapshotRaw(100)
				if len(got) != len(want) || s.retainedBytes != totalBytes {
					t.Fatalf("step%d len=%d want%d bytes=%d want%d", i, len(got), len(want), s.retainedBytes, totalBytes)
				}
				index := map[string]*api.Entry{}
				for j, w := range want {
					index[w.ID] = w
					k := len(want) - 1 - j
					if got[k] != w {
						t.Fatalf("FIFO mismatch step%d", i)
					}
					var decoded api.Entry
					if err := json.Unmarshal(raws[k], &decoded); err != nil || decoded.Seq != w.Seq {
						t.Fatalf("raw mirror mismatch: %v", err)
					}
				}
				for id, w := range index {
					if s.get(id) != w {
						t.Fatalf("duplicate ID index lost newest %s at step%d", id, i)
					}
				}
				if s.stats(0).TotalEntries != int64(i+1) {
					t.Fatal("oversized entries lost from ingestion stats")
				}
			}
		})
	}
}

func TestOversizedEntryPreservesHistoryAndFanoutPayload(t *testing.T) {
	s := newStore(10, 1000)
	e := &api.Entry{ID: "small", Protocol: api.ProtocolHTTP}
	s.add(e)
	big := &api.Entry{ID: "large", Protocol: api.ProtocolHTTP, Request: api.Payload{Body: strings.Repeat("x", 2000)}}
	if raw := s.add(big); len(raw) < 2000 {
		t.Fatal("oversized live payload was dropped")
	}
	if s.size() != 1 || s.get("small") != e || s.get("large") != nil {
		t.Fatal("oversized entry disturbed retained history")
	}
	if got := s.recentBeforeSeq(big.Seq, 10, nil); len(got) != 1 || got[0] != e {
		t.Fatal("sequence pagination broke across unretained entry")
	}
}
