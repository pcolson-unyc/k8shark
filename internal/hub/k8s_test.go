package hub

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pablocolson/k8shark/pkg/api"
)

// newTestResolver builds an enabled (non-nil client) resolver with a seeded IP
// map and an empty catch-up registry, for the catch-up tests below. byIP is an
// atomically-swapped snapshot, so it is published through setByIP rather than
// assigned in the literal.
func newTestResolver(byIP map[string]ref) *resolver {
	r := &resolver{
		log:     slog.Default(),
		client:  &http.Client{}, // non-nil => enabled()
		pending: map[string]*pendingResolve{},
	}
	r.setByIP(byIP)
	return r
}

// learn publishes a new snapshot with one extra IP -> identity mapping, the way
// a refresh cycle would (the published map is never mutated in place).
func (r *resolver) learn(ip string, rf ref) {
	m := map[string]ref{ip: rf}
	if cur := r.byIP.Load(); cur != nil {
		for k, v := range *cur {
			if k != ip {
				m[k] = v
			}
		}
	}
	r.setByIP(m)
}

// TestResolverEnrich fills endpoint Name/Namespace from the IP map, skips
// unknown IPs, and never overwrites an already-set Name.
func TestResolverEnrich(t *testing.T) {
	r := newTestResolver(map[string]ref{
		"10.0.0.1": {name: "web-abc", namespace: "shop"},
		"10.0.0.2": {name: "pg-0", namespace: "db"},
	})

	e := &api.Entry{
		Source:      api.Endpoint{IP: "10.0.0.1", Port: 5000},
		Destination: api.Endpoint{IP: "10.0.0.2", Port: 5432},
	}
	r.enrich(e)
	if e.Source.Name != "web-abc" || e.Source.Namespace != "shop" {
		t.Errorf("source = %q/%q, want web-abc/shop", e.Source.Name, e.Source.Namespace)
	}
	if e.Destination.Name != "pg-0" || e.Destination.Namespace != "db" {
		t.Errorf("dest = %q/%q, want pg-0/db", e.Destination.Name, e.Destination.Namespace)
	}

	// Unknown IP stays bare; an already-named endpoint is left untouched.
	e2 := &api.Entry{
		Source:      api.Endpoint{IP: "10.9.9.9"},
		Destination: api.Endpoint{IP: "10.0.0.1", Name: "keep"},
	}
	r.enrich(e2)
	if e2.Source.Name != "" {
		t.Errorf("unknown source got name %q, want empty", e2.Source.Name)
	}
	if e2.Destination.Name != "keep" {
		t.Errorf("named dest overwritten to %q, want keep", e2.Destination.Name)
	}
}

// TestResolverDisabledNoop: an off-cluster resolver (nil client) enriches
// nothing, even with a populated map.
func TestResolverDisabledNoop(t *testing.T) {
	r := &resolver{}
	r.setByIP(map[string]ref{"10.0.0.1": {name: "x"}})
	e := &api.Entry{Source: api.Endpoint{IP: "10.0.0.1"}}
	r.enrich(e)
	if e.Source.Name != "" {
		t.Errorf("disabled resolver enriched %q, want no-op", e.Source.Name)
	}
}

// The workload label (stable across pod restarts) is filled alongside the pod
// name, including on endpoints whose Name was already set by the worker.
func TestResolverEnrichWorkload(t *testing.T) {
	r := newTestResolver(map[string]ref{
		"10.0.0.1": {name: "web-7d9f4b-x2x4v", namespace: "shop", workload: "web"},
	})
	e := &api.Entry{Source: api.Endpoint{IP: "10.0.0.1"}, Destination: api.Endpoint{IP: "10.0.0.1", Name: "keep"}}
	r.enrich(e)
	if e.Source.Workload != "web" {
		t.Errorf("source workload = %q, want web", e.Source.Workload)
	}
	// Name already set (worker-supplied) still gains the workload.
	if e.Destination.Name != "keep" || e.Destination.Workload != "web" {
		t.Errorf("dest = %q/%q, want keep/web", e.Destination.Name, e.Destination.Workload)
	}
}

// A failed refresh (e.g. broken RBAC returning 403) is counted via failures(),
// exposed as k8shark_hub_k8s_enrich_failures_total, without blanking the
// previously resolved map.
func TestResolverRefreshFailureCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	r := &resolver{
		log:    slog.Default(),
		client: srv.Client(),
		api:    srv.URL,
		token:  "x",
	}
	r.setByIP(map[string]ref{"10.0.0.1": {name: "keep"}})
	r.refresh(context.Background())
	if got := r.failures(); got != 1 {
		t.Fatalf("failures() = %d, want 1", got)
	}
	if rf, _ := r.ipRef("10.0.0.1"); rf.name != "keep" {
		t.Error("a failed refresh must not blank the previous enrichment map")
	}
}

// TestResolverEnrichTracksOnlyUnresolved: enrich registers an entry for
// catch-up only while it still carries a bare endpoint IP; a fully resolved
// entry is not tracked.
func TestResolverEnrichTracksOnlyUnresolved(t *testing.T) {
	r := newTestResolver(map[string]ref{"10.0.0.1": {name: "web", namespace: "shop"}})

	// Both endpoints resolvable at ingest -> nothing to catch up.
	r.enrich(&api.Entry{ID: "a", Source: api.Endpoint{IP: "10.0.0.1"}, Destination: api.Endpoint{IP: "10.0.0.1"}})
	if len(r.pending) != 0 {
		t.Fatalf("resolved entry tracked: pending = %d, want 0", len(r.pending))
	}

	// Bare source IP the resolver doesn't know yet -> tracked for catch-up.
	r.enrich(&api.Entry{ID: "b", Source: api.Endpoint{IP: "10.9.9.9"}})
	if _, ok := r.pending["b"]; !ok {
		t.Fatal("unresolved entry not tracked for catch-up")
	}
}

// TestResolverCatchUp is the core HUB-6 path: an entry ingested before its pod
// was known keeps a bare IP, then the next refresh's catch-up re-resolves it
// once the resolver learns the mapping — delivering a corrected *copy* through
// onResolved and leaving the store-shared original untouched.
func TestResolverCatchUp(t *testing.T) {
	r := newTestResolver(map[string]ref{
		"10.0.0.2": {name: "pg-0", namespace: "db", workload: "pg"},
	})
	var corrected []*api.Entry
	r.onResolved = func(e *api.Entry) { corrected = append(corrected, e) }

	// Ingested before the source pod (10.0.0.5) exists: dst resolves, src bare.
	e := &api.Entry{
		ID:          "e1",
		Source:      api.Endpoint{IP: "10.0.0.5", Port: 5000},
		Destination: api.Endpoint{IP: "10.0.0.2", Port: 5432},
	}
	r.enrich(e)
	if e.Source.Name != "" {
		t.Fatalf("source resolved too early: %q", e.Source.Name)
	}
	if e.Destination.Name != "pg-0" {
		t.Fatalf("dest = %q, want pg-0", e.Destination.Name)
	}
	if got := len(r.pending); got != 1 {
		t.Fatalf("pending = %d, want 1 (source still bare)", got)
	}

	// The source pod appears; the next refresh's catch-up must resolve it.
	r.learn("10.0.0.5", ref{name: "cart-xyz", namespace: "shop", workload: "cart"})
	if n := r.retryPending(); n != 1 {
		t.Fatalf("retryPending resolved %d, want 1", n)
	}
	if r.lateResolved() != 1 {
		t.Fatalf("lateResolved() = %d, want 1", r.lateResolved())
	}
	if len(r.pending) != 0 {
		t.Fatalf("pending = %d after catch-up, want 0 (fully resolved)", len(r.pending))
	}

	// Shared-pointer safety: the stored/original entry must NOT be mutated —
	// the correction is applied to a copy the store's readers never touch.
	if e.Source.Name != "" {
		t.Errorf("catch-up mutated the shared entry in place (source=%q); must correct a copy", e.Source.Name)
	}
	if len(corrected) != 1 {
		t.Fatalf("onResolved fired %d times, want 1", len(corrected))
	}
	c := corrected[0]
	if c == e {
		t.Error("onResolved received the shared entry pointer, want a copy")
	}
	if c.Source.Name != "cart-xyz" || c.Source.Namespace != "shop" || c.Source.Workload != "cart" {
		t.Errorf("corrected source = %q/%q/%q, want cart-xyz/shop/cart",
			c.Source.Name, c.Source.Namespace, c.Source.Workload)
	}
	if c.Destination.Name != "pg-0" {
		t.Errorf("corrected dest = %q, want pg-0 (carried from ingest)", c.Destination.Name)
	}
}

// TestResolverCatchUpNilSeam: with no onResolved seam wired (the default),
// catch-up still performs its bookkeeping — detecting the resolution, counting
// it, and clearing the entry from the registry — without mutating the shared
// entry.
func TestResolverCatchUpNilSeam(t *testing.T) {
	r := newTestResolver(map[string]ref{})
	e := &api.Entry{ID: "e1", Source: api.Endpoint{IP: "10.0.0.7"}}
	r.enrich(e)
	if len(r.pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(r.pending))
	}
	r.learn("10.0.0.7", ref{name: "api-1", namespace: "shop", workload: "api"})
	if n := r.retryPending(); n != 1 {
		t.Fatalf("retryPending resolved %d, want 1", n)
	}
	if len(r.pending) != 0 || r.lateResolved() != 1 {
		t.Fatalf("bookkeeping off: pending=%d lateResolved=%d", len(r.pending), r.lateResolved())
	}
	if e.Source.Name != "" {
		t.Errorf("shared entry mutated with nil seam: source=%q", e.Source.Name)
	}
}

// TestResolverCatchUpAgesOut: an entry whose IP never becomes known (an external
// address) is dropped from the registry after maxResolveAttempts cycles and
// never reported as resolved.
func TestResolverCatchUpAgesOut(t *testing.T) {
	r := newTestResolver(map[string]ref{}) // nothing ever resolves
	fired := 0
	r.onResolved = func(*api.Entry) { fired++ }

	r.enrich(&api.Entry{ID: "ext", Source: api.Endpoint{IP: "8.8.8.8"}})
	if len(r.pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(r.pending))
	}
	for i := 0; i < maxResolveAttempts-1; i++ {
		r.retryPending()
		if len(r.pending) != 1 {
			t.Fatalf("dropped too early after %d attempts", i+1)
		}
	}
	r.retryPending() // maxResolveAttempts-th cycle without progress: aged out
	if len(r.pending) != 0 {
		t.Fatalf("pending = %d, want 0 after %d attempts", len(r.pending), maxResolveAttempts)
	}
	if fired != 0 || r.lateResolved() != 0 {
		t.Errorf("unresolvable IP reported resolved (fired=%d, lateResolved=%d)", fired, r.lateResolved())
	}
}

// TestResolverPendingCap: the catch-up registry is bounded — entries past
// maxPendingResolve are dropped rather than growing it without limit.
func TestResolverPendingCap(t *testing.T) {
	r := &resolver{pending: map[string]*pendingResolve{}}
	for i := 0; i < maxPendingResolve; i++ {
		r.trackPending(&api.Entry{ID: fmt.Sprintf("e%d", i), Source: api.Endpoint{IP: "10.1.2.3"}})
	}
	if len(r.pending) != maxPendingResolve {
		t.Fatalf("pending = %d, want %d", len(r.pending), maxPendingResolve)
	}
	r.trackPending(&api.Entry{ID: "overflow", Source: api.Endpoint{IP: "10.1.2.3"}})
	if len(r.pending) != maxPendingResolve {
		t.Fatalf("cap breached: pending = %d, want %d", len(r.pending), maxPendingResolve)
	}
	if _, ok := r.pending["overflow"]; ok {
		t.Error("entry added past the registry cap")
	}
}

// trackPending must not touch the catch-up registry at all for an entry that
// resolved at ingest — that is the common case, and taking the registry's
// exclusive lock for it serialised every worker-connection goroutine against
// every other. A zero-value resolver (nil pending map) makes the shortcut
// observable: reaching the locked section would allocate the map.
func TestTrackPendingSkipsRegistryForResolvedEntries(t *testing.T) {
	r := &resolver{} // pending == nil
	r.trackPending(&api.Entry{ID: "resolved", Source: api.Endpoint{IP: "10.0.0.1", Name: "web"}})
	r.trackPending(&api.Entry{ID: "no-ips"})
	if r.pending != nil {
		t.Errorf("a fully-resolved entry entered the catch-up registry (%d entries)", len(r.pending))
	}
	// An unresolved one still gets tracked (and lazily creates the registry).
	r.trackPending(&api.Entry{ID: "bare", Source: api.Endpoint{IP: "10.9.9.9"}})
	if _, ok := r.pending["bare"]; !ok {
		t.Error("unresolved entry not tracked for catch-up")
	}
}

// enrich runs concurrently on every worker connection's read goroutine while
// the refresh goroutine republishes byIP. The snapshot is swapped atomically
// and never mutated in place, so this must be race-free (run under -race) and
// a reader holding the previous snapshot must keep seeing consistent data.
func TestResolverEnrichConcurrentWithRefresh(t *testing.T) {
	r := newTestResolver(map[string]ref{"10.0.0.1": {name: "web-0", namespace: "shop", workload: "web"}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			r.setByIP(map[string]ref{
				"10.0.0.1": {name: "web-" + itoa(i), namespace: "shop", workload: "web"},
			})
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				e := &api.Entry{
					ID:          fmt.Sprintf("g%d-%d", g, i),
					Source:      api.Endpoint{IP: "10.0.0.1"},
					Destination: api.Endpoint{IP: "10.9.9.9"},
				}
				r.enrich(e)
				// Whatever snapshot was read, the identity must be coherent:
				// never a half-published mix of name and workload.
				if !strings.HasPrefix(e.Source.Name, "web-") || e.Source.Workload != "web" {
					t.Errorf("incoherent enrichment: %q/%q", e.Source.Name, e.Source.Workload)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	<-done
}

// The list calls must ask for the apiserver's cached view (resourceVersion=0)
// instead of forcing a quorum etcd read every cycle, must drop it once they are
// following a continue token (the apiserver rejects the combination with 400),
// and must ask for metadata-only ReplicaSets — the decoder reads nothing but
// ObjectMeta, while a full list ships every RS's embedded pod template. This
// also pins that a PartialObjectMetadataList response still decodes into the
// ReplicaSet -> Deployment owner map.
func TestResolverListRequestShape(t *testing.T) {
	type seenReq struct{ query, accept string }
	var mu sync.Mutex
	seen := map[string][]seenReq{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seen[req.URL.Path] = append(seen[req.URL.Path], seenReq{req.URL.RawQuery, req.Header.Get("Accept")})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/apis/apps/v1/replicasets":
			// Two pages, in the PartialObjectMetadataList shape the Accept
			// header asks for (items reduced to their metadata).
			if req.URL.Query().Get("continue") == "" {
				_, _ = w.Write([]byte(`{"kind":"PartialObjectMetadataList","apiVersion":"meta.k8s.io/v1",
					"metadata":{"continue":"tok1","resourceVersion":"12"},
					"items":[{"kind":"PartialObjectMetadata","apiVersion":"meta.k8s.io/v1",
						"metadata":{"name":"web-7d9f4b","namespace":"shop",
							"ownerReferences":[{"kind":"Deployment","name":"web"}]}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"kind":"PartialObjectMetadataList","apiVersion":"meta.k8s.io/v1",
				"metadata":{"resourceVersion":"12"},
				"items":[{"kind":"PartialObjectMetadata","apiVersion":"meta.k8s.io/v1",
					"metadata":{"name":"api-1a2b3c","namespace":"shop",
						"ownerReferences":[{"kind":"Deployment","name":"api"}]}}]}`))
		case "/api/v1/pods":
			_, _ = w.Write([]byte(`{"metadata":{},"items":[
				{"metadata":{"name":"web-7d9f4b-x2x4v","namespace":"shop",
					"ownerReferences":[{"kind":"ReplicaSet","name":"web-7d9f4b"}]},
				 "spec":{},"status":{"podIP":"10.0.0.1"}}]}`))
		case "/api/v1/services":
			_, _ = w.Write([]byte(`{"metadata":{},"items":[
				{"metadata":{"name":"payments","namespace":"shop"},"spec":{"clusterIP":"10.96.0.10"}}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := &resolver{log: slog.Default(), client: srv.Client(), api: srv.URL, token: "x"}
	r.refresh(context.Background())

	if got := r.failures(); got != 0 {
		t.Fatalf("failures() = %d, want 0 (the fake apiserver answered everything)", got)
	}
	// The RS owner map came from the metadata-only pages, across both of them.
	if rf, ok := r.ipRef("10.0.0.1"); !ok || rf.workload != "web" || rf.name != "web-7d9f4b-x2x4v" {
		t.Errorf("pod enrichment = %+v (ok=%v), want workload web from the PartialObjectMetadataList", rf, ok)
	}
	if rf, ok := r.ipRef("10.96.0.10"); !ok || rf.name != "payments" {
		t.Errorf("service enrichment = %+v (ok=%v), want payments", rf, ok)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/apis/apps/v1/replicasets", "/api/v1/pods", "/api/v1/services"} {
		reqs := seen[path]
		if len(reqs) == 0 {
			t.Fatalf("%s was never listed", path)
		}
		if !strings.Contains(reqs[0].query, "resourceVersion=0") {
			t.Errorf("%s first page query = %q, want resourceVersion=0 (serve from the watch cache)", path, reqs[0].query)
		}
		for i, rq := range reqs[1:] {
			if !strings.Contains(rq.query, "continue=") {
				t.Errorf("%s page %d = %q, want a continue token", path, i+2, rq.query)
			}
			if strings.Contains(rq.query, "resourceVersion=") {
				t.Errorf("%s page %d = %q: resourceVersion alongside continue is a 400", path, i+2, rq.query)
			}
		}
	}
	if len(seen["/apis/apps/v1/replicasets"]) != 2 {
		t.Errorf("replicasets fetched in %d pages, want 2 (the continue token must be followed)",
			len(seen["/apis/apps/v1/replicasets"]))
	}
	if got := seen["/apis/apps/v1/replicasets"][0].accept; got != metadataOnlyAccept {
		t.Errorf("replicasets Accept = %q, want %q", got, metadataOnlyAccept)
	}
	// Pods and services are decoded for spec/status too, so they must keep
	// asking for the full object.
	for _, path := range []string{"/api/v1/pods", "/api/v1/services"} {
		if got := seen[path][0].accept; got != "application/json" {
			t.Errorf("%s Accept = %q, want application/json (spec/status are read)", path, got)
		}
	}
}

// workloadOf resolves pod owners: ReplicaSet -> Deployment (via the RS map,
// or by stripping the pod-template hash when the map is missing), direct
// controllers by name, bare pods to themselves.
func TestWorkloadOf(t *testing.T) {
	owner := func(kind, name string) objMeta {
		m := objMeta{Name: "pod-x", Namespace: "shop"}
		m.OwnerReferences = append(m.OwnerReferences, struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		}{kind, name})
		return m
	}
	rsOwners := map[string]string{"shop/web-7d9f4b": "web"}

	if got := workloadOf(owner("ReplicaSet", "web-7d9f4b"), rsOwners); got != "web" {
		t.Errorf("RS via map = %q, want web", got)
	}
	if got := workloadOf(owner("ReplicaSet", "api-5c9d8e"), nil); got != "api" {
		t.Errorf("RS via hash-strip = %q, want api", got)
	}
	if got := workloadOf(owner("StatefulSet", "pg"), nil); got != "pg" {
		t.Errorf("StatefulSet = %q, want pg", got)
	}
	if got := workloadOf(owner("DaemonSet", "fluentd"), nil); got != "fluentd" {
		t.Errorf("DaemonSet = %q, want fluentd", got)
	}
	if got := workloadOf(objMeta{Name: "one-off", Namespace: "shop"}, nil); got != "one-off" {
		t.Errorf("bare pod = %q, want one-off", got)
	}
}
