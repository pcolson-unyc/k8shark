package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pablocolson/k8shark/pkg/api"
)

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// enrichInterval is how often the IP -> identity map is rebuilt.
	enrichInterval = 20 * time.Second
	// maxPendingResolve bounds the catch-up registry (see trackPending) so a
	// steady stream of external / never-cluster IPs can't grow it without limit;
	// past this the newest unresolved entries are simply not tracked.
	maxPendingResolve = 8192
	// maxResolveAttempts is how many refresh cycles an entry waits in the
	// catch-up registry before being dropped as unresolvable (an external IP
	// never enters byIP). At enrichInterval=20s that is ~2 minutes.
	maxResolveAttempts = 6
)

// pendingResolve is a buffered entry still carrying a bare endpoint IP, awaiting a
// late IP -> identity resolution, with the count of refresh cycles it has waited
// (dropped after maxResolveAttempts).
type pendingResolve struct {
	e        *api.Entry
	attempts int
}

// ref is the resolved k8s identity behind an IP (a pod or a service).
type ref struct {
	name      string
	namespace string
	// workload is the owning controller (Deployment/StatefulSet/...): a stable
	// label where name churns with every pod restart. For services it is the
	// service name itself.
	workload string
}

// resolver maps pod/service IPs to their k8s identity by periodically listing
// the in-cluster API, so captured endpoints show a workload name instead of a
// bare IP. It is dependency-free (no client-go): it reads the mounted
// service-account token/CA and polls the REST API (the same hand-rolled style
// as internal/mcp). When not running in a cluster (no token) it is a no-op, so
// the hub still runs in local dev — endpoints simply keep their ip:port.
type resolver struct {
	log    *slog.Logger
	api    string
	token  string
	client *http.Client

	// byIP is the IP -> identity snapshot. It is only ever *replaced* wholesale
	// by refresh (never mutated in place, so a reader can safely keep reading
	// the map it loaded), which makes an atomic pointer swap the exact fit: the
	// two RWMutex RLocks enrich() used to take per entry — on the path every
	// captured packet's entry crosses — become two atomic loads with no
	// cross-core cacheline ping-pong between concurrent worker connections.
	byIP atomic.Pointer[map[string]ref]

	// pmu guards pending, and nothing else: catch-up bookkeeping must never
	// contend with the hot enrich() path (which now reads byIP lock-free).
	pmu sync.Mutex
	// pending is the catch-up registry: entries whose endpoint IP wasn't known
	// at ingest, keyed by entry ID, so a later refresh can re-run enrichment
	// once the resolver learns the mapping (e.g. a pod created after the entry
	// was captured). See trackPending / retryPending.
	pending map[string]*pendingResolve

	// onResolved, when non-nil, receives a freshly-enriched *copy* of an entry
	// whose previously-bare endpoint IP the resolver has now learned (see
	// retryPending). It is the seam through which a caller applies the late
	// correction *safely*. The resolver must never mutate the entry the ring
	// buffer holds: store.go marks entries immutable-after-add and the REST read
	// paths marshal those pointers with no lock held, so an in-place write here
	// would data-race concurrent readers. The catch-up therefore hands back a
	// copy and leaves applying it (a store.mu-guarded slot swap + re-broadcast,
	// which lives in store.go / server.go) to the caller. Left nil — the default
	// — the catch-up performs detection and bookkeeping only.
	onResolved func(*api.Entry)

	// refreshFailures counts refresh() cycles that gave up without updating
	// byIP (a failed/partial API call — see refresh), exposed via /metrics so
	// a broken RBAC binding shows up as a rising counter instead of silently
	// stale enrichment.
	refreshFailures atomic.Int64

	// resolvedLate counts endpoints the catch-up re-resolved after their
	// pod/service became known post-ingest (see retryPending).
	resolvedLate atomic.Int64
}

func newResolver(log *slog.Logger) *resolver {
	r := &resolver{log: log, pending: map[string]*pendingResolve{}}
	r.setByIP(map[string]ref{})
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	token, err := os.ReadFile(saTokenPath)
	if host == "" || err != nil {
		return r // not in-cluster: enrichment stays disabled
	}
	if port == "" {
		port = "443"
	}
	pool := x509.NewCertPool()
	if ca, caErr := os.ReadFile(saCAPath); caErr == nil {
		pool.AppendCertsFromPEM(ca)
	}
	r.api = "https://" + net.JoinHostPort(host, port)
	r.token = string(token)
	r.client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	return r
}

func (r *resolver) enabled() bool { return r.client != nil }

// failures returns the count of refresh cycles that gave up without updating
// byIP, since process start.
func (r *resolver) failures() int64 { return r.refreshFailures.Load() }

// lateResolved returns how many buffered entries the catch-up registry has
// re-resolved after their pod/service became known post-ingest, since start.
func (r *resolver) lateResolved() int64 { return r.resolvedLate.Load() }

// run rebuilds the IP map every enrichInterval until ctx is cancelled. A no-op
// when the resolver is disabled (not in a cluster).
func (r *resolver) run(ctx context.Context) {
	if !r.enabled() {
		r.log.Info("k8s endpoint enrichment disabled (not running in-cluster)")
		return
	}
	r.log.Info("k8s endpoint enrichment enabled")
	r.refresh(ctx)
	t := time.NewTicker(enrichInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refresh(ctx)
		}
	}
}

// refresh rebuilds byIP from a pods list plus a services list. On a failed or
// empty refresh it keeps the previous map rather than blanking enrichment.
//
// This is a full periodic re-list, not an incremental watch. The ROADMAP (HUB-6)
// also floats moving to the streaming watch API (?watch=true&resourceVersion=N)
// for near-zero resolution latency; that is deliberately deferred here as a much
// larger change (streaming event decode, bookmark/resourceVersion tracking,
// 410-Gone resync, and a watch goroutine per resource kind) that would not be a
// safe single-file edit. The periodic list stays as the map's source of truth;
// the catch-up registry (retryPending) closes the narrower gap the watch was
// meant to help — entries already buffered when their pod was still unknown.
func (r *resolver) refresh(ctx context.Context) {
	m := r.listPods(ctx, r.listReplicaSetOwners(ctx))
	if m == nil {
		r.refreshFailures.Add(1)
		return // request failed; keep the previous map
	}
	// Services fill ClusterIP gaps; pods win on any overlap (disjoint in practice).
	for ip, rf := range r.listServices(ctx) {
		if _, ok := m[ip]; !ok {
			m[ip] = rf
		}
	}
	r.setByIP(m)
	// Now that the map is fresh, re-run enrichment for entries that were bare at
	// ingest — a pod created between two refreshes is resolvable from this point.
	late := r.retryPending()
	r.log.Debug("k8s enrichment refreshed", "endpoints", len(m), "lateResolved", late)
}

// get performs an authenticated GET and decodes the JSON body into out. accept
// overrides the Accept header when non-empty (see metadataOnlyAccept).
func (r *resolver) get(ctx context.Context, path, accept string, out any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.api+path, nil)
	if err != nil {
		return false
	}
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Accept", accept)
	resp, err := r.client.Do(req)
	if err != nil {
		r.log.Warn("k8s enrichment request failed", "path", path, "err", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.log.Warn("k8s enrichment non-200", "path", path, "status", resp.StatusCode)
		return false
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		r.log.Warn("k8s enrichment decode failed", "path", path, "err", err)
		return false
	}
	return true
}

// listPageSize bounds each list request so a big cluster is fetched in pages
// instead of one giant response.
const listPageSize = 500

// objMeta is the metadata subset the resolver reads off any listed object.
type objMeta struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	OwnerReferences []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

// metadataOnlyAccept asks the apiserver to convert the response to a
// PartialObjectMetadataList — every item reduced to its ObjectMeta. The
// resolver decodes nothing but metadata (name/namespace/ownerReferences), yet a
// plain list ships each object's full spec: for ReplicaSets that means the
// entire embedded pod template on every object, megabytes per refresh cycle in
// a cluster with a few hundred of them. The trailing application/json keeps the
// full object as a fallback for an apiserver that won't do the conversion —
// both shapes decode identically here, since objMeta only ever reads
// "metadata" and the list envelope is the same either way.
const metadataOnlyAccept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1,application/json"

// listAll GETs a paginated list endpoint, following the continue token, and
// returns every item. accept, when non-empty, overrides the Accept header. ok
// is false when any page failed (callers then keep their previous state rather
// than working from a partial list).
func listAll[T any](ctx context.Context, r *resolver, path, accept string) (items []T, ok bool) {
	var page struct {
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
		Items []T `json:"items"`
	}
	cont := ""
	for {
		u := path + "?limit=" + strconv.Itoa(listPageSize)
		if cont == "" {
			// resourceVersion=0 means "any version you already have": the
			// apiserver serves the first page straight from its watch cache
			// instead of doing a quorum read against etcd. Three of those every
			// enrichInterval, per hub, is real etcd load for data that is
			// allowed to be a moment stale (a missed pod is picked up by the
			// next cycle, or by the catch-up registry). It is only valid on the
			// first page — passing it alongside a continue token is rejected
			// with 400, since the token already pins the resource version.
			u += "&resourceVersion=0"
		} else {
			u += "&continue=" + url.QueryEscape(cont)
		}
		page.Metadata.Continue = ""
		page.Items = nil
		if !r.get(ctx, u, accept, &page) {
			return nil, false
		}
		items = append(items, page.Items...)
		if page.Metadata.Continue == "" {
			return items, true
		}
		cont = page.Metadata.Continue
	}
}

// listReplicaSetOwners maps "namespace/replicaset-name" to the owning
// Deployment's name, so pods resolve to the stable Deployment rather than a
// hash-suffixed ReplicaSet. Best effort: on failure workloadOf falls back to
// stripping the pod-template hash off the ReplicaSet name.
func (r *resolver) listReplicaSetOwners(ctx context.Context) map[string]string {
	type rs struct {
		Metadata objMeta `json:"metadata"`
	}
	items, ok := listAll[rs](ctx, r, "/apis/apps/v1/replicasets", metadataOnlyAccept)
	if !ok {
		return nil
	}
	m := make(map[string]string, len(items))
	for _, it := range items {
		for _, o := range it.Metadata.OwnerReferences {
			if o.Kind == "Deployment" {
				m[it.Metadata.Namespace+"/"+it.Metadata.Name] = o.Name
				break
			}
		}
	}
	return m
}

// workloadOf resolves a pod's owning controller name. rsOwners may be nil.
func workloadOf(meta objMeta, rsOwners map[string]string) string {
	for _, o := range meta.OwnerReferences {
		switch o.Kind {
		case "ReplicaSet":
			if d, ok := rsOwners[meta.Namespace+"/"+o.Name]; ok {
				return d
			}
			// ReplicaSet names are "<deployment>-<pod-template-hash>"; stripping
			// the last segment recovers the Deployment when the RS list failed.
			if i := strings.LastIndexByte(o.Name, '-'); i > 0 {
				return o.Name[:i]
			}
			return o.Name
		case "StatefulSet", "DaemonSet", "Job":
			return o.Name
		}
	}
	return meta.Name // bare pod: the pod is its own workload
}

func (r *resolver) listPods(ctx context.Context, rsOwners map[string]string) map[string]ref {
	type pod struct {
		Metadata objMeta `json:"metadata"`
		Spec     struct {
			HostNetwork bool `json:"hostNetwork"`
		} `json:"spec"`
		Status struct {
			PodIP  string `json:"podIP"`
			PodIPs []struct {
				IP string `json:"ip"`
			} `json:"podIPs"`
		} `json:"status"`
	}
	items, ok := listAll[pod](ctx, r, "/api/v1/pods", "")
	if !ok {
		return nil
	}
	m := make(map[string]ref, len(items))
	for _, p := range items {
		if p.Spec.HostNetwork {
			continue // shares the node IP — ambiguous, skip
		}
		rf := ref{
			name:      p.Metadata.Name,
			namespace: p.Metadata.Namespace,
			workload:  workloadOf(p.Metadata, rsOwners),
		}
		if p.Status.PodIP != "" {
			m[p.Status.PodIP] = rf
		}
		for _, ip := range p.Status.PodIPs {
			if ip.IP != "" {
				m[ip.IP] = rf
			}
		}
	}
	return m
}

func (r *resolver) listServices(ctx context.Context) map[string]ref {
	type svc struct {
		Metadata objMeta `json:"metadata"`
		Spec     struct {
			ClusterIP  string   `json:"clusterIP"`
			ClusterIPs []string `json:"clusterIPs"`
		} `json:"spec"`
	}
	items, ok := listAll[svc](ctx, r, "/api/v1/services", "")
	if !ok {
		return nil
	}
	m := make(map[string]ref, len(items))
	for _, s := range items {
		rf := ref{name: s.Metadata.Name, namespace: s.Metadata.Namespace, workload: s.Metadata.Name}
		for _, ip := range append(s.Spec.ClusterIPs, s.Spec.ClusterIP) {
			if ip != "" && ip != "None" {
				m[ip] = rf
			}
		}
	}
	return m
}

// enrich fills Name/Namespace on the entry's endpoints from the IP map, when
// known and not already set. Safe to call when disabled (no-op). It also
// registers the entry for catch-up re-enrichment when an endpoint IP is still
// unresolved (see trackPending), so a pod that appears later still gets a name.
func (r *resolver) enrich(e *api.Entry) {
	if e == nil || !r.enabled() {
		return
	}
	r.enrichEndpoint(&e.Source)
	r.enrichEndpoint(&e.Destination)
	r.trackPending(e)
}

// setByIP publishes a freshly built IP map. The previous snapshot stays valid
// for any reader still holding it — nothing mutates a published map.
func (r *resolver) setByIP(m map[string]ref) { r.byIP.Store(&m) }

// ipRef looks ip up in the current snapshot.
func (r *resolver) ipRef(ip string) (ref, bool) {
	m := r.byIP.Load()
	if m == nil {
		return ref{}, false // never published (zero-value resolver in a test)
	}
	rf, ok := (*m)[ip]
	return rf, ok
}

func (r *resolver) enrichEndpoint(ep *api.Endpoint) {
	if ep.IP == "" {
		return
	}
	rf, ok := r.ipRef(ep.IP)
	if !ok {
		return
	}
	if ep.Name == "" {
		ep.Name, ep.Namespace = rf.name, rf.namespace
	}
	if ep.Workload == "" {
		ep.Workload = rf.workload
	}
}

// endpointUnresolved reports whether ep carries an IP the resolver could still
// put a name to (an IP is set but no name was filled). External IPs also match —
// they simply never become resolvable, and the attempts cap ages them out of
// the registry.
func endpointUnresolved(ep *api.Endpoint) bool {
	return ep.IP != "" && ep.Name == ""
}

// hasUnresolvedEntry reports whether either endpoint of e is still bare.
func hasUnresolvedEntry(e *api.Entry) bool {
	return endpointUnresolved(&e.Source) || endpointUnresolved(&e.Destination)
}

// trackPending records e in the catch-up registry when it still has a bare
// endpoint IP after enrich, so a later refresh can re-run enrichment once the
// resolver learns the mapping. Called from enrich, i.e. while the ingest
// goroutine still exclusively owns e; the registry only ever *reads* e's fields
// afterwards (retryPending copies before enriching), so retaining the pointer is
// safe against store.go's immutable-after-add contract. A fully resolved entry
// has nothing to track.
func (r *resolver) trackPending(e *api.Entry) {
	// Checked *before* taking pmu, which is the only exclusive lock the ingest
	// path touches (and so the only hard serialisation point between concurrent
	// worker-connection goroutines). In a cluster with working enrichment the
	// overwhelming majority of entries resolve at ingest and return right here,
	// never contending. The lock used to be taken unconditionally for a
	// delete(pending, e.ID) that can never hit: entry IDs are unique monotonic
	// counters and enrich() runs exactly once per entry, so an already-resolved
	// entry was never inserted in the first place. (And were an ID ever reused,
	// retryPending drops a tracked entry as soon as it fully resolves, so the
	// registry still self-heals.)
	if !hasUnresolvedEntry(e) {
		return
	}
	r.pmu.Lock()
	defer r.pmu.Unlock()
	if r.pending == nil {
		r.pending = map[string]*pendingResolve{}
	}
	if _, ok := r.pending[e.ID]; ok {
		return // already tracked; keep its accumulated attempts
	}
	if len(r.pending) >= maxPendingResolve {
		return // registry full: drop this one (see maxPendingResolve)
	}
	r.pending[e.ID] = &pendingResolve{e: e}
}

// retryPending re-runs enrichment against the freshly rebuilt byIP map for every
// tracked entry, and returns how many gained a name this cycle. It never mutates
// a tracked (store-shared) entry: for each one it enriches a *copy* and, when
// that copy resolved something new, hands the copy to onResolved for the caller
// to apply safely (see the onResolved field doc). Entries fully resolved, or
// that have waited maxResolveAttempts cycles without progress (presumed
// external), are dropped from the registry.
func (r *resolver) retryPending() int {
	r.pmu.Lock()
	if len(r.pending) == 0 {
		r.pmu.Unlock()
		return 0
	}
	pend := make([]*pendingResolve, 0, len(r.pending))
	for _, pe := range r.pending {
		pend = append(pend, pe)
	}
	r.pmu.Unlock()

	resolved := 0
	var drop []string
	for _, pe := range pend {
		// Read-only shallow copy of the shared entry, then enrich the copy only —
		// the original stays untouched (see the onResolved field doc for why).
		cp := *pe.e
		r.enrichEndpoint(&cp.Source)
		r.enrichEndpoint(&cp.Destination)
		progressed := (endpointUnresolved(&pe.e.Source) && !endpointUnresolved(&cp.Source)) ||
			(endpointUnresolved(&pe.e.Destination) && !endpointUnresolved(&cp.Destination))
		if progressed {
			resolved++
			r.resolvedLate.Add(1)
			if r.onResolved != nil {
				r.onResolved(&cp)
			}
		}
		if !hasUnresolvedEntry(&cp) {
			drop = append(drop, pe.e.ID) // fully resolved
			continue
		}
		// attempts is only ever touched from the single refresh goroutine that
		// drives retryPending, so it needs no extra synchronisation.
		pe.attempts++
		if pe.attempts >= maxResolveAttempts {
			drop = append(drop, pe.e.ID)
		}
	}

	if len(drop) > 0 {
		r.pmu.Lock()
		for _, id := range drop {
			delete(r.pending, id)
		}
		r.pmu.Unlock()
	}
	return resolved
}
