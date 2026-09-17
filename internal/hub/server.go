// Package hub is the central aggregator. Workers stream reconstructed entries
// into it over WebSocket; front-end clients subscribe (also over WebSocket) and
// receive a live, server-side-filtered feed plus periodic stats. A REST API
// exposes recent history for cold loads and for the CLI/MCP.
package hub

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pablocolson/k8shark/internal/config"
	"github.com/pablocolson/k8shark/pkg/api"
)

// Options configures a hub. The zero value is a working local-dev hub.
type Options struct {
	// UIDir, when non-empty, is a directory whose static files are served at
	// "/" (used for local runs; in-cluster the front is a separate nginx pod).
	UIDir string
	// APIToken, when non-empty, requires `Authorization: Bearer <token>` (or,
	// for browser WebSockets that cannot set headers, a
	// `Sec-WebSocket-Protocol: bearer.<token>` subprotocol or a ?token= query
	// param — prefer the subprotocol: a token in the URL leaks into access
	// logs, browser history and Referer headers) on /api/* and the WebSocket
	// endpoints. Empty keeps the API open (local dev, trusted clusters).
	APIToken string
	// WorkerToken, when non-empty, is required on /ws/worker instead of
	// APIToken — so a leaked read token can't inject forged entries into the
	// dashboard, and a worker credential can't read captured traffic. Empty
	// falls back to APIToken (single-token setups keep working).
	WorkerToken string
	// AdminToken, when non-empty, is required on mutating /api calls (e.g.
	// POST /api/workers/capture, which pauses capture cluster-wide) instead
	// of APIToken; it also grants read access. The front's nginx proxy only
	// injects APIToken, so setting this withholds control from dashboard
	// users. Empty falls back to APIToken.
	AdminToken string
	// BufferSize overrides the in-memory entry ring size (0 = default).
	BufferSize int
	// AllowedOrigins lists extra browser Origins granted API/WebSocket access
	// and CORS headers, on top of the same-origin default (Origin host ==
	// request Host). "*" restores the old allow-any behavior.
	AllowedOrigins []string
	// TLSCert/TLSKey are PEM file paths; when both are set the hub serves
	// HTTPS/wss instead of plain HTTP/ws, so captured traffic (including
	// eBPF-decrypted TLS bodies) and bearer tokens stop crossing the cluster
	// network in clear text. Empty keeps plain HTTP (local dev, or a service
	// mesh already providing mTLS).
	TLSCert string
	TLSKey  string
	// ExportFile / ExportWebhook (EXT-4) opt into the export sink: a copy of
	// every ingested entry is fanned out to a rotating JSONL file and/or a
	// batched webhook, for a SIEM/data-lake/log pipeline. Both empty (default)
	// disable it entirely (see internal/hub/export.go). ExportFileMaxBytes and
	// ExportWebhookInterval override the rotation/flush defaults (0 = default).
	ExportFile            string
	ExportFileMaxBytes    int64
	ExportWebhook         string
	ExportWebhookInterval time.Duration
}

// Server is the hub. Construct with New and start with Run.
type Server struct {
	aggMu         sync.Mutex
	aggCache      map[string]aggCacheEntry
	aggCacheBytes int
	store         *store
	log           *slog.Logger
	upgrader      websocket.Upgrader
	apiToken      string
	workerToken   string
	adminToken    string
	allowOrigins  []string
	tlsCert       string
	tlsKey        string

	mu           sync.RWMutex
	frontClients map[*frontClient]struct{}
	workerCount  int32
	// frontCount mirrors len(frontClients), maintained at the register and
	// unregister sites so the per-entry broadcast fast path can test "is
	// anyone listening?" without taking mu. See broadcast for why reading it
	// lock-free is safe.
	frontCount atomic.Int32

	// wmu guards workers (the per-node registry behind /api/workers) and
	// workerConns (live connections' send channels, used to deliver
	// pause/resume commands). Separate from mu so per-entry bookkeeping
	// never contends with the broadcast path.
	wmu         sync.Mutex
	workers     map[string]*workerEntry
	workerConns map[string]chan []byte

	broadcastDropped int64 // entries dropped to slow front clients (atomic)

	// bmu guards pending, the entries accumulated between fan-out flushes.
	// broadcast appends here and arms a one-shot flush timer; flushBroadcast
	// drains it into one MsgEntryBatch frame per client (see broadcast).
	bmu     sync.Mutex
	pending []pendingEntry

	resolver *resolver // k8s IP -> pod/service name enrichment (no-op off-cluster)

	exporter *exporter // optional EXT-4 export sink (nil when unconfigured)

	uiDir string // optional: serve a built front from here (local dev)

	statsHistMu sync.RWMutex
	statsHist   []api.StatsPoint // rolling throughput history, capped at statsHistoryCap
}
type aggCacheEntry struct {
	body []byte
	at   time.Time
}

const aggCacheTTL = time.Second

func (s *Server) cachedAgg(key string, build func() ([]byte, error)) ([]byte, error) {
	// Serialize aggregate builds across keys as well as coalescing identical
	// requests. Ingestion only shares the store's brief snapshot lock, not this
	// cache lock. Bodies are immutable after insertion.
	s.aggMu.Lock()
	defer s.aggMu.Unlock()
	now := time.Now()
	if s.aggCache != nil {
		if v, ok := s.aggCache[key]; ok && now.Sub(v.at) < aggCacheTTL {
			return v.body, nil
		}
	}
	b, err := build()
	if err != nil || len(b) > 4<<20 {
		return b, err
	}
	if s.aggCache == nil {
		s.aggCache = map[string]aggCacheEntry{}
	}
	if old, ok := s.aggCache[key]; ok {
		s.aggCacheBytes -= len(old.body)
		delete(s.aggCache, key)
	}
	for (len(s.aggCache) >= 32 || s.aggCacheBytes+len(b) > 4<<20) && len(s.aggCache) > 0 {
		for k := range s.aggCache {
			s.aggCacheBytes -= len(s.aggCache[k].body)
			delete(s.aggCache, k)
			break
		}
	}
	s.aggCache[key] = aggCacheEntry{b, now}
	s.aggCacheBytes += len(b)
	return b, nil
}
func writeCachedJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// statsHistoryCap bounds the rolling stats history: at the statsLoop's 2s
// sample interval this covers 10 minutes, enough for a "requests/sec" trend
// sparkline without unbounded growth.
const statsHistoryCap = 300

// workerGCTTL bounds how long a disconnected worker's row survives in the
// registry after it was last seen. Without this, an autoscaling or spot-node
// cluster that churns through node names accumulates stale rows (and their
// per-node Prometheus series) in /api/workers forever. A currently-connected
// worker is never pruned regardless of LastSeen; the window is kept
// generous enough that "the worker was here, went away N minutes ago" stays
// answerable during an incident.
const workerGCTTL = time.Hour

// workerReadLimit bounds the per-message allocation on a worker connection.
// It is deliberately larger than the front-end limit: a worker coalesces
// whatever is already queued into one MsgEntryBatch frame (see
// sinkBatchMaxBytes in internal/worker/sink.go, currently 512 KiB), and a frame
// over this limit doesn't get truncated — gorilla fails the read and the
// connection dies, so an undersized limit here reads as a worker that
// reconnects forever under load. The margin over the worker's own budget covers
// a single pathological entry, which the worker always includes rather than
// dropping captured traffic to stay under budget.
const workerReadLimit = 4 << 20

// New builds a hub.
func New(log *slog.Logger, opts Options) *Server {
	size := opts.BufferSize
	if size <= 0 {
		size = config.EntryBufferSize
	}
	s := &Server{
		store:        newStore(size),
		log:          log,
		apiToken:     opts.APIToken,
		workerToken:  opts.WorkerToken,
		adminToken:   opts.AdminToken,
		allowOrigins: opts.AllowedOrigins,
		tlsCert:      opts.TLSCert,
		tlsKey:       opts.TLSKey,
		frontClients: map[*frontClient]struct{}{},
		workers:      map[string]*workerEntry{},
		workerConns:  map[string]chan []byte{},
		resolver:     newResolver(log),
		uiDir:        opts.UIDir,
		// EnableCompression is deliberately left off. permessage-deflate was
		// evaluated and rejected on measurement, not on principle — recorded
		// here so it doesn't get re-litigated every time someone notices the
		// entries are JSON:
		//
		//   realistic HTTP entry, post RawView.Data:  5747 B
		//   deflated (level -1, writer reused):        749 B  (7.67x)
		//   marginal CPU, writer reused via Reset:    30.6 us/entry
		//
		// 30.6 us/entry is 6.1% of a core per subscribed client at 2000
		// entries/s — and it burns on the fan-out goroutine, i.e. exactly the
		// one being unblocked. Two viewers exceed the hub's whole 100m CPU
		// request (helm/k8shark/values.yaml). The ratio also fell from the
		// ~12x measured before RawView.Data, because the pre-rendered hexdump
		// text that used to dominate every entry was the highly compressible
		// part; shrinking the payload took most of compression's prize with it.
		// Meanwhile the genuinely large responses are the REST ones, and nginx
		// now gzips those (build/nginx.conf.template) off the hot path.
		//
		// Enabling it would also invalidate the shared-batch-bytes optimisation
		// in flushBroadcast, since gorilla mutates the payload when compressing.
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
		},
	}
	s.exporter = newExporter(log, ExportOptions{
		File:            opts.ExportFile,
		FileMaxBytes:    opts.ExportFileMaxBytes,
		Webhook:         opts.ExportWebhook,
		WebhookInterval: opts.ExportWebhookInterval,
	})
	// Same-origin by default (plus the --allow-origin list): during a
	// port-forward without a token — the default — an allow-any policy would
	// let any web page open in the operator's browser open the WS and exfiltrate
	// the cluster's captured traffic. Non-browser clients send no Origin and
	// are unaffected; in-cluster the nginx front and the vite dev proxy both
	// preserve a matching Host, so same-origin holds there too.
	s.upgrader.CheckOrigin = s.originAllowed
	return s
}

// handler builds the fully-wrapped HTTP handler (route mux + auth + CORS) the
// hub serves. Split out of Run so tests can mount the real route tree — WS
// endpoints included — on an httptest.Server without binding a port.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/worker", s.handleWorker)
	mux.HandleFunc("/ws", s.handleFront)
	mux.HandleFunc("/api/entries", s.handleEntries)
	mux.HandleFunc("/api/entry/", s.handleEntry)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stats/history", s.handleStatsHistory)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/timeline", s.handleTimeline)
	mux.HandleFunc("/api/graph", s.handleGraph)
	mux.HandleFunc("/api/pcap", s.handlePcap)
	mux.HandleFunc("/api/workers", s.handleWorkers)
	mux.HandleFunc("/api/workers/capture", s.handleWorkerCapture)
	mux.HandleFunc("/api/fields", s.handleFields)
	mux.HandleFunc("/api/fields/", s.handleFieldValues)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if s.uiDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(s.uiDir)))
	}
	return s.withCORS(s.withAuth(mux))
}

// Run serves until ctx is cancelled (e.g. SIGINT/SIGTERM), then drains
// in-flight requests via a bounded graceful shutdown.
func (s *Server) Run(ctx context.Context, addr string) error {
	go s.statsLoop(ctx)
	go s.resolver.run(ctx)
	if s.exporter != nil {
		go s.exporter.run(ctx)
	}

	useTLS := s.tlsCert != "" && s.tlsKey != ""
	s.log.Info("hub listening", "addr", addr, "ui", s.uiDir != "", "auth", s.apiToken != "", "tls", useTLS, "export", s.exporter != nil)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("hub shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		s.stopExporter()
		return err
	}
}

// stopExporter waits for the export drain goroutine to flush and exit after ctx
// cancellation, bounded so a wedged sink can't hold shutdown open indefinitely.
func (s *Server) stopExporter() {
	if s.exporter == nil {
		return
	}
	select {
	case <-s.exporter.done:
	case <-time.After(exportShutdownTimeout):
		s.log.Warn("export drain did not finish before shutdown deadline")
	}
}

// --- worker channel --------------------------------------------------------

// workerInfo is one row of the /api/workers registry: a worker's lifecycle
// plus its self-reported counters, kept after disconnect so "worker was here,
// went away 2 min ago" is answerable during an incident.
type workerInfo struct {
	Node          string    `json:"node"`
	Version       string    `json:"version,omitempty"`
	Connected     bool      `json:"connected"`
	ConnectedAt   time.Time `json:"connectedAt"`
	LastSeen      time.Time `json:"lastSeen"`
	Entries       int64     `json:"entries"`       // entries the hub received from this worker
	Dropped       uint64    `json:"dropped"`       // worker-reported sink-buffer drops
	CaptureLive   bool      `json:"captureLive"`   // AF_PACKET source active on the worker
	CaptureTLS    bool      `json:"captureTls"`    // eBPF TLS capture active on the worker
	CapturePaused bool      `json:"capturePaused"` // hub told this worker to stop turning capture into entries
	RingPackets   uint64    `json:"ringPackets"`   // AF_PACKET kernel ring: cumulative packets delivered
	RingDrops     uint64    `json:"ringDrops"`     // AF_PACKET kernel ring: cumulative packets dropped before userspace saw them
	FlowsEvicted  uint64    `json:"flowsEvicted"`  // generic L4 flows dropped by the worker's maxFlows cap
	TLSLagDrops   uint64    `json:"tlsLagDrops"`   // eBPF TLS streams truncated after a backpressure drop
	TCPLossEvents uint64    `json:"tcpLossEvents"` // AF_PACKET TCP directions truncated after a lost segment (FIFO desync guard)
}

// workerEntry is the registry's internal row. The cold fields live in info,
// guarded by wmu; the two counters the ingest path touches for *every* entry
// are atomics next to it, so that path never takes a mutex. A plain
// sync.Mutex is fine at today's worker counts, but it is the wrong shape for a
// lock every worker pod's read goroutine hits per entry — at 50+ nodes the
// contention grows with the fleet even though the work is per-node bookkeeping
// that never needs to be serialised across nodes.
type workerEntry struct {
	info workerInfo // guarded by Server.wmu

	entries  atomic.Int64 // entries ingested from this worker
	lastSeen atomic.Int64 // unix nanos of the last ingested entry; 0 = none yet
}

// snapshot folds the atomics back into a plain workerInfo for JSON/metrics.
// info.Entries is *added* to rather than replaced: the ingest path only ever
// touches the atomic, so info.Entries is normally 0, but workerUpdate exposes
// the field and tests seed it directly — summing keeps both visible instead of
// silently discarding one.
func (we *workerEntry) snapshot() workerInfo {
	info := we.info
	info.Entries += we.entries.Load()
	info.LastSeen = we.lastSeenTime()
	return info
}

// lastSeenTime is the later of the wmu-guarded LastSeen (hello, worker stats,
// tests) and the ingest path's atomic one.
func (we *workerEntry) lastSeenTime() time.Time {
	if ns := we.lastSeen.Load(); ns != 0 {
		if t := time.Unix(0, ns); t.After(we.info.LastSeen) {
			return t
		}
	}
	return we.info.LastSeen
}

// ingest runs one entry through the full worker-side path: k8s enrichment,
// then the store (which assigns Seq and caches the marshaled JSON), then
// fan-out and export off that same cached JSON so neither re-marshals.
// Shared by the MsgEntry and MsgEntryBatch branches so a batched entry can
// never take a different path from an unbatched one.
func (s *Server) ingest(e *api.Entry) {
	s.resolver.enrich(e)
	raw := s.store.add(e)
	s.broadcast(e, raw)
	s.exporter.export(raw) // nil-safe; no-op when export unconfigured
}

// recordWorkerEntries credits n entries to a worker's registry row. Lock-free:
// this is per-connection state that nothing needs serialised across workers.
// A nil row is a pre-hello connection, which isn't tracked at all.
func recordWorkerEntries(row *workerEntry, n int) {
	if row == nil || n == 0 {
		return
	}
	row.entries.Add(int64(n))
	row.lastSeen.Store(time.Now().UnixNano())
}

func (s *Server) handleWorker(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, wsUpgradeHeader(r))
	if err != nil {
		s.log.Warn("worker upgrade failed", "err", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(workerReadLimit)

	atomic.AddInt32(&s.workerCount, 1)
	defer atomic.AddInt32(&s.workerCount, -1)

	// send carries commands (pause/resume) down to this worker; workerWriter
	// drains it concurrently with the read loop below so a command can go
	// out at any time without waiting on (or blocking) message reads.
	send := make(chan []byte, 8)
	go s.workerWriter(conn, send)

	node := "unknown"
	// row is this connection's registry row, resolved once at hello so the
	// per-entry bookkeeping below is two atomic stores rather than a map
	// lookup under a global mutex. nil until hello arrives (a pre-hello
	// connection isn't tracked at all — see workerRow).
	var row *workerEntry
	defer func() {
		s.workerUpdate(node, func(wi *workerInfo) { wi.Connected = false })
		s.wmu.Lock()
		// Only remove if this connection's channel is still the registered
		// one — a reconnect for the same node may have already replaced it.
		if s.workerConns[node] == send {
			delete(s.workerConns, node)
		}
		s.wmu.Unlock()
		close(send)
	}()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			s.log.Debug("worker disconnected", "node", node, "err", err)
			return
		}
		var env api.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		switch env.Type {
		case api.MsgHello:
			if env.Hello != nil {
				node = env.Hello.Node
				version := env.Hello.Version
				s.log.Info("worker connected", "node", node, "version", version)
				now := time.Now()
				row = s.workerRow(node)
				s.workerUpdate(node, func(wi *workerInfo) {
					wi.Version = version
					wi.Connected = true
					wi.ConnectedAt = now
					wi.LastSeen = now
				})
				s.wmu.Lock()
				s.workerConns[node] = send
				s.wmu.Unlock()
			}
		case api.MsgEntry:
			if env.Entry != nil {
				s.ingest(env.Entry)
				recordWorkerEntries(row, 1)
			}
		case api.MsgEntryBatch:
			// A batch is semantically identical to its entries arriving as
			// individual MsgEntry frames, oldest first — the worker only
			// coalesces what was already queued (see sink.assembleBatch). The
			// per-connection bookkeeping is hoisted out of the loop: it is the
			// whole batch's worth of work reported once, not per entry.
			n := 0
			for _, e := range env.Entries {
				if e == nil {
					continue
				}
				s.ingest(e)
				n++
			}
			recordWorkerEntries(row, n)
		case api.MsgWorkerStats:
			if ws := env.WorkerStats; ws != nil {
				s.workerUpdate(node, func(wi *workerInfo) {
					wi.Dropped = ws.Dropped
					wi.CaptureLive = ws.CaptureLive
					wi.CaptureTLS = ws.CaptureTLS
					wi.CapturePaused = ws.CapturePaused
					wi.RingPackets = ws.RingPackets
					wi.RingDrops = ws.RingDrops
					wi.FlowsEvicted = ws.FlowsEvicted
					wi.TLSLagDrops = ws.TLSLagDrops
					wi.TCPLossEvents = ws.TCPLossEvents
					wi.LastSeen = time.Now()
				})
			}
		}
	}
}

// workerWriter drains send to conn until the channel closes (worker
// disconnected) or a write fails (dead connection — the read loop's next
// ReadMessage will notice and tear things down).
func (s *Server) workerWriter(conn *websocket.Conn, send chan []byte) {
	for b := range send {
		if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
			return
		}
	}
}

// sendWorkerCommand delivers cmd to node's connection, or to every currently
// connected worker when node is "". Returns how many it reached — 0 for an
// unknown/disconnected node is a normal, silent no-op (the front end's
// toggle reflects registry state, not a per-call delivery guarantee).
func (s *Server) sendWorkerCommand(node string, cmd api.WorkerCommand) int {
	b, err := json.Marshal(api.Envelope{Type: api.MsgWorkerCommand, WorkerCommand: &cmd})
	if err != nil {
		return 0
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	sent := 0
	deliver := func(ch chan []byte) {
		select {
		case ch <- b:
			sent++
		default:
			// Worker's inbound command buffer is full (very small, 8 slots) —
			// drop rather than block the caller; the next state fetch will
			// still reflect whatever the worker was last told.
		}
	}
	if node == "" {
		for _, ch := range s.workerConns {
			deliver(ch)
		}
		return sent
	}
	if ch, ok := s.workerConns[node]; ok {
		deliver(ch)
	}
	return sent
}

// handleWorkerCapture pauses or resumes capture on one worker (node) or all
// of them (node omitted/empty). Pausing doesn't stop AF_PACKET/eBPF at the
// source or drop the hub connection — the worker just stops turning what it
// reads into entries — so resuming is instant.
func (s *Server) handleWorkerCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Node   string `json:"node"`
		Paused bool   `json:"paused"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	sent := s.sendWorkerCommand(req.Node, api.WorkerCommand{Paused: req.Paused})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"sent": sent})
}

// workerUpdate applies fn to node's registry row, creating it on first sight.
// A pre-hello connection ("unknown" node) is not tracked. This is the cold
// path (connect/disconnect, periodic worker stats) — the per-entry counters go
// through workerEntry's atomics instead, see handleWorker.
func (s *Server) workerUpdate(node string, fn func(*workerInfo)) {
	if we := s.workerRow(node); we != nil {
		s.wmu.Lock()
		fn(&we.info)
		s.wmu.Unlock()
	}
}

// workerRow returns node's registry row, creating it on first sight, or nil
// for an untracked ("" / pre-hello "unknown") node. handleWorker resolves the
// row once at hello and then updates its atomics directly, so the per-entry
// path costs neither a map lookup nor wmu.
func (s *Server) workerRow(node string) *workerEntry {
	if node == "" || node == "unknown" {
		return nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	we := s.workers[node]
	if we == nil {
		we = &workerEntry{info: workerInfo{Node: node}}
		s.workers[node] = we
	}
	return we
}

// gcWorkers removes registry rows for workers disconnected for more than
// workerGCTTL. Called periodically from statsLoop, which already runs a 2s
// ticker on the hub's lifetime.
func (s *Server) gcWorkers() {
	cutoff := time.Now().Add(-workerGCTTL)
	s.wmu.Lock()
	for node, we := range s.workers {
		if !we.info.Connected && we.lastSeenTime().Before(cutoff) {
			delete(s.workers, node)
		}
	}
	s.wmu.Unlock()
}

// workerSnapshot copies the registry, sorted by node name.
func (s *Server) workerSnapshot() []workerInfo {
	s.wmu.Lock()
	out := make([]workerInfo, 0, len(s.workers))
	for _, we := range s.workers {
		out = append(out, we.snapshot())
	}
	s.wmu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// --- front channel ---------------------------------------------------------

type frontClient struct {
	conn *websocket.Conn
	send chan []byte
	mu   sync.RWMutex
	pred Predicate
	// filterKey identifies pred for the purpose of sharing one assembled
	// batch frame between clients (see flushBroadcast). It is derived from the
	// filter *source*, never from the Predicate value: CompileFilter("")
	// returns a non-nil always-true closure, so "no filter" can't be detected
	// with a nil check, and two closures compiled from the same source are
	// never comparable as values.
	//
	// The empty string is reserved for "unknown" — a frontClient built without
	// going through handleFront/frontReader, i.e. a test — and is never
	// shared: such a client always gets a group of its own, so an unset key
	// can't silently pool clients whose predicates differ. Guarded by mu
	// alongside pred.
	filterKey string
	// queuedBytes is the total size of the frames sitting in send, kept so the
	// queue can be bounded by bytes and not just by slot count (see trySend).
	queuedBytes atomic.Int64
}

// filterKeySource builds a frontClient.filterKey for a successfully compiled
// filter. The prefix keeps it out of the reserved "" (unknown) and
// filterKeyReject values.
func filterKeySource(filter string) string { return "f:" + filter }

// filterKeyReject is the key of the match-nothing predicate installed when a
// client's ?filter= fails to compile. No filter source can produce it, so
// those clients pool only with each other.
const filterKeyReject = "!reject"

func (s *Server) handleFront(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, wsUpgradeHeader(r))
	if err != nil {
		s.log.Warn("front upgrade failed", "err", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(1 << 20) // bound per-message allocation (1 MiB)
	// Read deadline + pong handler so the 30s ping in frontWriter actually
	// detects a dead peer: every pong pushes the deadline out; a silent client
	// trips ReadMessage in frontReader once the window elapses, which then
	// deregisters and closes the send channel.
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})

	pred, filterErr := CompileFilter(r.URL.Query().Get("filter"))
	if filterErr != nil {
		// A bad ?filter= must not fall back to nil (which matches everything and
		// replays the whole firehose); match nothing until the client sends a
		// valid filter frame.
		s.log.Debug("front filter compile failed; using match-nothing", "err", filterErr)
		pred = func(*api.Entry) bool { return false }
	}
	c := &frontClient{
		conn:      conn,
		send:      make(chan []byte, 256),
		pred:      pred,
		filterKey: filterKeySource(r.URL.Query().Get("filter")),
	}
	if filterErr != nil {
		c.filterKey = filterKeyReject
	}

	s.log.Debug("front client connected", "remote", r.RemoteAddr)

	if filterErr != nil {
		if b, err := json.Marshal(api.Envelope{Type: api.MsgFilterError, Error: filterErr.Error()}); err == nil {
			c.trySend(b)
		}
	}

	// Snapshot history *before* registering c for live broadcast, not after:
	// store.add() always runs before broadcast() (see the MsgEntry handler
	// below), so an entry that lands in the gap between the two would
	// otherwise be caught by both — once in this replay's snapshot, once
	// again ~30ms later via the live broadcast flush once c is registered —
	// and show up as a duplicate row in the UI. Registering after avoids
	// that at the cost of a vanishingly rare single missed entry landing in
	// this now much narrower gap, which is the better trade for a live feed.
	s.replayHistory(c, pred)
	c.trySend(s.statsBytes())

	s.mu.Lock()
	s.frontClients[c] = struct{}{}
	s.frontCount.Store(int32(len(s.frontClients)))
	s.mu.Unlock()

	go s.frontReader(c)
	s.frontWriter(c)
}

// frontReader consumes control frames from a front client (filter updates).
func (s *Server) frontReader(c *frontClient) {
	defer func() {
		s.mu.Lock()
		delete(s.frontClients, c)
		s.frontCount.Store(int32(len(s.frontClients)))
		s.mu.Unlock()
		close(c.send)
	}()
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		var env api.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		if env.Type == api.MsgFilter {
			pred, err := CompileFilter(env.Filter)
			if err != nil {
				if b, merr := json.Marshal(api.Envelope{Type: api.MsgFilterError, Error: err.Error()}); merr == nil {
					c.trySend(b)
				}
				continue // keep previous filter on parse error
			}
			// Snapshot under the new predicate *before* switching c.pred over —
			// flushBroadcast() matches against whatever c.pred is at flush time
			// (up to ~30ms after an entry is queued), so swapping it first would
			// let an entry landing in the gap match both this replay and a
			// subsequent live broadcast, arriving twice. See the matching
			// comment in handleFront.
			s.replayHistory(c, pred)
			c.mu.Lock()
			c.pred = pred
			c.filterKey = filterKeySource(env.Filter)
			c.mu.Unlock()
		}
	}
}

// replayBatchSize bounds how many entries share one replay frame — chunking
// keeps individual frames modest while still collapsing a 500-entry replay
// from 500 frames into a handful.
const replayBatchSize = 100

// replayHistory resends up to 500 recent entries matching pred, oldest first
// so the UI appends chronologically, as chunked MsgEntryBatch frames
// assembled from the store's cached JSON — no re-marshaling per connection or
// filter swap. Used on initial connect and after a live filter swap. pred is
// taken as a parameter rather than read from c.pred so callers can snapshot
// under it before c.pred (and therefore live broadcast matching) switches
// over — see the callers' comments.
func (s *Server) replayHistory(c *frontClient, pred Predicate) {
	history := s.store.recentRaw(500, pred) // newest first
	// Walk chunks from the slice's tail (the oldest entries) toward its head,
	// reversing within each chunk, so the client sees strict chronological
	// order across all frames.
	for end := len(history); end > 0; end -= replayBatchSize {
		start := end - replayBatchSize
		if start < 0 {
			start = 0
		}
		chunk := history[start:end]
		raws := make([][]byte, 0, len(chunk))
		for i := len(chunk) - 1; i >= 0; i-- {
			raws = append(raws, chunk[i])
		}
		c.trySend(assembleBatch(raws))
	}
}

// assembleBatch builds a MsgEntryBatch frame by splicing cached per-entry
// JSON into the envelope — the entries are never re-marshaled.
func assembleBatch(raws [][]byte) []byte {
	size := len(`{"type":"entryBatch","entries":[]}`) + len(raws)
	for _, r := range raws {
		size += len(r)
	}
	b := make([]byte, 0, size)
	b = append(b, `{"type":"entryBatch","entries":[`...)
	for i, r := range raws {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, r...)
	}
	return append(b, `]}`...)
}

// frontWriter drains the send channel to the socket.
func (s *Server) frontWriter(c *frontClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case b, ok := <-c.send:
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			err := c.conn.WriteMessage(websocket.TextMessage, b)
			// Release the frame's byte reservation once it has left the queue,
			// whether or not the write succeeded — on failure this writer is
			// about to exit and the client is torn down anyway.
			c.queuedBytes.Add(-int64(len(b)))
			if err != nil {
				return
			}
		case <-ticker.C:
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// frontQueueBytes bounds a front client's pending frames by size. The slot
// count alone is not a bound worth anything here: every element of send is a
// whole batch frame — around a megabyte under live load, a couple on replay —
// so 256 slots admit hundreds of megabytes against a pod that typically runs
// with a 512Mi limit. One backgrounded browser tab that stops reading is
// enough to reach that, so the queue is capped by bytes too.
//
// The floor on the value is a full history replay: handleFront queues all
// ~500 entries (replayBatchSize at a time) *before* frontWriter starts
// draining, so a budget under that would silently truncate the newest history
// on a busy hub — replayHistory sends oldest-chunk-first. 16 MiB clears that
// with headroom while still cutting the pathological case by ~20x.
const frontQueueBytes = 16 << 20

// trySend queues b for the client without blocking. It reports false when the
// client is too far behind — either the slot buffer is full or the queued
// bytes would exceed frontQueueBytes — so the caller can account for the drop.
func (c *frontClient) trySend(b []byte) bool {
	n := int64(len(b))
	// Reserve first, release on failure: frontWriter decrements concurrently,
	// so incrementing only after a successful send would let the counter go
	// negative. A frame larger than the whole budget is still admitted when
	// the queue is empty (queued == n after the reservation), so an unusually
	// large batch can never permanently starve a client that is keeping up.
	if queued := c.queuedBytes.Add(n); queued > frontQueueBytes && queued != n {
		c.queuedBytes.Add(-n)
		return false
	}
	select {
	case c.send <- b:
		return true
	default:
		// Slow client: drop rather than block the broadcaster.
		c.queuedBytes.Add(-n)
		return false
	}
}

// snapshotFilter reads the client's current predicate and its grouping key in
// one lock acquisition, so flushBroadcast pays c.mu once per client per flush
// instead of once per client per entry.
func (c *frontClient) snapshotFilter() (Predicate, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pred, c.filterKey
}

// pendingEntry is one not-yet-flushed live entry: the entry for per-client
// filtering plus its cached JSON for zero-marshal batch assembly.
type pendingEntry struct {
	entry *api.Entry
	raw   []byte
}

// broadcastFlushInterval is how long live entries coalesce before fan-out.
// At 2000 entries/s with 10 clients, per-entry fan-out means 20000 frames and
// syscalls per second; a 30ms window collapses that by ~60x for an added
// latency no dashboard user can perceive.
const broadcastFlushInterval = 30 * time.Millisecond

// broadcast queues a live entry for the next batched fan-out. raw is the
// store's cached JSON for e (a nil raw — marshal failure — is skipped). The
// first entry of a window arms a one-shot flush timer, so an idle hub runs no
// ticker and tests exercising the handler need no background loop.
func (s *Server) broadcast(e *api.Entry, raw []byte) {
	if raw == nil {
		return
	}
	// Fast path: with no front clients, don't even queue.
	//
	// frontCount is a hint maintained at the register/unregister sites, read
	// here without a lock so the ingest path doesn't touch s.mu once per
	// entry. It is only ever trusted in the positive direction: a non-zero
	// count means "there is at least one listener, go queue", while a zero
	// falls back to confirming under the lock. That asymmetry is what keeps
	// the hint safe — a client inserted into s.frontClients directly (tests
	// do this to drive the fan-out by hand) leaves the counter at zero and is
	// still found by the fallback, and the fallback only runs on the idle
	// path, where there is no fan-out work to be saved anyway.
	if s.frontCount.Load() == 0 {
		s.mu.RLock()
		empty := len(s.frontClients) == 0
		s.mu.RUnlock()
		if empty {
			return
		}
	}
	s.bmu.Lock()
	s.pending = append(s.pending, pendingEntry{entry: e, raw: raw})
	first := len(s.pending) == 1
	s.bmu.Unlock()
	if first {
		time.AfterFunc(broadcastFlushInterval, s.flushBroadcast)
	}
}

// flushBroadcast drains the pending window and sends each front client one
// MsgEntryBatch frame with the subset matching its filter, assembled from the
// entries' cached JSON. A client whose send buffer is full drops the whole
// batch (counted per entry in broadcastDropped, keeping the metric's unit).
//
// Clients that share a filter share the work: the predicate is snapshotted
// once per client per flush (rather than re-locked per entry), clients with
// the same filter key are grouped, and each group runs the per-entry match
// loop and assembleBatch exactly once. On a dashboard where every open tab
// carries the same filter — the normal case — that turns O(clients × entries)
// predicate calls and O(clients) megabyte-scale frame builds into O(entries)
// and O(1).
//
// The resulting []byte is then handed to every client in the group. That is
// safe because the frame is concatenated store JSON that nothing mutates:
// frontWriter only reads it, and no WebSocket compression is negotiated.
// WARNING: re-verify this if permessage-deflate is ever enabled on the
// upgrader — gorilla's compressing writer mutates the payload buffer, and
// sharing one frame across clients would then corrupt it.
func (s *Server) flushBroadcast() {
	s.bmu.Lock()
	batch := s.pending
	s.pending = nil
	s.bmu.Unlock()
	if len(batch) == 0 {
		return
	}

	// filterGroup is the set of clients that will receive byte-identical
	// frames for this flush.
	type filterGroup struct {
		pred    Predicate
		clients []*frontClient
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make([]*filterGroup, 0, len(s.frontClients))
	byKey := make(map[string]*filterGroup, len(s.frontClients))
	for c := range s.frontClients {
		pred, key := c.snapshotFilter()
		if key != "" {
			if g := byKey[key]; g != nil {
				g.clients = append(g.clients, c)
				continue
			}
		}
		g := &filterGroup{pred: pred, clients: []*frontClient{c}}
		if key != "" {
			byKey[key] = g
		}
		groups = append(groups, g)
	}

	raws := make([][]byte, 0, len(batch))
	for _, g := range groups {
		raws = raws[:0]
		for _, p := range batch {
			if g.pred == nil || g.pred(p.entry) {
				raws = append(raws, p.raw)
			}
		}
		if len(raws) == 0 {
			continue
		}
		frame := assembleBatch(raws)
		for _, c := range g.clients {
			if !c.trySend(frame) {
				atomic.AddInt64(&s.broadcastDropped, int64(len(raws)))
			}
		}
	}
}

// --- stats -----------------------------------------------------------------

func (s *Server) statsLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.gcWorkers()
		st := s.statsSnapshot()
		s.recordStatsPoint(st)
		b := s.marshalStats(st)
		s.mu.RLock()
		for c := range s.frontClients {
			c.trySend(b)
		}
		s.mu.RUnlock()
	}
}

// statsSnapshot returns the store's aggregate stats plus hub-level counters
// the store doesn't own (broadcastDropped is tracked on Server, see broadcast).
func (s *Server) statsSnapshot() api.Stats {
	st := s.store.stats(int(atomic.LoadInt32(&s.workerCount)))
	st.BroadcastDropped = atomic.LoadInt64(&s.broadcastDropped)
	return st
}

// recordStatsPoint appends one sample to the rolling stats history, trimming
// the oldest entry once statsHistoryCap is exceeded.
func (s *Server) recordStatsPoint(st api.Stats) {
	s.statsHistMu.Lock()
	s.statsHist = append(s.statsHist, api.StatsPoint{
		Timestamp:     time.Now(),
		EntriesPerSec: st.EntriesPerSec,
		TotalEntries:  st.TotalEntries,
	})
	if len(s.statsHist) > statsHistoryCap {
		s.statsHist = s.statsHist[len(s.statsHist)-statsHistoryCap:]
	}
	s.statsHistMu.Unlock()
}

func (s *Server) marshalStats(st api.Stats) []byte {
	b, _ := json.Marshal(api.Envelope{Type: api.MsgStats, Stats: &st})
	return b
}

func (s *Server) statsBytes() []byte {
	return s.marshalStats(s.statsSnapshot())
}

// --- REST ------------------------------------------------------------------

func (s *Server) handleEntries(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		// Invalid or non-positive keeps the default; oversized clamps to the
		// buffer instead of silently snapping back to 200.
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = clampInt(n, 1, s.store.capacity)
		}
	}
	pred, err := s.queryPredicate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sortField := r.URL.Query().Get("sort"); sortField != "" {
		desc, err := sortOrder(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !validSortField(sortField) {
			http.Error(w, "unknown or non-numeric sort field: "+sortField, http.StatusBadRequest)
			return
		}
		// The only branch that still marshals from structs: reordering needs
		// the entries themselves, so the store's cached per-entry JSON (which
		// the unsorted paths below splice in verbatim) can't be used here.
		matched := s.store.recent(s.store.capacity, pred)
		writeJSON(w, topNBySort(matched, fieldGetter(sortField), desc, limit))
		return
	}

	// before_seq is the robust pagination anchor (see recentBeforeSeq): unlike
	// before (an entry ID that must still be present in the ring to locate
	// the starting point), it keeps working once the anchoring entry itself
	// has aged out, since it's a plain numeric comparison. Preferred over
	// before when both are given.
	if beforeSeq := r.URL.Query().Get("before_seq"); beforeSeq != "" {
		n, err := strconv.ParseInt(beforeSeq, 10, 64)
		if err != nil {
			http.Error(w, "invalid before_seq: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONArray(w, s.store.recentBeforeSeqRaw(n, limit, pred))
		return
	}
	if before := r.URL.Query().Get("before"); before != "" {
		writeJSONArray(w, s.store.recentBeforeRaw(before, limit, pred))
		return
	}
	writeJSONArray(w, s.store.recentRaw(limit, pred))
}

// sortOrder parses ?order=asc|desc for handleEntries' ?sort=, defaulting to
// desc (the common "biggest/slowest first" case) when order is omitted.
func sortOrder(r *http.Request) (desc bool, err error) {
	switch v := r.URL.Query().Get("order"); v {
	case "", "desc":
		return true, nil
	case "asc":
		return false, nil
	default:
		return false, fmt.Errorf("invalid order %q (want asc or desc)", v)
	}
}

// queryPredicate compiles the shared ?filter=&since=&until= query params into
// one predicate. since/until accept RFC3339, unix seconds, or a relative
// duration meaning "that long ago" (e.g. since=15m).
func (s *Server) queryPredicate(r *http.Request) (Predicate, error) {
	pred, err := CompileFilter(r.URL.Query().Get("filter"))
	if err != nil {
		return nil, fmt.Errorf("invalid filter: %w", err)
	}
	since, until, err := timeRange(r)
	if err != nil {
		return nil, err
	}
	if since.IsZero() && until.IsZero() {
		return pred, nil
	}
	return func(e *api.Entry) bool {
		if !since.IsZero() && e.Timestamp.Before(since) {
			return false
		}
		if !until.IsZero() && e.Timestamp.After(until) {
			return false
		}
		return pred(e)
	}, nil
}

// timeRange parses the optional since/until query params.
func timeRange(r *http.Request) (since, until time.Time, err error) {
	if v := r.URL.Query().Get("since"); v != "" {
		if since, err = parseTimeParam(v); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid since: %w", err)
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if until, err = parseTimeParam(v); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid until: %w", err)
		}
	}
	return since, until, nil
}

// parseTimeParam accepts RFC3339 ("2026-07-15T14:00:00Z"), unix seconds
// ("1752588000"), or a Go duration meaning that long ago ("15m", "1h30m").
func parseTimeParam(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(secs, 0), nil
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return time.Now().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("want RFC3339, unix seconds, or a duration like 15m: %q", v)
}

// sortedKeys returns m's keys sorted ascending, for deterministic /metrics
// output ordering.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func (s *Server) handleEntry(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/entry/"):]
	e := s.store.get(id)
	if e == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, e)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.statsSnapshot())
}

// handleStatsHistory serves the rolling throughput history (one point per
// statsLoop tick, ~10 minutes at the current 2s interval) so a freshly
// connected client can render a trend sparkline immediately instead of
// waiting to accumulate its own samples live.
func (s *Server) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	s.statsHistMu.RLock()
	out := make([]api.StatsPoint, len(s.statsHist))
	copy(out, s.statsHist)
	s.statsHistMu.RUnlock()
	writeJSON(w, out)
}

// handleSummary serves GET /api/summary?groupBy=&filter=&since=&until=&limit=,
// aggregating the buffered entries into per-group counts, error totals and
// latency percentiles. See summarize (summary.go) for the groupBy keys.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	groupBy := r.URL.Query().Get("groupBy")
	if groupBy == "" {
		groupBy = "workload"
	}
	if !validGroupBy(groupBy) {
		http.Error(w, "unknown groupBy field: "+groupBy, http.StatusBadRequest)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = clampInt(n, 1, 1000)
		}
	}
	pred, err := s.queryPredicate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := "summary:" + r.URL.RequestURI()
	body, err := s.cachedAgg(key, func() ([]byte, error) {
		entries := s.store.recent(s.store.capacity, pred)
		groups := summarize(entries, groupBy)
		if len(groups) > limit {
			groups = groups[:limit]
		}
		return json.Marshal(map[string]any{"groupBy": groupBy, "total": len(entries), "groups": groups})
	})
	if err != nil {
		http.Error(w, "encode summary: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeCachedJSON(w, body)
}

// handleTimeline serves GET /api/timeline?bucket=&filter=&since=&until=,
// bucketing matching entries into a fixed-step time series (gaps included as
// zero buckets) so "when did this start" is answerable at a glance.
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	bucket := 60 * time.Second
	if v := r.URL.Query().Get("bucket"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			bucket = time.Duration(clampInt(n, 1, 3600)) * time.Second
		}
	}
	since, until, err := timeRange(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() {
		since = until.Add(-15 * time.Minute)
	}
	pred, err := s.queryPredicate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries := s.store.recent(s.store.capacity, pred)
	writeJSON(w, map[string]any{
		"bucketSeconds": int(bucket / time.Second),
		"buckets":       timeline(entries, since, until, bucket),
	})
}

// handleGraph serves GET /api/graph?filter=&since=&until=&focus=, aggregating
// the buffered entries into the service call graph: one directed src→dst edge
// per node pair with counts, error/warning totals and latency percentiles.
// focus restricts to edges touching one service, matched against either
// endpoint's workload, name, or namespace-qualified node label. See
// serviceGraph (graph.go).
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	pred, err := s.queryPredicate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := "graph:" + r.URL.RequestURI()
	body, err := s.cachedAgg(key, func() ([]byte, error) {
		entries := s.store.recent(s.store.capacity, pred)
		return json.Marshal(map[string]any{"edges": serviceGraph(entries, r.URL.Query().Get("focus"))})
	})
	if err != nil {
		http.Error(w, "encode graph: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeCachedJSON(w, body)
}

// handleWorkers serves GET /api/workers: every worker ever seen (connected or
// not), with self-reported drop/capture state.
func (s *Server) handleWorkers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.workerSnapshot())
}

// handleMetrics emits the hub's self-metrics in Prometheus text exposition
// format, hand-rolled to avoid a client_golang dependency (stdlib only).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	st := s.store.stats(int(atomic.LoadInt32(&s.workerCount)))
	s.mu.RLock()
	frontClients := len(s.frontClients)
	s.mu.RUnlock()
	dropped := atomic.LoadInt64(&s.broadcastDropped)

	var b strings.Builder
	metric := func(name, typ, help, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, typ)
		fmt.Fprintf(&b, "%s %s\n", name, value)
	}
	metric("k8shark_hub_entries_total", "counter",
		"Total entries ingested by the hub.", strconv.FormatInt(st.TotalEntries, 10))
	metric("k8shark_hub_front_clients", "gauge",
		"Currently connected front-end clients.", strconv.Itoa(frontClients))
	metric("k8shark_hub_workers", "gauge",
		"Currently connected workers.", strconv.Itoa(st.Workers))
	metric("k8shark_hub_broadcast_dropped_total", "counter",
		"Entries dropped to slow front clients.", strconv.FormatInt(dropped, 10))
	if s.exporter != nil {
		metric("k8shark_hub_export_dropped_total", "counter",
			"Entries/batches dropped by the export sink (full buffer or failed delivery).",
			strconv.FormatUint(s.exporter.drops(), 10))
	}
	metric("k8shark_hub_entries_per_sec", "gauge",
		"Entries ingested per second, trailing 5s window.", strconv.FormatFloat(st.EntriesPerSec, 'f', -1, 64))
	metric("k8shark_hub_buffer_entries", "gauge",
		"Ring buffer slots currently filled.", strconv.Itoa(s.store.size()))
	metric("k8shark_hub_buffer_capacity", "gauge",
		"Ring buffer capacity (max entries retained).", strconv.Itoa(s.store.capacity))
	metric("k8shark_hub_k8s_enrich_failures_total", "counter",
		"Failed k8s enrichment refresh cycles (e.g. broken RBAC).", strconv.FormatInt(s.resolver.failures(), 10))

	if len(st.ByProtocol) > 0 {
		fmt.Fprintf(&b, "# HELP k8shark_hub_entries_by_protocol_total Entries ingested, by protocol.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_hub_entries_by_protocol_total counter\n")
		for _, proto := range sortedKeys(st.ByProtocol) {
			fmt.Fprintf(&b, "k8shark_hub_entries_by_protocol_total{protocol=%q} %d\n", proto, st.ByProtocol[proto])
		}
	}
	if len(st.ByStatus) > 0 {
		fmt.Fprintf(&b, "# HELP k8shark_hub_entries_by_status_total Entries ingested, by normalised status.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_hub_entries_by_status_total counter\n")
		for _, status := range sortedKeys(st.ByStatus) {
			fmt.Fprintf(&b, "k8shark_hub_entries_by_status_total{status=%q} %d\n", status, st.ByStatus[status])
		}
	}

	// Per-worker series, from the registry (self-reported drops make silent
	// capture loss visible to alerting).
	workers := s.workerSnapshot()
	if len(workers) > 0 {
		fmt.Fprintf(&b, "# HELP k8shark_worker_entries_total Entries received from each worker.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_worker_entries_total counter\n")
		for _, wi := range workers {
			fmt.Fprintf(&b, "k8shark_worker_entries_total{node=%q} %d\n", wi.Node, wi.Entries)
		}
		fmt.Fprintf(&b, "# HELP k8shark_worker_dropped_total Worker-reported entries dropped before reaching the hub.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_worker_dropped_total counter\n")
		for _, wi := range workers {
			fmt.Fprintf(&b, "k8shark_worker_dropped_total{node=%q} %d\n", wi.Node, wi.Dropped)
		}
		fmt.Fprintf(&b, "# HELP k8shark_worker_connected Whether the worker is currently connected.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_worker_connected gauge\n")
		for _, wi := range workers {
			v := 0
			if wi.Connected {
				v = 1
			}
			fmt.Fprintf(&b, "k8shark_worker_connected{node=%q} %d\n", wi.Node, v)
		}
		fmt.Fprintf(&b, "# HELP k8shark_worker_ring_drops_total AF_PACKET kernel ring packets dropped before userspace saw them.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_worker_ring_drops_total counter\n")
		for _, wi := range workers {
			fmt.Fprintf(&b, "k8shark_worker_ring_drops_total{node=%q} %d\n", wi.Node, wi.RingDrops)
		}
		fmt.Fprintf(&b, "# HELP k8shark_worker_flows_evicted_total Generic L4 flows dropped by the worker's maxFlows cap.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_worker_flows_evicted_total counter\n")
		for _, wi := range workers {
			fmt.Fprintf(&b, "k8shark_worker_flows_evicted_total{node=%q} %d\n", wi.Node, wi.FlowsEvicted)
		}
		fmt.Fprintf(&b, "# HELP k8shark_worker_tls_lag_drops_total eBPF TLS streams truncated after a backpressure drop.\n")
		fmt.Fprintf(&b, "# TYPE k8shark_worker_tls_lag_drops_total counter\n")
		for _, wi := range workers {
			fmt.Fprintf(&b, "k8shark_worker_tls_lag_drops_total{node=%q} %d\n", wi.Node, wi.TLSLagDrops)
		}
		fmt.Fprintf(&b, "# HELP k8shark_worker_tcp_loss_events_total AF_PACKET TCP stream directions truncated after a lost segment (FIFO pairing desync guard).\n")
		fmt.Fprintf(&b, "# TYPE k8shark_worker_tcp_loss_events_total counter\n")
		for _, wi := range workers {
			fmt.Fprintf(&b, "k8shark_worker_tcp_loss_events_total{node=%q} %d\n", wi.Node, wi.TCPLossEvents)
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// --- IFL autocomplete (fields/values) ---------------------------------------

// fieldMeta is the /api/fields JSON shape for a single field.
type fieldMeta struct {
	Name      string       `json:"name"`
	Type      FieldType    `json:"type"`
	Operators []string     `json:"operators"`
	Values    []FieldValue `json:"values,omitempty"`
}

// handleFields returns the full field catalog, with current top-N observed
// values (merged with any static EnumValues) inlined for tracked fields.
func (s *Server) handleFields(w http.ResponseWriter, r *http.Request) {
	out := make([]fieldMeta, 0, len(fieldCatalog))
	for _, spec := range fieldCatalog {
		fm := fieldMeta{Name: spec.Name, Type: spec.Type, Operators: spec.Operators}
		if spec.TrackValues {
			fm.Values = s.fieldValuesFor(spec, "", facetTopN)
		}
		out = append(out, fm)
	}
	// Header field names are dynamic (any header key can appear) so they
	// aren't in the static fieldCatalog above; append one synthetic entry per
	// observed key instead, with no value list (header values are
	// effectively freetext -- see DIS-12).
	reqHeaders, respHeaders := s.store.facets.headerFieldNames()
	for _, h := range reqHeaders {
		out = append(out, fieldMeta{Name: "request.header." + h, Type: FieldTypeString, Operators: opsString})
	}
	for _, h := range respHeaders {
		out = append(out, fieldMeta{Name: "response.header." + h, Type: FieldTypeString, Operators: opsString})
	}
	writeJSON(w, map[string]any{"fields": out})
}

// handleFieldValues serves GET /api/fields/{field}/values?prefix=&limit=.
func (s *Server) handleFieldValues(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/fields/")
	field := strings.TrimSuffix(rest, "/values")
	if field == rest || field == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// 404 only for a genuinely unknown field. A known but untracked field
	// (freetext / high-cardinality, e.g. request.path) returns 200 with an empty
	// value list — "no suggestions" is a valid answer, not an error.
	spec, ok := fieldSpecByName[field]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			switch {
			case n < 1:
				n = 1
			case n > 200:
				n = 200
			}
			limit = n
		}
	}
	prefix := r.URL.Query().Get("prefix")

	writeJSON(w, map[string]any{
		"field":  field,
		"type":   spec.Type,
		"values": s.fieldValuesFor(spec, prefix, limit),
	})
}

// fieldValuesFor returns spec's observed values (via the store's facet
// index) merged with any static EnumValues -- so an enum domain (protocol,
// status, ...) is fully suggestable even before matching traffic arrives.
// Static-only values get count 0; observed counts win when a value appears
// in both. Filtered by prefix (case-insensitive) and truncated to limit.
// Only meaningful when spec.TrackValues is true.
func (s *Server) fieldValuesFor(spec FieldSpec, prefix string, limit int) []FieldValue {
	observed, _ := s.store.facets.values(spec.Name, prefix, facetTrackCap)
	byValue := make(map[string]int64, len(observed)+len(spec.EnumValues))
	for _, v := range observed {
		byValue[v.Value] = v.Count
	}
	lowerPrefix := strings.ToLower(prefix)
	for _, ev := range spec.EnumValues {
		if _, exists := byValue[ev]; exists {
			continue
		}
		if prefix == "" || strings.HasPrefix(strings.ToLower(ev), lowerPrefix) {
			byValue[ev] = 0
		}
	}
	out := make([]FieldValue, 0, len(byValue))
	for v, c := range byValue {
		out = append(out, FieldValue{Value: v, Count: c})
	}
	sortFieldValues(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONArray writes raws as a JSON array without re-marshaling anything:
// the elements are the store's cached per-entry JSON, produced by the same
// encoder (and therefore the same HTML-escaping rules) writeJSON would use.
// The output is byte-for-byte what writeJSON would have emitted for the
// equivalent []*api.Entry — including the trailing newline json.Encoder adds —
// which is what TestHandleEntriesRawJSONMatchesStructs pins down. A history
// page is several MB of entries, so skipping the round-trip through reflection
// is the difference between a page being free and being the most expensive
// thing the hub does per request.
func writeJSONArray(w http.ResponseWriter, raws [][]byte) {
	size := len("[]\n") + len(raws)
	for _, r := range raws {
		size += len(r)
	}
	b := make([]byte, 0, size)
	b = append(b, '[')
	for i, r := range raws {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, r...)
	}
	b = append(b, ']', '\n')

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// withAuth enforces the optional tokens on /api/* and the WebSocket
// endpoints. Static UI assets, /healthz and /metrics stay open (the data is
// behind /api; metrics scraping is cluster-internal). Browsers cannot set
// headers on a WebSocket, so a `Sec-WebSocket-Protocol: bearer.<token>`
// subprotocol is accepted, as is a ?token= query param (deprecated: a token in
// the URL leaks into access logs, history and Referer headers).
//
// Three token classes route by path/method (see acceptedTokens): the worker
// channel, mutations, and reads. Each optional class falls back to APIToken
// when unset, so a single-token setup behaves exactly as before.
func (s *Server) withAuth(h http.Handler) http.Handler {
	if s.apiToken == "" && s.workerToken == "" && s.adminToken == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/") && p != "/api" && p != "/ws" && !strings.HasPrefix(p, "/ws/") {
			h.ServeHTTP(w, r)
			return
		}
		accepted := s.acceptedTokens(p, r.Method)
		if len(accepted) == 0 {
			h.ServeHTTP(w, r)
			return
		}
		got := []byte(presentedToken(r))
		for _, want := range accepted {
			if subtle.ConstantTimeCompare(got, []byte(want)) == 1 {
				h.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// acceptedTokens returns the token values granting access to this request, or
// nil for open access. Classes:
//   - /ws/worker (entry injection): the worker token alone when set — a read
//     token must not let anyone forge entries, and a compromised worker
//     credential must not read captured traffic.
//   - mutating /api calls (non-GET/HEAD, e.g. POST /api/workers/capture): the
//     admin token alone when set — the front proxy only injects the API token,
//     so dashboard users lose cluster-wide control once an admin token exists.
//   - reads (/api GETs, the front /ws): the API token, plus the admin token
//     (an admin can read; a worker cannot). No API token = reads stay open.
func (s *Server) acceptedTokens(path, method string) []string {
	switch {
	case path == "/ws/worker" || strings.HasPrefix(path, "/ws/worker/"):
		if s.workerToken != "" {
			return []string{s.workerToken}
		}
	case method != http.MethodGet && method != http.MethodHead && strings.HasPrefix(path, "/api"):
		if s.adminToken != "" {
			return []string{s.adminToken}
		}
	default:
		if s.apiToken == "" {
			return nil
		}
		if s.adminToken != "" {
			return []string{s.apiToken, s.adminToken}
		}
	}
	if s.apiToken == "" {
		return nil
	}
	return []string{s.apiToken}
}

// presentedToken extracts the client's credential: `Authorization: Bearer`
// wins, then the `bearer.<token>` WS subprotocol, then ?token= (deprecated).
func presentedToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if proto := wsBearerProtocol(r); proto != "" {
		return strings.TrimPrefix(proto, wsBearerPrefix)
	}
	return r.URL.Query().Get("token")
}

// wsBearerPrefix marks the WebSocket subprotocol entry that carries the API
// token for browser clients (which cannot set an Authorization header on a
// WebSocket): `Sec-WebSocket-Protocol: bearer.<token>`.
const wsBearerPrefix = "bearer."

// wsBearerProtocol returns the full `bearer.<token>` entry from the request's
// Sec-WebSocket-Protocol list, or "" if none. The full entry (not just the
// token) is returned so upgrade handlers can echo it back as the selected
// subprotocol — browsers fail the connection when a requested subprotocol
// isn't acknowledged by the server.
func wsBearerProtocol(r *http.Request) string {
	for _, part := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		if part = strings.TrimSpace(part); strings.HasPrefix(part, wsBearerPrefix) {
			return part
		}
	}
	return ""
}

// wsUpgradeHeader builds the response header for a WebSocket upgrade: when the
// client authenticated via the bearer subprotocol, it must be echoed as the
// selected one or browsers abort the freshly-opened connection.
func wsUpgradeHeader(r *http.Request) http.Header {
	if proto := wsBearerProtocol(r); proto != "" {
		return http.Header{"Sec-WebSocket-Protocol": {proto}}
	}
	return nil
}

// originAllowed reports whether a browser Origin may reach the API: same-origin
// (Origin host equals the request Host, the case for the nginx front, the vite
// dev proxy and a direct port-forward) or listed in --allow-origin ("*" allows
// any). Requests without an Origin header — curl, workers, the MCP — always
// pass; this guards browsers, whose cross-site requests can't drop the header.
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if u, err := url.Parse(origin); err == nil && strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, allowed := range s.allowOrigins {
		if allowed == "*" || strings.EqualFold(strings.TrimRight(allowed, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}

// withCORS emits CORS headers only for allowed origins (echoing the origin,
// never a wildcard), so a random web page can't read API responses from an
// operator's port-forwarded hub. Same-origin requests don't need CORS headers
// but get them anyway (harmless); disallowed origins get none, which makes the
// browser block the response.
func (s *Server) withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && s.originAllowed(r) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
