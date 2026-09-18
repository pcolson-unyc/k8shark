package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pablocolson/k8shark/internal/config"
	"github.com/pablocolson/k8shark/pkg/api"
)

// sinkWriteTimeout bounds a single hub WriteMessage so a half-open connection
// can't wedge the pump for the OS TCP timeout (minutes) while the buffer
// silently drops all capture.
const sinkWriteTimeout = 10 * time.Second

// sinkStatsInterval is how often the sink self-reports drop counters and
// capture state to the hub (surfaced at /api/workers).
const sinkStatsInterval = 10 * time.Second

// sinkBatchMaxEntries and sinkBatchMaxBytes bound one MsgEntryBatch frame.
//
// The hub->front leg has coalesced entries into batches for a while; this is
// the same trick on the worker->hub leg, which was the last unbatched hop. The
// batch is drained *opportunistically* — pump only ever takes what is already
// sitting in s.ch — so unlike the hub's timer-driven flush it adds exactly zero
// latency: a quiet node still sends one entry per frame the instant it is
// produced, and batching only kicks in once entries are arriving faster than
// they can be written, which is precisely when the per-frame syscall and
// per-frame json.Unmarshal at the hub start to matter.
//
// sinkBatchMaxBytes must stay comfortably below the hub's per-connection read
// limit (workerReadLimit in internal/hub/server.go) or an oversized frame kills
// the connection instead of being delivered. The two constants are deliberately
// far apart so neither has to move when the other is tuned.
const (
	sinkBatchMaxEntries = 64
	sinkBatchMaxBytes   = 512 << 10
)

// sink is a reconnecting WebSocket client that ships entries to the hub. Entries
// are buffered on a channel; if the hub is unreachable the buffer drops the
// newest (incoming) entry rather than blocking capture.
type sink struct {
	hubURL   string
	hubToken string // bearer token sent on dial ("" = no auth)
	node     string
	log      *slog.Logger
	dialer   *websocket.Dialer // DefaultDialer unless setHubCA installed a custom root pool

	ch      chan *api.Entry
	dropped atomic.Uint64 // entries dropped on a full buffer
	sent    atomic.Uint64 // entries successfully written to the hub

	// capture state, set by worker.Run / captureLoop and self-reported to the
	// hub so a dead capture source is visible cluster-side, not just in logs.
	captureLive atomic.Bool // AF_PACKET source active
	captureTLS  atomic.Bool // eBPF TLS capture active

	// capturePaused is set remotely by the hub (MsgWorkerCommand, see
	// reader()) via POST /api/workers/capture. eBPF stays attached either
	// way — consumeTLS checks this and drops what it reads before doing any
	// reassembly/dissection work. AF_PACKET is different: captureLoop closes
	// the live source on pause and reopens it on resume (see pauseChanged),
	// so the kernel ring genuinely stops filling and its ~48MB mmap is
	// freed — resume costs a fresh socket+mmap+BPF-filter setup instead of
	// being instant, which is the tradeoff for the CPU/RAM actually going
	// down while paused.
	capturePaused atomic.Bool

	// pauseChanged wakes captureLoop the moment capturePaused actually flips,
	// instead of polling it once per packet/tick. Buffered 1 and drained
	// non-blocking on send: only the latest state matters, so a burst of
	// commands collapses to a single wakeup rather than queuing every edge.
	pauseChanged chan struct{}

	// ringPackets/ringDrops mirror the AF_PACKET kernel ring's own cumulative
	// counters (captureLoop probes capture.PacketSource.Stats periodically).
	// Distinct from dropped above, which only counts entries lost after the
	// pipeline already turned them into dissected output — a rising
	// ringDrops means traffic was lost before the worker ever saw it.
	ringPackets atomic.Uint64
	ringDrops   atomic.Uint64

	// flowsEvicted counts generic L4 flows dropped by dissect_l4.go's
	// maxFlows cap (a burst of new connections between flushFlows cycles),
	// set directly by the pipeline via p.sink.flowsEvicted.
	flowsEvicted atomic.Uint64

	// tlsLagDrops counts eBPF TLS streams abandoned because backpressure
	// dropped one of their interior chunks (see ebpf.TLSRecord.Lagged) —
	// closed with a clean truncation instead of misparsing past a hole.
	tlsLagDrops    atomic.Uint64
	tlsBudgetDrops atomic.Uint64

	// tcpLossEvents counts AF_PACKET TCP stream directions truncated after a
	// lost segment surfaced as tcpreader.DataLost (LossErrors): the
	// connection's pending requests are purged and the direction dropped, so
	// the FIFO request/response pairing can't silently desync across the hole
	// (see pipeline.go lossReader). Set by the pipeline via p.sink.tcpLossEvents.
	tcpLossEvents atomic.Uint64

	mu   sync.Mutex
	conn *websocket.Conn
}

func newSink(hubURL, hubToken, node string, log *slog.Logger) *sink {
	return &sink{
		hubURL:       hubURL,
		hubToken:     hubToken,
		node:         node,
		log:          log,
		dialer:       websocket.DefaultDialer,
		ch:           make(chan *api.Entry, 1024),
		pauseChanged: make(chan struct{}, 1),
	}
}

// setHubCA installs a custom CA (PEM file) for verifying a wss:// hub
// certificate — needed when the hub's cert is issued by a private CA
// (cert-manager) rather than one in the system roots. Must be called before
// run.
func (s *sink) setHubCA(path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("no CA certificates found in %s", path)
	}
	d := *websocket.DefaultDialer
	d.TLSClientConfig = &tls.Config{RootCAs: pool}
	s.dialer = &d
	return nil
}

// paused reports whether the hub has told this worker to stop turning
// capture into entries. Checked by route() / consumeTLS on every
// packet/record, so it stays a plain atomic load.
func (s *sink) paused() bool {
	return s.capturePaused.Load()
}

// emit queues an entry, dropping the incoming (newest) entry if the buffer is
// full so capture never blocks. Full-buffer drops are counted and logged every
// 1000 so they aren't completely invisible.
func (s *sink) emit(e *api.Entry) {
	select {
	case s.ch <- e:
	default:
		// buffer full — drop this (newest) entry to keep capture non-blocking
		if n := s.dropped.Add(1); n%1000 == 0 {
			s.log.Warn("hub sink buffer full, dropping entries", "dropped", n)
		}
	}
}

// run maintains the connection and drains the buffer until ctx is cancelled.
func (s *sink) run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.connect(); err != nil {
			s.log.Debug("hub connect failed, retrying", "url", s.hubURL, "err", err)
			if !sleepCtx(ctx, 2*time.Second) {
				return
			}
			continue
		}
		s.log.Info("connected to hub", "url", s.hubURL)
		s.pump(ctx)
		s.log.Debug("hub connection lost, reconnecting")
		if !sleepCtx(ctx, time.Second) {
			return
		}
	}
}

// sleepCtx waits d, returning false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (s *sink) connect() error {
	u, err := url.Parse(s.hubURL)
	if err != nil {
		return err
	}
	var hdr http.Header
	if s.hubToken != "" {
		hdr = http.Header{"Authorization": {"Bearer " + s.hubToken}}
	}
	conn, _, err := s.dialer.Dial(u.String(), hdr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	hello, _ := json.Marshal(api.Envelope{
		Type:  api.MsgHello,
		Hello: &api.Hello{Node: s.node, Version: config.Ver()},
	})
	return conn.WriteMessage(websocket.TextMessage, hello)
}

// reader consumes control frames (currently just pause/resume) from the hub
// on conn until it closes. Runs concurrently with pump's writes — gorilla's
// websocket.Conn supports one concurrent reader alongside one concurrent
// writer, which is exactly this split.
func (s *sink) reader(conn *websocket.Conn) {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var env api.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		if env.Type == api.MsgWorkerCommand && env.WorkerCommand != nil {
			prev := s.capturePaused.Swap(env.WorkerCommand.Paused)
			s.log.Info("capture pause state set by hub", "paused", env.WorkerCommand.Paused)
			if prev != env.WorkerCommand.Paused {
				select {
				case s.pauseChanged <- struct{}{}:
				default: // captureLoop hasn't drained the last wakeup yet — it'll re-check paused() then anyway
				}
			}
		}
	}
}

// assembleBatch marshals first plus whatever else is *already* queued on s.ch
// into a single frame, and returns that frame together with the entries it
// covers so a failed write can requeue exactly those and nothing else. It never
// blocks waiting for more: the drain stops at the first empty read.
//
// A lone entry goes out as a plain MsgEntry frame, byte-identical to what the
// worker sent before batching existed. That costs nothing to keep and means a
// version-skewed pair — a worker newer than its hub, which is what a rolling
// upgrade looks like for a few seconds — still delivers at low traffic instead
// of silently discarding everything into the hub's unknown-message default.
//
// Entries are marshaled individually and spliced, rather than marshaling one
// Envelope holding the slice, so the byte budget can be enforced as the batch
// grows. The first entry is always included even if it alone exceeds the
// budget: dropping it here would lose captured traffic to make a frame smaller.
func (s *sink) assembleBatch(first *api.Entry) ([]byte, []*api.Entry) {
	if first == nil {
		return nil, nil
	}
	b, err := json.Marshal(first)
	if err != nil {
		return nil, nil
	}
	raws := [][]byte{b}
	entries := []*api.Entry{first}
	size := len(b)

drain:
	for len(entries) < sinkBatchMaxEntries && size < sinkBatchMaxBytes {
		select {
		case e := <-s.ch:
			if e == nil {
				continue
			}
			eb, err := json.Marshal(e)
			if err != nil {
				continue // same silent skip a marshal failure got before batching
			}
			raws = append(raws, eb)
			entries = append(entries, e)
			size += len(eb)
		default:
			break drain // nothing else queued — send now rather than wait for more
		}
	}

	if len(raws) == 1 {
		frame := make([]byte, 0, len(`{"type":"entry","entry":}`)+len(raws[0]))
		frame = append(frame, `{"type":"entry","entry":`...)
		frame = append(frame, raws[0]...)
		return append(frame, '}'), entries
	}
	frame := make([]byte, 0, len(`{"type":"entryBatch","entries":[]}`)+size+len(raws))
	frame = append(frame, `{"type":"entryBatch","entries":[`...)
	for i, r := range raws {
		if i > 0 {
			frame = append(frame, ',')
		}
		frame = append(frame, r...)
	}
	return append(frame, `]}`...), entries
}

// pump writes buffered entries (plus a periodic self-report frame) to the
// current connection until it errors or ctx is cancelled.
func (s *sink) pump(ctx context.Context) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return
	}
	defer conn.Close()
	go s.reader(conn)

	write := func(b []byte) error {
		_ = conn.SetWriteDeadline(time.Now().Add(sinkWriteTimeout))
		return conn.WriteMessage(websocket.TextMessage, b)
	}

	stats := time.NewTicker(sinkStatsInterval)
	defer stats.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stats.C:
			b, err := json.Marshal(api.Envelope{Type: api.MsgWorkerStats, WorkerStats: &api.WorkerStats{
				Node:           s.node,
				EntriesSent:    s.sent.Load(),
				Dropped:        s.dropped.Load(),
				CaptureLive:    s.captureLive.Load(),
				CaptureTLS:     s.captureTLS.Load(),
				CapturePaused:  s.capturePaused.Load(),
				RingPackets:    s.ringPackets.Load(),
				RingDrops:      s.ringDrops.Load(),
				FlowsEvicted:   s.flowsEvicted.Load(),
				TLSLagDrops:    s.tlsLagDrops.Load(),
				TLSBudgetDrops: s.tlsBudgetDrops.Load(),
				TCPLossEvents:  s.tcpLossEvents.Load(),
			}})
			if err != nil {
				continue
			}
			if write(b) != nil {
				return
			}
		case e := <-s.ch:
			frame, batched := s.assembleBatch(e)
			if len(batched) == 0 {
				continue
			}
			if write(frame) != nil {
				// Requeue everything we failed to send, then bail to
				// reconnect. emit() drops on a full buffer exactly as it does
				// for fresh capture, so a wedged hub can't grow the queue.
				for _, re := range batched {
					s.emit(re)
				}
				return
			}
			s.sent.Add(uint64(len(batched)))
		}
	}
}
