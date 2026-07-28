package worker

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pablocolson/k8shark/pkg/api"
)

// TestSinkReaderPause exercises sink.reader() against a real WebSocket pair
// (a fake hub server + the sink's own client connection) since it needs an
// actual *websocket.Conn, not a fakeable interface: a MsgWorkerCommand frame
// sent from the "hub" side must flip s.paused(), and a resume must flip it
// back — the exact mechanism route()/consumeTLS/runDemo all gate on.
func TestSinkReaderPause(t *testing.T) {
	upgrader := websocket.Upgrader{}
	var hubConn *websocket.Conn
	connected := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("hub-side upgrade: %v", err)
			return
		}
		hubConn = c
		close(connected)
	}))
	defer srv.Close()

	s := newSink("ws://"+srv.Listener.Addr().String(), "", "n", discardLogger())
	if err := s.connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	<-connected
	defer hubConn.Close()

	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	go s.reader(conn)

	if s.paused() {
		t.Fatal("sink starts paused, want capturing")
	}

	send := func(paused bool) {
		b, _ := json.Marshal(api.Envelope{Type: api.MsgWorkerCommand, WorkerCommand: &api.WorkerCommand{Paused: paused}})
		if err := hubConn.WriteMessage(websocket.TextMessage, b); err != nil {
			t.Fatalf("hub write: %v", err)
		}
	}
	waitFor := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if s.paused() == want {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("paused() = %v after deadline, want %v", s.paused(), want)
	}

	send(true)
	waitFor(true)

	send(false)
	waitFor(false)
}

// TestSinkReaderNotifiesPauseChangedOnlyOnRealTransitions checks the signal
// captureLoop relies on to actually close/reopen the AF_PACKET source: it
// must fire on a genuine flip, and must NOT fire when the hub resends the
// same state (which would otherwise make captureLoop redundantly close an
// already-closed source, or reopen an already-open one).
func TestSinkReaderNotifiesPauseChangedOnlyOnRealTransitions(t *testing.T) {
	upgrader := websocket.Upgrader{}
	var hubConn *websocket.Conn
	connected := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("hub-side upgrade: %v", err)
			return
		}
		hubConn = c
		close(connected)
	}))
	defer srv.Close()

	s := newSink("ws://"+srv.Listener.Addr().String(), "", "n", discardLogger())
	if err := s.connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	<-connected
	defer hubConn.Close()

	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	go s.reader(conn)

	send := func(paused bool) {
		b, _ := json.Marshal(api.Envelope{Type: api.MsgWorkerCommand, WorkerCommand: &api.WorkerCommand{Paused: paused}})
		if err := hubConn.WriteMessage(websocket.TextMessage, b); err != nil {
			t.Fatalf("hub write: %v", err)
		}
	}
	drainNotify := func(want bool) {
		t.Helper()
		// Proving a real transition fires can need to wait out the reader
		// goroutine's scheduling; proving a no-op resend does NOT fire only
		// needs long enough to rule out a slow, wrongly-fired signal, so a
		// short bound there keeps the common (no-op) case fast.
		timeout := 100 * time.Millisecond
		if want {
			timeout = 2 * time.Second
		}
		select {
		case <-s.pauseChanged:
			if !want {
				t.Fatal("pauseChanged fired for a no-op resend")
			}
		case <-time.After(timeout):
			if want {
				t.Fatal("pauseChanged never fired for a real transition")
			}
		}
	}

	send(true) // false -> true: real transition
	drainNotify(true)

	send(true) // true -> true: resend, no transition
	drainNotify(false)

	send(false) // true -> false: real transition
	drainNotify(true)
}

// TestSetHubCA covers the SEC-7 CA loading paths: a bad path and a PEM
// without certificates must error; a valid CA installs a custom dialer.
func TestSetHubCA(t *testing.T) {
	s := newSink("wss://x", "", "n", discardLogger())
	if err := s.setHubCA("/no/such/file.pem"); err == nil {
		t.Error("missing file: want error")
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.setHubCA(junk); err == nil {
		t.Error("junk PEM: want error")
	}
	if s.dialer != websocket.DefaultDialer {
		t.Fatal("failed loads must leave the default dialer in place")
	}
}

// TestSinkConnectsWSSWithCustomCA dials a real TLS WebSocket server whose
// self-signed cert is trusted only via setHubCA — locking the worker's wss://
// path end to end: without the CA the dial must fail, with it it must succeed.
func TestSinkConnectsWSSWithCustomCA(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Consume the hello frame so connect()'s write lands.
		_, _, _ = c.ReadMessage()
		c.Close()
	}))
	defer srv.Close()
	wssURL := "wss://" + srv.Listener.Addr().String()

	noCA := newSink(wssURL, "", "n", discardLogger())
	if err := noCA.connect(); err == nil {
		t.Fatal("dial without the CA succeeded, want certificate verification failure")
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newSink(wssURL, "", "n", discardLogger())
	if err := s.setHubCA(caFile); err != nil {
		t.Fatalf("setHubCA: %v", err)
	}
	if err := s.connect(); err != nil {
		t.Fatalf("wss connect with custom CA: %v", err)
	}
}

// --- WRK-BATCH: worker -> hub entry batching --------------------------------

// workerReadLimitMirror is a hand-kept copy of hub.workerReadLimit
// (internal/hub/server.go). The worker package deliberately does not import the
// hub — that would drag gopacket's dependency tree into the hub binary — so the
// coupling is enforced by this mirror plus the cross-referencing comments on
// both constants. If the hub lowers its read limit, this test starts failing,
// which is the point.
const workerReadLimitMirror = 4 << 20

// batchEntry builds an entry whose marshaled size is roughly padBytes, so the
// byte-budget cases below can be expressed in entry counts. The padding is
// printable ASCII on purpose: NUL bytes JSON-escape to a 6-character \u0000
// sequence, which would make the marshaled size 6x the padding and the budget
// assertions meaningless.
func batchEntry(id string, padBytes int) *api.Entry {
	e := &api.Entry{
		ID: id, Protocol: api.ProtocolHTTP, Timestamp: time.Unix(0, 0).UTC(),
		Status: "success",
	}
	if padBytes > 0 {
		e.Request.Body = strings.Repeat("x", padBytes)
	}
	return e
}

// decodeFrame unmarshals a frame assembled by assembleBatch. The frames are
// hand-spliced rather than produced by json.Marshal(Envelope{...}), so this
// also proves the splice yields valid JSON in the shape the hub expects.
func decodeFrame(t *testing.T, frame []byte) api.Envelope {
	t.Helper()
	var env api.Envelope
	if err := json.Unmarshal(frame, &env); err != nil {
		t.Fatalf("assembled frame is not valid JSON: %v\nframe: %s", err, frame)
	}
	return env
}

// TestAssembleBatchSingleEntryStaysMsgEntry pins the version-skew guarantee: a
// lone entry must go out as a plain MsgEntry frame, exactly as it did before
// batching existed, so a worker newer than its hub still delivers.
func TestAssembleBatchSingleEntryStaysMsgEntry(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	frame, batched := s.assembleBatch(batchEntry("a", 0))
	if len(batched) != 1 || batched[0].ID != "a" {
		t.Fatalf("batched = %+v, want exactly entry a", batched)
	}
	env := decodeFrame(t, frame)
	if env.Type != api.MsgEntry {
		t.Errorf("type = %q, want %q", env.Type, api.MsgEntry)
	}
	if env.Entry == nil || env.Entry.ID != "a" {
		t.Errorf("entry = %+v, want a", env.Entry)
	}
	if len(env.Entries) != 0 {
		t.Errorf("entries = %+v, want empty on a single-entry frame", env.Entries)
	}
}

// TestAssembleBatchCoalescesQueued covers the actual win: everything already
// sitting on the channel goes out in one frame, oldest first.
func TestAssembleBatchCoalescesQueued(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	first := batchEntry("a", 0)
	for _, id := range []string{"b", "c", "d"} {
		s.emit(batchEntry(id, 0))
	}
	frame, batched := s.assembleBatch(first)
	if len(batched) != 4 {
		t.Fatalf("batched %d entries, want 4", len(batched))
	}
	env := decodeFrame(t, frame)
	if env.Type != api.MsgEntryBatch {
		t.Fatalf("type = %q, want %q", env.Type, api.MsgEntryBatch)
	}
	var ids []string
	for _, e := range env.Entries {
		ids = append(ids, e.ID)
	}
	want := []string{"a", "b", "c", "d"}
	for i := range want {
		if i >= len(ids) || ids[i] != want[i] {
			t.Fatalf("entry IDs = %v, want %v (oldest first)", ids, want)
		}
	}
	if len(s.ch) != 0 {
		t.Errorf("%d entries left queued, want the batch to have drained them", len(s.ch))
	}
}

// TestAssembleBatchStopsAtEntryCap keeps the frame bounded by count even when
// the channel is deeper than one batch, and leaves the remainder queued for the
// next iteration rather than dropping it.
func TestAssembleBatchStopsAtEntryCap(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	const extra = 10
	for i := 0; i < sinkBatchMaxEntries+extra; i++ {
		s.emit(batchEntry("q", 0))
	}
	_, batched := s.assembleBatch(batchEntry("first", 0))
	if len(batched) != sinkBatchMaxEntries {
		t.Errorf("batched %d entries, want the %d cap", len(batched), sinkBatchMaxEntries)
	}
	// first + cap-1 drained from the channel, so the remainder stays queued.
	if got, want := len(s.ch), extra+1; got != want {
		t.Errorf("%d entries left queued, want %d", got, want)
	}
}

// TestAssembleBatchStopsAtByteBudget is the one that keeps the hub connection
// alive: an oversized frame is not truncated by gorilla, it fails the read and
// kills the connection, so the budget must bind before workerReadLimit does.
func TestAssembleBatchStopsAtByteBudget(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	const pad = 64 << 10 // 8 of these exceed the 512 KiB budget
	for i := 0; i < 32; i++ {
		s.emit(batchEntry("q", pad))
	}
	frame, batched := s.assembleBatch(batchEntry("first", pad))
	if len(batched) >= 32 {
		t.Errorf("batched %d entries — the byte budget never bound", len(batched))
	}
	// The budget is checked before appending, so the frame can overshoot by at
	// most one entry plus the envelope wrapper.
	if max := sinkBatchMaxBytes + 2*pad; len(frame) > max {
		t.Errorf("frame is %d bytes, want <= %d", len(frame), max)
	}
	if len(frame) > workerReadLimitMirror {
		t.Errorf("frame is %d bytes, over the hub's %d read limit", len(frame), workerReadLimitMirror)
	}
}

// TestAssembleBatchAlwaysIncludesFirst: a single entry larger than the whole
// byte budget must still be sent. Dropping it would lose captured traffic
// purely to make a frame smaller.
func TestAssembleBatchAlwaysIncludesFirst(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	frame, batched := s.assembleBatch(batchEntry("huge", sinkBatchMaxBytes*2))
	if len(batched) != 1 || batched[0].ID != "huge" {
		t.Fatalf("batched = %+v, want the oversized entry kept", batched)
	}
	if env := decodeFrame(t, frame); env.Entry == nil || env.Entry.ID != "huge" {
		t.Errorf("frame did not carry the oversized entry")
	}
}
