package hub

// TST-2: an end-to-end test over real WebSockets exercising the product's
// central path — a worker connects (/ws/worker, MsgHello), pushes entries, and
// a front client (/ws) receives them live, server-side filtered, plus the
// hub->worker command round-trip (pause capture). server_test.go covers each
// REST handler in isolation via httptest.NewRecorder; nothing else drives the
// WS fan-out, the live filter, or the Envelope contract between the three
// components. This locks that contract before Phase 3 refactors it.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pablocolson/k8shark/pkg/api"
)

// wsURL rewrites an httptest http:// base into a ws:// URL for a given path.
func wsURL(base, path string) string {
	return strings.Replace(base, "http://", "ws://", 1) + path
}

// dialWS opens a WebSocket to url with optional headers, failing the test on
// error.
func dialWS(t *testing.T, url string, hdr http.Header) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(url, hdr)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	return c
}

// readEnvelope reads one frame with a deadline and decodes it.
func readEnvelope(t *testing.T, c *websocket.Conn) api.Envelope {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var env api.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("decode frame %q: %v", data, err)
	}
	return env
}

func writeEnvelope(t *testing.T, c *websocket.Conn, env api.Envelope) {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
}

func httpEntry(id string) *api.Entry {
	return &api.Entry{
		ID:        id,
		Protocol:  api.ProtocolHTTP,
		Timestamp: time.Now(),
		Status:    "success",
		Request:   api.Payload{Method: "GET", Path: "/" + id, Summary: "GET /" + id},
		Response:  api.Payload{StatusCode: 200, Summary: "200 OK"},
	}
}

// TestE2EWorkerToFrontRoundTrip drives worker -> hub -> front over real
// WebSockets: the front, subscribed with a server-side filter, must receive
// only the matching entries; the REST snapshot must show all of them; the
// registry must show the worker; and a POST /api/workers/capture command must
// reach the worker. Auth is enabled to also cover both token paths (Bearer
// header for the worker, ?token= for the browser-style front WS).
func TestE2EWorkerToFrontRoundTrip(t *testing.T) {
	const token = "e2e-secret"
	s := New(discardLogger(), Options{APIToken: token})
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	bearer := http.Header{"Authorization": {"Bearer " + token}}

	// --- worker connects and identifies itself ---
	worker := dialWS(t, wsURL(ts.URL, "/ws/worker"), bearer)
	defer worker.Close()
	writeEnvelope(t, worker, api.Envelope{Type: api.MsgHello, Hello: &api.Hello{Node: "node-a", Version: "test"}})

	// The registry row is written on the hub's read goroutine; poll briefly.
	waitFor(t, func() bool {
		for _, wi := range s.workerSnapshot() {
			if wi.Node == "node-a" && wi.Connected {
				return true
			}
		}
		return false
	}, "worker to register as connected")

	// --- front subscribes with a server-side filter (http only) ---
	frontQ := url.Values{"filter": {`protocol == "http"`}, "token": {token}}
	front := dialWS(t, wsURL(ts.URL, "/ws?"+frontQ.Encode()), nil)
	defer front.Close()
	// On connect the front is sent a stats frame (history is empty here).
	if env := readEnvelope(t, front); env.Type != api.MsgStats {
		t.Fatalf("first front frame type = %q, want %q", env.Type, api.MsgStats)
	}

	// --- worker pushes three entries: two http (match), one redis (filtered) ---
	writeEnvelope(t, worker, api.Envelope{Type: api.MsgEntry, Entry: httpEntry("h1")})
	writeEnvelope(t, worker, api.Envelope{Type: api.MsgEntry, Entry: &api.Entry{
		ID: "r1", Protocol: api.ProtocolRedis, Timestamp: time.Now(), Status: "success",
		Request: api.Payload{Command: "GET k"},
	}})
	writeEnvelope(t, worker, api.Envelope{Type: api.MsgEntry, Entry: httpEntry("h2")})

	// The front must receive exactly the two http entries, in order, and never
	// the redis one (server-side filtered out before fan-out). Live entries
	// arrive as MsgEntryBatch frames (HUB-4 coalesces the fan-out); how the
	// two entries split across batches depends on timing, so collect until
	// both are seen.
	var got []string
	for len(got) < 2 {
		env := readEnvelope(t, front)
		if env.Type != api.MsgEntryBatch { // stats frames may interleave; ignore
			continue
		}
		for _, e := range env.Entries {
			if e.Protocol != api.ProtocolHTTP {
				t.Fatalf("front received a non-http entry despite the filter: %+v", e)
			}
			got = append(got, e.ID)
		}
	}
	if got[0] != "h1" || got[1] != "h2" {
		t.Errorf("front entry IDs = %v, want [h1 h2]", got)
	}

	// --- REST snapshot sees all three (unfiltered), newest first ---
	all := getEntries(t, ts.URL, token, "")
	if len(all) != 3 {
		t.Fatalf("/api/entries returned %d entries, want 3", len(all))
	}
	// A filtered REST query must match the live filter's behavior.
	httpOnly := getEntries(t, ts.URL, token, `protocol == "http"`)
	if len(httpOnly) != 2 {
		t.Errorf("/api/entries?filter=http returned %d, want 2", len(httpOnly))
	}

	// --- hub -> worker command round-trip: pause capture ---
	body := strings.NewReader(`{"node":"node-a","paused":true}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/workers/capture", body)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/workers/capture: %v", err)
	}
	var sent struct {
		Sent int `json:"sent"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sent)
	resp.Body.Close()
	if sent.Sent != 1 {
		t.Errorf("capture command reached %d workers, want 1", sent.Sent)
	}
	// The worker must actually receive the command frame.
	cmd := readEnvelope(t, worker)
	if cmd.Type != api.MsgWorkerCommand || cmd.WorkerCommand == nil || !cmd.WorkerCommand.Paused {
		t.Errorf("worker command = %+v, want MsgWorkerCommand paused=true", cmd)
	}
}

// TestE2EBadTokenRejected confirms the WS endpoints enforce the API token: a
// wrong token fails the upgrade rather than silently exposing captured traffic.
func TestE2EBadTokenRejected(t *testing.T) {
	s := New(discardLogger(), Options{APIToken: "right"})
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	_, resp, err := websocket.DefaultDialer.Dial(wsURL(ts.URL, "/ws/worker"),
		http.Header{"Authorization": {"Bearer wrong"}})
	if err == nil {
		t.Fatal("dial with a wrong token succeeded, want rejection")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-token upgrade status = %v, want 401", resp)
	}
}

// getEntries GETs /api/entries with an optional filter and decodes the array.
func getEntries(t *testing.T, base, token, filter string) []api.Entry {
	t.Helper()
	u := base + "/api/entries"
	if filter != "" {
		u += "?filter=" + url.QueryEscape(filter)
	}
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", u, resp.StatusCode)
	}
	var entries []api.Entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("decode entries: %v", err)
	}
	return entries
}

// waitFor polls cond up to ~2s, failing the test with what if it never holds.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestReplayHistoryChunksChronological: HUB-4 replays history as chunked
// MsgEntryBatch frames assembled from the store's cached JSON. 250 entries
// must arrive as 3 frames (100+100+50) whose concatenated entries are in
// strict chronological order.
func TestReplayHistoryChunksChronological(t *testing.T) {
	s := New(discardLogger(), Options{})
	for i := 0; i < 250; i++ {
		s.store.add(httpEntry(fmt.Sprintf("e%03d", i)))
	}
	c := &frontClient{send: make(chan []byte, 16)}
	s.replayHistory(c, nil)
	close(c.send)

	var ids []string
	frames := 0
	for b := range c.send {
		var env api.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatalf("frame %d is not valid JSON: %v", frames, err)
		}
		if env.Type != api.MsgEntryBatch {
			t.Fatalf("frame type = %q, want %q", env.Type, api.MsgEntryBatch)
		}
		frames++
		for _, e := range env.Entries {
			ids = append(ids, e.ID)
		}
	}
	if frames != 3 {
		t.Errorf("frames = %d, want 3 (250 entries chunked by %d)", frames, replayBatchSize)
	}
	if len(ids) != 250 || ids[0] != "e000" || ids[len(ids)-1] != "e249" {
		t.Fatalf("got %d ids, first %q last %q; want 250, e000..e249", len(ids), ids[0], ids[len(ids)-1])
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("chronological order breaks at %d: %s >= %s", i, ids[i-1], ids[i])
		}
	}
}

// TestConnectSnapshotBeforeRegisterAvoidsDuplicate is a regression test for a
// hub-side race that showed up in the UI as duplicate ("ghost") rows right
// after a page reload: store.add() always runs before broadcast() (see the
// MsgEntry handler in server.go), so a client that gets registered into
// s.frontClients *before* its history snapshot is taken can have an entry
// land in the gap and be delivered twice — once in the snapshot, once again
// via the live broadcast flush now that it's registered. handleFront and
// frontReader's filter-swap handler now snapshot first and register/switch
// c.pred after, closing that window. This drives the same primitives by hand
// (flushing on demand instead of waiting out the real 30ms timer) to place an
// entry's broadcast() call exactly in that gap and assert it isn't
// duplicated, plus that ordinary post-registration live delivery still
// works.
func TestConnectSnapshotBeforeRegisterAvoidsDuplicate(t *testing.T) {
	s := New(discardLogger(), Options{})
	c := &frontClient{send: make(chan []byte, 16)}

	// e1 is already in the store by the time the snapshot is taken.
	e1 := httpEntry("e1")
	raw1 := s.store.add(e1)
	s.replayHistory(c, nil) // mirrors handleFront: snapshot before registering

	// Its broadcast() call (made by the worker-ingest goroutine, independent
	// of handleFront's timing) lands in the gap between the snapshot above
	// and registration below — the exact window this fix narrows.
	s.broadcast(e1, raw1)

	s.mu.Lock()
	s.frontClients[c] = struct{}{}
	s.mu.Unlock()

	s.flushBroadcast() // simulate the 30ms timer firing

	// e2 arrives normally, after c is registered: ordinary live delivery.
	e2 := httpEntry("e2")
	raw2 := s.store.add(e2)
	s.broadcast(e2, raw2)
	s.flushBroadcast()

	close(c.send)
	var ids []string
	for b := range c.send {
		var env api.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatalf("decode frame: %v", err)
		}
		for _, e := range env.Entries {
			ids = append(ids, e.ID)
		}
	}
	if len(ids) != 2 || ids[0] != "e1" || ids[1] != "e2" {
		t.Fatalf("got ids %v, want exactly one delivery each of [e1 e2]", ids)
	}
}

// TestE2EReplayArrivesAsBatches: a front connecting after traffic exists gets
// the history over the real WebSocket as MsgEntryBatch frames.
func TestE2EReplayArrivesAsBatches(t *testing.T) {
	s := New(discardLogger(), Options{})
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	for i := 0; i < 5; i++ {
		e := httpEntry(fmt.Sprintf("h%d", i))
		raw := s.store.add(e)
		s.broadcast(e, raw) // no front clients yet: fast-path no-op
	}

	front := dialWS(t, wsURL(ts.URL, "/ws"), nil)
	defer front.Close()

	var ids []string
	for len(ids) < 5 {
		env := readEnvelope(t, front)
		if env.Type != api.MsgEntryBatch { // the initial stats frame interleaves
			continue
		}
		for _, e := range env.Entries {
			ids = append(ids, e.ID)
		}
	}
	for i, id := range ids {
		if want := fmt.Sprintf("h%d", i); id != want {
			t.Fatalf("replay ids = %v, want chronological h0..h4", ids)
		}
	}
}
