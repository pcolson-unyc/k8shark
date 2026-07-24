package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pablocolson/k8shark/internal/worker/capture"
)

// fakeSource is a capture.PacketSource double that never touches a real
// socket — captureLoop's pause/resume close-and-reopen logic only needs the
// interface, and AF_PACKET itself is Linux-only (see CLAUDE.md), so this is
// the only way to exercise that logic in CI on any platform.
type fakeSource struct {
	ch     chan gopacket.Packet
	closed atomic.Bool
}

func newFakeSource() *fakeSource {
	return &fakeSource{ch: make(chan gopacket.Packet)}
}

func (f *fakeSource) Packets() <-chan gopacket.Packet  { return f.ch }
func (f *fakeSource) Stats() (capture.RingStats, bool) { return capture.RingStats{}, false }
func (f *fakeSource) Close() error {
	if !f.closed.CompareAndSwap(false, true) {
		return errors.New("fakeSource: double close")
	}
	close(f.ch)
	return nil
}

// setPaused mirrors exactly what sink.reader() does on a MsgWorkerCommand
// frame — used here to drive captureLoop without a real WebSocket, since
// TestSinkReaderPause/TestSinkReaderNotifiesPauseChangedOnlyOnRealTransitions
// (sink_test.go) already cover that reader()->pauseChanged wiring itself.
func setPaused(s *sink, paused bool) {
	prev := s.capturePaused.Swap(paused)
	if prev != paused {
		select {
		case s.pauseChanged <- struct{}{}:
		default:
		}
	}
}

func waitForBool(t *testing.T, get func() bool, want bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if get() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s = %v after deadline, want %v", what, get(), want)
}

// TestCaptureLoopClosesAndReopensOnPause is the core regression test for the
// "pause capture" feature actually reducing worker CPU/RAM: before this, a
// pause only made route() drop what it read, but AF_PACKET itself (and its
// ~48MB ring mmap) stayed open and fully decoding every packet regardless.
// Now captureLoop must Close() the source on pause and call reopen() on
// resume, flipping captureLive to match at each edge.
func TestCaptureLoopClosesAndReopensOnPause(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())

	first := newFakeSource()
	var second *fakeSource
	var reopenCalls atomic.Int32
	reopen := func() (capture.PacketSource, error) {
		reopenCalls.Add(1)
		second = newFakeSource()
		return second, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan error, 1)
	go func() { loopDone <- captureLoop(ctx, discardLogger(), p, first, reopen) }()

	setPaused(s, true)
	waitForBool(t, func() bool { return first.closed.Load() }, true, "first.closed")
	waitForBool(t, s.captureLive.Load, false, "captureLive")

	setPaused(s, false)
	waitForBool(t, func() bool { return reopenCalls.Load() == 1 }, true, "reopenCalls")
	waitForBool(t, s.captureLive.Load, true, "captureLive")
	if second == nil {
		t.Fatal("reopen ran but never produced a second source")
	}
	if second.closed.Load() {
		t.Fatal("the freshly reopened source must not already be closed")
	}

	// A packet fed through the *reopened* source must still reach route() —
	// proves captureLoop is actually selecting on the new channel, not a
	// stale reference to the closed first one.
	tc := layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodeNoRouteToDst)
	pkt := mkICMPv6Packet(t, "2001:db8::1", "2001:db8::2", tc)
	second.ch <- pkt
	waitForBool(t, func() bool { return len(drain(s)) > 0 }, true, "post-reopen entry delivery")

	cancel()
	select {
	case err := <-loopDone:
		if err != nil {
			t.Fatalf("captureLoop returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("captureLoop did not return after ctx cancellation")
	}
	if !second.closed.Load() {
		t.Fatal("ctx cancellation must close whatever source captureLoop currently holds")
	}
}

// TestCaptureLoopIgnoresPauseWithoutReopen covers pcap/demo: no reopen func
// (see Run) must leave the source alone across a pause/resume edge — closing
// it would misreport a finite replay as merely "paused."
func TestCaptureLoopIgnoresPauseWithoutReopen(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	src := newFakeSource()

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan error, 1)
	go func() { loopDone <- captureLoop(ctx, discardLogger(), p, src, nil) }()

	setPaused(s, true)
	setPaused(s, false)
	time.Sleep(50 * time.Millisecond) // let captureLoop process both edges
	if src.closed.Load() {
		t.Fatal("source must not be closed when captureLoop has no reopen func")
	}

	cancel()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("captureLoop did not return after ctx cancellation")
	}
	// Ownership stays with the caller (Run's own defer) in this mode.
	if src.closed.Load() {
		t.Fatal("captureLoop must not close a source it doesn't own (reopen == nil)")
	}
}

// TestCaptureLoopReopenFailureLeavesCaptureOff proves a failed reopen doesn't
// panic or wedge the loop — capture just stays off (visible via captureLive
// at /api/workers) until the next pause/resume edge retries.
func TestCaptureLoopReopenFailureLeavesCaptureOff(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "1.2.3.4", discardLogger())
	first := newFakeSource()

	reopenErr := errors.New("boom")
	reopen := func() (capture.PacketSource, error) { return nil, reopenErr }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopDone := make(chan error, 1)
	go func() { loopDone <- captureLoop(ctx, discardLogger(), p, first, reopen) }()

	setPaused(s, true)
	waitForBool(t, s.captureLive.Load, false, "captureLive after pause")

	setPaused(s, false)
	time.Sleep(50 * time.Millisecond) // give the failed reopen a chance to (not) flip anything
	if s.captureLive.Load() {
		t.Fatal("captureLive must stay false after a failed reopen")
	}

	cancel()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("captureLoop did not return after ctx cancellation")
	}
}
