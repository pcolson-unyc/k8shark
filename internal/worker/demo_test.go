package worker

import (
	"testing"
	"time"
)

// TestRunDemoRespectsPause: a demo worker is still a worker as far as the
// hub's pause/resume control is concerned (see sink.reader) — runDemo must
// stop emitting while paused and resume immediately once unpaused, the same
// contract route()/consumeTLS hold for real capture.
func TestRunDemoRespectsPause(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	s.capturePaused.Store(true)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runDemo(s, "n", "1.2.3.4", 1000, stop) // high rps: a few ms is many opportunities to (wrongly) emit
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	<-done

	select {
	case e := <-s.ch:
		t.Fatalf("runDemo emitted %v while paused, want nothing", e.ID)
	default:
	}

	// Unpaused, it emits normally.
	s.capturePaused.Store(false)
	stop = make(chan struct{})
	done = make(chan struct{})
	go func() {
		runDemo(s, "n", "1.2.3.4", 1000, stop)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	<-done

	select {
	case <-s.ch:
	default:
		t.Fatal("runDemo emitted nothing once unpaused")
	}
}
