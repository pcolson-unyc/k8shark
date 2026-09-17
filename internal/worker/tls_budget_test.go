package worker

import (
	"context"
	"github.com/pablocolson/k8shark/internal/worker/ebpf"
	"io"
	"testing"
	"time"
)

func TestTLSBudgetAdmissionAndCleanup(t *testing.T) {
	s := newSink("", "", "n", discardLogger())
	p := newPipeline(s, "n", "", discardLogger())
	src := newFakeTLSSource()
	b := newTLSByteBudget(32)
	src.ch <- ebpf.TLSRecord{ConnID: 1, Direction: ebpf.TLSDirWrite, Data: []byte("G")}
	src.ch <- ebpf.TLSRecord{ConnID: 2, Direction: ebpf.TLSDirWrite, Data: []byte("G")}
	close(src.ch)
	p.consumeTLSBounded(context.Background(), src, 1, b)
	if s.tlsBudgetDrops.Load() != 1 {
		t.Fatal("stream admission drop not counted")
	}
	deadline := time.Now().Add(time.Second)
	for {
		b.mu.Lock()
		used := b.used
		b.mu.Unlock()
		if used == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("parser exit retained %d bytes", used)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTLSBudgetDiscardRejectsFurtherData(t *testing.T) {
	b := newTLSByteBudget(20)
	c := newChanPipe(2, b)
	c.push([]byte("abcdef"))
	if _, err := c.Read(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	c.push([]byte("queued"))
	c.discard()
	c.discard()
	c.push([]byte("late"))
	if b.used != 0 || len(c.ch) != 0 || c.buf != nil {
		t.Fatal("discard retained payload or admitted new data")
	}
}

func TestTLSBudgetOverflowUnblocksWaitingReader(t *testing.T) {
	b := newTLSByteBudget(1)
	c := newChanPipe(1, b)
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	c.push([]byte("too big"))
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("got %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("budget overflow left reader blocked")
	}
}

func TestTLSBudgetPipeLifecycle(t *testing.T) {
	b := newTLSByteBudget(5)
	c := newChanPipe(4, b)
	c.push([]byte("hello"))
	out := make([]byte, 2)
	if n, _ := c.Read(out); n != 2 {
		t.Fatal(n)
	}
	b.mu.Lock()
	used := b.used
	b.mu.Unlock()
	if used != 5 {
		t.Fatalf("partial read released budget: %d", used)
	}
	if _, err := c.Read(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	used = b.used
	b.mu.Unlock()
	if used != 0 {
		t.Fatalf("fully consumed chunk retained budget: %d", used)
	}

	c.push([]byte("prefix")) // over budget: marks EOF, but retains no new bytes
	c.Close()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("overflow read err=%v", err)
	}
	c.discard()
	b.mu.Lock()
	used = b.used
	b.mu.Unlock()
	if used != 0 {
		t.Fatalf("discard retained budget: %d", used)
	}
}

func TestTLSBudgetClosePreservesPrefixAndOverflowWakes(t *testing.T) {
	b := newTLSByteBudget(100)
	c := newChanPipe(2, b)
	c.push([]byte("prefix"))
	c.Close()
	out := make([]byte, 6)
	if n, err := c.Read(out); n != 6 || err != nil {
		t.Fatalf("prefix n=%d err=%v", n, err)
	}
	if _, err := c.Read(out); err != io.EOF {
		t.Fatal(err)
	}

	b = newTLSByteBudget(2)
	c = newChanPipe(1, b)
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	time.Sleep(time.Millisecond)
	c.push([]byte("too big"))
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("overflow did not wake reader")
	}
	if b.drops.Load() != 1 {
		t.Fatalf("drops=%d", b.drops.Load())
	}
}
