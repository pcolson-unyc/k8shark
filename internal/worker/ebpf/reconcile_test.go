//go:build linux

package ebpf

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

type countedLink struct {
	link.Link
	closes int
}

func (l *countedLink) Close() error { l.closes++; return nil }

func TestAttachmentLifecycle(t *testing.T) {
	s := &linuxSource{cfg: Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, attached: map[string]*attachment{}, grace: time.Minute}
	static, dynamic := &countedLink{}, &countedLink{}
	s.staticLinks = []link.Link{static}
	calls := 0
	attach := func(libTarget) ([]link.Link, error) { calls++; return []link.Link{dynamic}, nil }
	targets := []libTarget{{devIno: "same", pid: 1}, {devIno: "same", pid: 2}}
	now := time.Unix(100, 0)
	s.reconcileAttachments(targets, true, now, attach)
	if calls != 1 || len(s.attached) != 1 {
		t.Fatal("shared inode attached twice")
	}
	s.reconcileAttachments(nil, true, now.Add(30*time.Second), attach)
	if dynamic.closes != 0 {
		t.Fatal("closed before grace")
	}
	s.reconcileAttachments(targets, true, now.Add(50*time.Second), attach)
	s.reconcileAttachments(nil, true, now.Add(70*time.Second), attach)
	if dynamic.closes != 0 {
		t.Fatal("reappearance did not refresh grace")
	}
	s.reconcileAttachments(nil, false, now.Add(2*time.Minute), attach)
	if dynamic.closes != 0 {
		t.Fatal("incomplete scan detached probes")
	}
	s.reconcileAttachments(nil, true, now.Add(3*time.Minute), attach)
	if dynamic.closes != 1 || len(s.attached) != 0 || static.closes != 0 {
		t.Fatal("stale ownership not released precisely")
	}
	second := &countedLink{}
	s.reconcileAttachments(targets, true, now.Add(4*time.Minute), func(libTarget) ([]link.Link, error) { return []link.Link{second}, nil })
	s.closeAttachments()
	s.closeAttachments()
	if dynamic.closes != 1 || second.closes != 1 || static.closes != 1 {
		t.Fatal("links were not closed exactly once")
	}
}

func TestAttachmentFailureDoesNotCreateOwnership(t *testing.T) {
	s := &linuxSource{cfg: Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, attached: map[string]*attachment{}, grace: time.Minute}
	s.reconcileAttachments([]libTarget{{devIno: "bad"}}, true, time.Now(), func(libTarget) ([]link.Link, error) { return nil, errors.New("exited") })
	if len(s.attached) != 0 {
		t.Fatal("failed attach retained")
	}
}

func TestDiscoveryReportsIncompleteScan(t *testing.T) {
	root := setupProcRoot(t, 42)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, complete, err := discoverTargets(root, log); err != nil || !complete {
		t.Fatalf("healthy scan: %v %v", complete, err)
	}
	if err := os.MkdirAll(filepath.Join(root, "43", "maps"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := discoverTargets(root, log); err != nil || complete {
		t.Fatalf("partial scan: %v %v", complete, err)
	}
	if _, complete, err := discoverTargets(filepath.Join(root, "absent"), log); err == nil || complete {
		t.Fatal("root failure was complete")
	}
}
