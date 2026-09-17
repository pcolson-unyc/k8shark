//go:build linux

package ebpf

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// setupProcRoot copies testdata/maps.txt into <tmp>/<pid>/maps, mimicking the
// /proc/<pid>/maps layout scanPidMaps/discoverTargets read.
func setupProcRoot(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "maps.txt"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	pidDir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestScanPidMapsFindsUniqueTLSLibraries(t *testing.T) {
	root := setupProcRoot(t, 4242)
	targets, err := scanPidMaps(root, 4242)
	if err != nil {
		t.Fatal(err)
	}

	// testdata/maps.txt maps libssl.so.3 three times (dedup expected within
	// one pid's scan — seen[pathname] in scanPidMaps), libcrypto.so.3 once,
	// libgnutls.so.30 once (classified but unsupported), and libc.so.6/nginx
	// which must not match at all.
	byPath := map[string]libTarget{}
	for _, tg := range targets {
		if _, dup := byPath[tg.pathname]; dup {
			t.Errorf("duplicate target for %s within one pid scan", tg.pathname)
		}
		byPath[tg.pathname] = tg
	}

	ssl, ok := byPath["/usr/lib/x86_64-linux-gnu/libssl.so.3"]
	if !ok {
		t.Fatal("libssl.so.3 not discovered")
	}
	if ssl.kind != sslOpenSSL {
		t.Errorf("libssl.so.3 kind = %v, want sslOpenSSL", ssl.kind)
	}
	if ssl.devIno != "08:01:1234567" {
		t.Errorf("libssl.so.3 devIno = %q, want %q", ssl.devIno, "08:01:1234567")
	}

	crypto, ok := byPath["/usr/lib/x86_64-linux-gnu/libcrypto.so.3"]
	if !ok || crypto.kind != sslOpenSSL {
		t.Errorf("libcrypto.so.3 not discovered as sslOpenSSL: %+v (ok=%v)", crypto, ok)
	}

	gnutls, ok := byPath["/usr/lib/x86_64-linux-gnu/libgnutls.so.30"]
	if !ok || gnutls.kind != sslGnuTLS {
		t.Errorf("libgnutls.so.30 not discovered as sslGnuTLS: %+v (ok=%v)", gnutls, ok)
	}

	if _, ok := byPath["/usr/lib/x86_64-linux-gnu/libc.so.6"]; ok {
		t.Error("libc.so.6 should not match the TLS library regex")
	}
	if _, ok := byPath["/usr/bin/nginx"]; ok {
		t.Error("the main executable (nginx) should not match the TLS library regex")
	}
}

func TestDiscoverTargetsWalksAllPids(t *testing.T) {
	root := setupProcRoot(t, 100)
	// Add a second pid sharing the exact same library (same devIno) to
	// exercise the multi-pid walk; the per-library dedup-by-devIno itself is
	// attachTarget/rescan's job (see loader.go's s.attached map), not
	// discoverTargets's — it returns one entry per (pid, library) pair.
	raw, err := os.ReadFile(filepath.Join("testdata", "maps.txt"))
	if err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(root, "4343")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-numeric entry (e.g. "self", "thread-self") must be skipped, not
	// error the whole walk.
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	targets, complete, err := discoverTargets(root, discardTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("scan unexpectedly incomplete")
	}
	pids := map[int]int{}
	for _, tg := range targets {
		pids[tg.pid]++
	}
	if len(pids) != 2 {
		t.Errorf("discovered targets from %d pids, want 2 (100, 4343): %+v", len(pids), pids)
	}
}

func discardTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}
