//go:build linux

package ebpf

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// sslKind classifies which TLS library a mapped file is, so we know which
// probe set applies (and can log-and-skip the ones we don't support yet).
type sslKind int

const (
	sslUnknown sslKind = iota
	sslOpenSSL         // libssl.so*/libcrypto.so* — covers boringssl too (same SSL_* ABI)
	sslGnuTLS          // libgnutls.so* — different symbol names, not probed (Phase 2a scope)
)

// libPathRE matches the shared TLS libraries we can discover from a mapped
// file's pathname in /proc/<pid>/maps.
var libPathRE = regexp.MustCompile(`/(libssl|libcrypto|libgnutls)[-.](?:[^/]*\.)?so(?:\.[0-9]+)*$`)

// sslSymbol is one uprobe/uretprobe pair (or single uprobe) we try to attach
// per discovered OpenSSL-ABI-compatible library. Matches bpf/tls.bpf.c's
// SEC() names exactly.
type sslSymbol struct {
	fn         string // ELF symbol name in the target library
	uprobeProg string // program name for the entry hook ("" = none)
	uretProg   string // program name for the return hook ("" = none)
}

var sslSymbols = []sslSymbol{
	{fn: "SSL_write", uprobeProg: "uprobe_ssl_write"},
	{fn: "SSL_write_ex", uprobeProg: "uprobe_ssl_write_ex", uretProg: "uretprobe_ssl_write_ex"},
	{fn: "SSL_read", uprobeProg: "uprobe_ssl_read", uretProg: "uretprobe_ssl_read"},
	{fn: "SSL_read_ex", uprobeProg: "uprobe_ssl_read_ex", uretProg: "uretprobe_ssl_read_ex"},
}

// libTarget is one shared library discovered via a process's memory map,
// worth trying to attach uprobes to.
type libTarget struct {
	pid      int
	execPath string // resolved via <procRoot>/<pid>/root/<pathname>, readable from our mount ns
	pathname string // original pathname as it appears in the mapping (for logging)
	kind     sslKind
	devIno   string // "<dev>:<inode>" dedup key — a kernel uprobe attaches to the inode, not
	// the process, so multiple pods/processes sharing one image layer (and
	// therefore the same underlying libssl.so inode) only need one attach.
}

// discoverTargets walks <procRoot>/<pid>/maps for every numeric pid directory
// and returns one libTarget per distinct mapped TLS library. It never fails
// hard on a per-pid error (a process can exit mid-scan, permissions can be
// denied for a pid outside our pid namespace) — those are skipped and logged
// at debug level; discoverTargets only returns an error if procRoot itself is
// unreadable.
func discoverTargets(procRoot string, log *slog.Logger) ([]libTarget, bool, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", procRoot, err)
	}
	var targets []libTarget
	complete := true
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		ts, err := scanPidMaps(procRoot, pid)
		if err != nil {
			complete = false
			log.Debug("ebpf: skip pid (maps unreadable)", "pid", pid, "err", err)
			continue
		}
		targets = append(targets, ts...)
	}
	return targets, complete, nil
}

// scanPidMaps parses one process's /proc/<pid>/maps for TLS library mappings.
func scanPidMaps(procRoot string, pid int) ([]libTarget, error) {
	mapsPath := filepath.Join(procRoot, strconv.Itoa(pid), "maps")
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{} // pathname already handled for this pid
	var out []libTarget
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue // no file-backed pathname on this mapping
		}
		pathname := fields[len(fields)-1]
		if !libPathRE.MatchString(pathname) || seen[pathname] {
			continue
		}
		seen[pathname] = true

		devIno := fields[3] + ":" + fields[4] // "08:01" + ":" + "1234567"
		kind := sslUnknown
		switch {
		case strings.Contains(pathname, "libssl") || strings.Contains(pathname, "libcrypto"):
			kind = sslOpenSSL
		case strings.Contains(pathname, "libgnutls"):
			kind = sslGnuTLS
		}

		execPath := filepath.Join(procRoot, strconv.Itoa(pid), "root", pathname)
		out = append(out, libTarget{
			pid: pid, execPath: execPath, pathname: pathname, kind: kind,
			devIno: devIno,
		})
	}
	return out, sc.Err()
}

// attachTarget opens libTarget's executable and attaches every sslSymbol that
// resolves. A missing symbol (e.g. an older OpenSSL lacking the _ex variants)
// is logged and skipped, not fatal for the rest of the library; a fully
// unreadable/stripped/static binary (a musl/Alpine libssl with no dynamic
// symbol table is a documented gap) yields zero attached links and is
// logged once.
func attachTarget(prog map[string]*ebpf.Program, t libTarget, log *slog.Logger) ([]link.Link, error) {
	if t.kind != sslOpenSSL {
		log.Debug("ebpf: skip unsupported TLS library kind", "path", t.pathname, "pid", t.pid)
		return nil, nil
	}
	ex, err := link.OpenExecutable(t.execPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", t.execPath, err)
	}

	var links []link.Link
	for _, sym := range sslSymbols {
		if sym.uprobeProg != "" {
			if p := prog[sym.uprobeProg]; p != nil {
				l, err := ex.Uprobe(sym.fn, p, nil)
				if err != nil {
					log.Debug("ebpf: symbol not found, skipping", "lib", t.pathname, "symbol", sym.fn, "err", err)
				} else {
					links = append(links, l)
				}
			}
		}
		if sym.uretProg != "" {
			if p := prog[sym.uretProg]; p != nil {
				l, err := ex.Uretprobe(sym.fn, p, nil)
				if err != nil {
					log.Debug("ebpf: symbol not found, skipping", "lib", t.pathname, "symbol", sym.fn, "err", err)
				} else {
					links = append(links, l)
				}
			}
		}
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("no SSL_* symbols resolved in %s (static/stripped binary?)", t.pathname)
	}
	return links, nil
}
