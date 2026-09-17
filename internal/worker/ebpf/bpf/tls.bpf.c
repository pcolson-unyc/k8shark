// tls.bpf.c — uprobe/uretprobe capture of plaintext at the OpenSSL/boringssl
// TLS library boundary. Loaded by loader.go via github.com/cilium/ebpf/link;
// see source.go for the design rationale (hybrid AF_PACKET + eBPF, PLAN.md
// §2/§WS1).
//
// SSL_write's buffer is plaintext at function entry (about to be encrypted),
// so one uprobe suffices. SSL_read's buffer is only populated once the call
// returns, so entry stashes (ssl*, buf*) keyed by pid_tgid and the matching
// uretprobe reads the actual byte count (the return value for SSL_read;
// *written/*readbytes, an out-param, for the _ex variants) before copying.
//
// Only userspace memory is touched (bpf_probe_read_user) — no kernel struct
// walks, so this needs no vmlinux.h/CO-RE relocation of kernel types.
// No linux/types.h or linux/bpf.h: those pull in <asm/types.h>, which lives
// under an arch-specific multiarch path (e.g. /usr/include/aarch64-linux-gnu)
// that clang's default search doesn't add when cross-targeting "-target bpf"
// (a different target triple than the host compiling it). Defining the
// handful of types/constants bpf_helpers.h actually needs sidesteps that
// entirely and keeps this buildable regardless of host arch. Values are
// stable UAPI ABI, never renumbered.
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16; // big-endian u16 (sparse annotation only; same layout)
typedef __u32 __be32;
typedef __u32 __wsum;

typedef unsigned long size_t;

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_ANY 0

#include <bpf/bpf_helpers.h>

// bpf_tracing.h's PT_REGS_PARMn/PT_REGS_RC macros (__TARGET_ARCH_x86, set via
// gen.go's -cflags) dereference named fields on a real struct pt_regs — a
// direct member access, not a BPF_CORE_READ, so no CO-RE relocation ever
// touches it; the layout below must just match the kernel ABI exactly.
// Without __VMLINUX_H__ defined, bpf_tracing.h's x86_64 branch expects the
// glibc/ptrace "r"-prefixed field names (struct user_regs_struct from
// <sys/user.h>), not the kernel-internal asm/ptrace.h short names — same
// memory layout either way, just different field spelling, confirmed against
// the actual macro definitions in /usr/include/bpf/bpf_tracing.h. Defining it
// here (instead of pulling the ~150k-line vmlinux.h) sidesteps having to
// generate that from a real x86_64 kernel's BTF, which this repo's build
// machines (including Apple Silicon Docker Desktop) can't produce since BTF
// always reflects the *host* kernel's arch, not the eventual target's. Every
// node on the deployed cluster is amd64 (PLAN.md §7 open question #5); an
// arm64 target would need the arm64 user_pt_regs layout instead.
struct pt_regs {
	unsigned long r15, r14, r13, r12, rbp, rbx;
	unsigned long r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi;
	unsigned long orig_rax, rip, cs, eflags, rsp, ss;
};

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define MAX_DATA 16384
#define EVENT_FLAG_LAGGED 0x80000000U
#define DIR_WRITE 1
#define DIR_READ 2
#define AF_INET 2
#define AF_INET6 10

// in6_addr_blob is just a same-size stand-in for the kernel's real
// `struct in6_addr` — CO-RE relocates skc_v6_daddr/skc_v6_rcv_saddr by field
// name against the target's BTF, so the exact internal shape here doesn't
// matter, only that BPF_CORE_READ_INTO's sizeof(*dst) come out to 16 bytes
// (see record_tuple).
struct in6_addr_blob {
	__u8 b[16];
};

// Minimal CO-RE view of the kernel's struct sock, just the 4-tuple fields of
// sock_common (IPv4 and IPv6). preserve_access_index makes libbpf relocate
// the real field offsets against the node's BTF at load time — so we read the
// tuple without committing the arch-specific ~150k-line vmlinux.h (the reason
// the rest of this file hand-defines its types). Field names must match the
// kernel's. This is the ONLY CO-RE (BTF-relocated) read in the program; the
// SSL uprobes touch only userspace memory and function args.
struct sock_common {
	__be32 skc_daddr;      // remote IPv4 (network order)
	__be32 skc_rcv_saddr;  // local IPv4 (network order)
	__u16 skc_num;         // local port (host order)
	__be16 skc_dport;      // remote port (network order)
	short unsigned int skc_family;
	struct in6_addr_blob skc_v6_daddr;     // remote IPv6
	struct in6_addr_blob skc_v6_rcv_saddr; // local IPv6
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

// conn_tuple is the resolved 4-tuple for a thread's current TCP socket, IPv4
// or IPv6 (family tells the Go side which of the 16 addr bytes are
// meaningful — 4 for AF_INET, all 16 for AF_INET6).
struct conn_tuple {
	__u8 saddr[16];  // network order
	__u8 daddr[16];  // network order
	__u16 sport;     // host order
	__u16 dport;     // host order
	__u8 family;     // 0 = unresolved, AF_INET or AF_INET6
};

// Field order matters: it is hand-decoded on the Go side (loader.go's
// decodeEvent) without relying on bpf2go's -type codegen, so this must stay a
// flat, unambiguous layout — every field naturally aligned with NO compiler-
// inserted padding before data[] (u64 forces 8-byte struct alignment, hence
// pid+tid packed first to fill that to 8; saddr/daddr are 16-byte arrays so
// need no extra alignment padding either side; data_len then lands on a
// 4-aligned offset, followed by fields needing no alignment at all). If you
// change this struct, update decodeEvent's offsets to match.
struct event {
	__u32 pid;        // offset 0
	__u32 tid;        // offset 4
	__u64 ssl_ctx;    // offset 8
	__u8 saddr[16];   // offset 16 (network order; first 4 bytes for IPv4, all zero if unknown)
	__u8 daddr[16];   // offset 32
	__u32 data_len;   // offset 48
	__u16 sport;      // offset 52 (host order)
	__u16 dport;      // offset 54
	__u8 family;      // offset 56 (0 = unresolved, AF_INET or AF_INET6)
	__u8 direction;   // offset 57
	__u8 data[MAX_DATA]; // offset 58
};

// events is drained by loader.go's ringbuf.Reader into TLSRecord values.
// Sized per PLAN.md §5.6 ("WS1 ring buffer 16 MiB").
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} scratch SEC(".maps");

// read_ctx is what an SSL_read*/SSL_write_ex entry probe stashes for its
// uretprobe to finish the job with. written_ptr is 0 for plain SSL_read,
// whose byte count is the return value instead of an out-param.
struct read_ctx {
	__u64 ssl_ctx;
	__u64 buf;
	__u64 written_ptr;
};

// active_reads is keyed by pid_tgid: a single thread can't be inside more
// than one of SSL_read/SSL_read_ex/SSL_write_ex at once (synchronous calls),
// so entry/return pairs never collide.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct read_ctx);
} active_reads SEC(".maps");

// tuples caches each thread's current TCP 4-tuple, populated by the
// tcp_sendmsg/tcp_recvmsg kprobes and read by emit(). Correlation is by
// pid_tgid + recency: an SSL_write is immediately followed by tcp_sendmsg on
// the same thread (OpenSSL flushing the ciphertext), and an SSL_read's
// uretprobe fires after tcp_recvmsg — so the freshest tuple for the thread is
// the right connection for a persistent socket. Best-effort: 0 until the first
// syscall on the connection, and imprecise if one thread multiplexes several
// sockets between TLS calls (rare). Real IPs replace the synthetic pid:<n>
// endpoints; Phase 2b.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct conn_tuple);
} tuples SEC(".maps");

// record_tuple reads the socket's 4-tuple via CO-RE and caches it for the
// current thread, IPv4 or IPv6. An unrecognised family (neither) leaves the
// thread's cached tuple untouched rather than overwriting it with a bogus
// zero one.
static __always_inline void record_tuple(struct sock *sk)
{
	if (!sk)
		return;
	short unsigned int family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	struct conn_tuple t = {};
	if (family == AF_INET) {
		__be32 addr = 0;
		BPF_CORE_READ_INTO(&addr, sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(t.saddr, &addr, sizeof(addr));
		BPF_CORE_READ_INTO(&addr, sk, __sk_common.skc_daddr);
		__builtin_memcpy(t.daddr, &addr, sizeof(addr));
		t.family = AF_INET;
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&t.saddr, sk, __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO(&t.daddr, sk, __sk_common.skc_v6_daddr);
		t.family = AF_INET6;
	} else {
		return;
	}
	BPF_CORE_READ_INTO(&t.sport, sk, __sk_common.skc_num); // already host order
	__be16 dport = 0;
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	t.dport = bpf_ntohs(dport);
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&tuples, &id, &t, BPF_ANY);
}

// Populate the fixed header in per-CPU scratch memory. Output below includes
// only this header and the captured payload, without unused array capacity.
// The matching Go decoder handles the high-bit loss marker used for explicit
// stream termination; field offsets stay unchanged.
static __always_inline void fill_event(struct event *e, __u64 ssl, __u8 dir)
{
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->ssl_ctx = ssl;
	e->direction = dir;

	// Attach the thread's current 4-tuple if a kprobe resolved one (family 0 =
	// unknown -> the Go side falls back to the synthetic pid:<n> endpoint).
	struct conn_tuple *t = bpf_map_lookup_elem(&tuples, &id);
	if (t) {
		__builtin_memcpy(e->saddr, t->saddr, sizeof(e->saddr));
		__builtin_memcpy(e->daddr, t->daddr, sizeof(e->daddr));
		e->sport = t->sport;
		e->dport = t->dport;
		e->family = t->family;
	} else {
		__builtin_memset(e->saddr, 0, sizeof(e->saddr));
		__builtin_memset(e->daddr, 0, sizeof(e->daddr));
		e->sport = 0;
		e->dport = 0;
		e->family = 0;
	}
}

// emit_chunk copies one contiguous piece.  A failed user read is represented
// by a data-less tombstone, allowing the Go consumer to close the stream
// instead of parsing across an interior hole.
static __always_inline int emit_chunk(__u64 ssl, __u8 dir, const void *buf, __u32 len, __u32 terminal)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &key);
	if (!e)
		return 0;
	fill_event(e, ssl, dir);

	// Keep a verifier-visible upper bound without the old exact-power-of-two
	// hole: mask len-1, then add one, so 16384 remains 16384 rather than zero.
	__u32 rlen = len - 1;
	asm volatile("%0 &= %1" : "+r"(rlen) : "i"(MAX_DATA - 1));
	rlen++;
	e->data_len = rlen | terminal;
	if (bpf_probe_read_user(e->data, rlen, buf) < 0) {
		e->data_len = EVENT_FLAG_LAGGED;
		bpf_ringbuf_output(&events, e, 58, 0);
		return -1;
	}
	bpf_ringbuf_output(&events, e, 58 + rlen, 0);
	return 1;
}

static __always_inline void emit(__u64 ssl, __u8 dir, const void *buf, __u32 len)
{
	if (len == 0)
		return;
	// Capture one bounded chunk.  Larger TLS callbacks are explicitly
	// terminated with a tombstone rather than silently feeding a partial
	// interior stream to the parser; this keeps the program small and verifier
	// compatible on older kernels.
	__u32 n = len > MAX_DATA ? MAX_DATA : len;
	// Mark the bounded event itself terminal when bytes were omitted.  A
	// second reservation would be another possible loss point under pressure.
	(void)emit_chunk(ssl, dir, buf, n, len > MAX_DATA ? EVENT_FLAG_LAGGED : 0);
}

// --- SSL_write(SSL *ssl, const void *buf, int num) -------------------------

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
	__u64 ssl = (__u64)PT_REGS_PARM1(ctx);
	void *buf = (void *)PT_REGS_PARM2(ctx);
	int num = (int)PT_REGS_PARM3(ctx);
	if (num > 0)
		emit(ssl, DIR_WRITE, buf, (__u32)num);
	return 0;
}

// --- SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written) --

SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_ctx rc = {
		.ssl_ctx = (__u64)PT_REGS_PARM1(ctx),
		.buf = (__u64)PT_REGS_PARM2(ctx),
		.written_ptr = (__u64)PT_REGS_PARM4(ctx),
	};
	bpf_map_update_elem(&active_reads, &id, &rc, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_write_ex")
int uretprobe_ssl_write_ex(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_ctx *rc = bpf_map_lookup_elem(&active_reads, &id);
	if (!rc)
		return 0;
	int ok = (int)PT_REGS_RC(ctx);
	if (ok == 1 && rc->written_ptr) {
		size_t written = 0;
		if (bpf_probe_read_user(&written, sizeof(written), (void *)rc->written_ptr) == 0 && written > 0)
			emit(rc->ssl_ctx, DIR_WRITE, (void *)rc->buf, (__u32)written);
	}
	bpf_map_delete_elem(&active_reads, &id);
	return 0;
}

// --- SSL_read(SSL *ssl, void *buf, int num) ---------------------------------

SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_ctx rc = {
		.ssl_ctx = (__u64)PT_REGS_PARM1(ctx),
		.buf = (__u64)PT_REGS_PARM2(ctx),
		.written_ptr = 0,
	};
	bpf_map_update_elem(&active_reads, &id, &rc, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_ctx *rc = bpf_map_lookup_elem(&active_reads, &id);
	if (!rc)
		return 0;
	int n = (int)PT_REGS_RC(ctx);
	if (n > 0)
		emit(rc->ssl_ctx, DIR_READ, (void *)rc->buf, (__u32)n);
	bpf_map_delete_elem(&active_reads, &id);
	return 0;
}

// --- SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) -------

SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_ctx rc = {
		.ssl_ctx = (__u64)PT_REGS_PARM1(ctx),
		.buf = (__u64)PT_REGS_PARM2(ctx),
		.written_ptr = (__u64)PT_REGS_PARM4(ctx),
	};
	bpf_map_update_elem(&active_reads, &id, &rc, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct read_ctx *rc = bpf_map_lookup_elem(&active_reads, &id);
	if (!rc)
		return 0;
	int ok = (int)PT_REGS_RC(ctx);
	if (ok == 1 && rc->written_ptr) {
		size_t n = 0;
		if (bpf_probe_read_user(&n, sizeof(n), (void *)rc->written_ptr) == 0 && n > 0)
			emit(rc->ssl_ctx, DIR_READ, (void *)rc->buf, (__u32)n);
	}
	bpf_map_delete_elem(&active_reads, &id);
	return 0;
}

// --- 4-tuple resolution (Phase 2b) -----------------------------------------
// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size) and
// tcp_recvmsg(struct sock *sk, ...) — the first arg is the socket. These run
// on the same thread as the SSL_write/SSL_read that drives them, so caching
// the tuple by pid_tgid lets emit() label the plaintext with real IPs/ports.

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk)
{
	record_tuple(sk);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk)
{
	record_tuple(sk);
	return 0;
}
