# k8shark binary image — runs both the hub and the worker.
# CGO is required for AF_PACKET live capture (gopacket/afpacket), so the build
# happens on a Linux toolchain with C headers available (linux-libc-dev supplies
# the kernel uapi headers gopacket/afpacket needs). The eBPF bytecode is NOT
# compiled here: `go generate ./internal/worker/ebpf/...` (bpf2go on
# bpf/tls.bpf.c) is run at development time and the resulting tls_bpf*.go plus
# .o objects are committed and pulled in via go:embed, so the image needs no
# clang/llvm/libbpf toolchain. CO-RE relocates the embedded .o against node BTF
# at load time, no compiler needed at runtime either.
FROM golang:1.25-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

# The RUN --mount=type=cache mounts below need BuildKit (the default builder
# since Docker 23, and what `docker buildx` always uses). They only speed up
# repeated *local* builds — CI's registry/gha cache exports layers, not cache
# mounts, so they are a no-op there. No `# syntax=` directive is pinned: the
# built-in frontend has supported cache mounts for years and the repo doesn't
# pin one anywhere else.
#
# Cache modules first. The module cache lives in the mount rather than in the
# layer, so this step stays cheap even when go.sum changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy only what the Go build actually reads, so a UI-only commit doesn't
# invalidate this layer (and with it the whole compile). That is: the three Go
# source trees, plus helm/ — helm/embed.go does `//go:embed all:k8shark`, so
# the chart is compiled into the binary for `k8shark tap`. Nothing else in the
# repo is embedded (the only other go:embed directives are the eBPF .o objects
# under internal/worker/ebpf, already covered by internal/). Keep this list in
# sync if a new go:embed appears outside these paths.
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY helm/ ./helm/
ARG VERSION=dev
ENV CGO_ENABLED=1 GOOS=linux
# The build cache is shared across target architectures on purpose: Go keys its
# cache entries by GOARCH, so a multi-arch buildx run can't mix objects up.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath \
    -ldflags="-s -w -X github.com/pablocolson/k8shark/internal/config.Version=${VERSION}" \
    -o /out/k8shark ./cmd/k8shark

# Runtime: slim Debian (glibc for the cgo binary). No libpcap needed — AF_PACKET
# talks to the kernel directly.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/k8shark /usr/local/bin/k8shark
# Run non-root by default (matches the hub's securityContext.runAsUser). The
# worker DaemonSet overrides this via its in-cluster securityContext, so its
# privileged AF_PACKET/eBPF capture is unaffected.
USER 65532:65532
ENTRYPOINT ["k8shark"]
