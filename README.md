# k8shark

**Cluster-wide network observability for Kubernetes.**

k8shark captures and reconstructs L7 traffic across a Kubernetes cluster and
streams it to a real-time dashboard — a from-scratch, self-hostable take on
the Kubeshark model. Capture is **userspace AF_PACKET** (gopacket, no kernel
modules, no libpcap) with an optional **eBPF uprobe layer** that also
decrypts OpenSSL/boringssl TLS traffic for clusters that are mostly HTTPS.

## Architecture

```
        ┌────────────┐   entries (WS)   ┌──────────┐   entries + stats (WS)   ┌─────────┐
node ──▶│  worker    │ ───────────────▶ │   hub    │ ──────────────────────▶ │  front  │
        │ DaemonSet  │                  │ Deploy   │  ◀── IFL filter (WS) ─── │  nginx  │
        └────────────┘                  └──────────┘                          └─────────┘
   AF_PACKET + eBPF TLS           in-memory ring buffer                  React dashboard
   TCP reassembly                 IFL filtering + k8s enrichment         live table + detail
   HTTP/DNS/Redis/PG/AMQP         REST API + /metrics                    + service map
```

A single Go binary provides three roles, selected by sub-command:

| Component | Role |
|-----------|------|
| **worker** (`k8shark worker`) | Runs on every node (DaemonSet). Captures packets, reassembles TCP streams, dissects L7 protocols, and streams paired request/response **entries** to the hub. Optional eBPF uprobes add decrypted TLS traffic through the same dissectors. |
| **hub** (`k8shark hub`) | Central aggregator. Holds a bounded ring buffer of recent entries, serves a REST API + `/metrics`, resolves captured IPs to pod/service names when running in-cluster, and fans a live, **server-side-filtered** feed out to front-end clients over WebSocket. |
| **front** (nginx + React) | The dashboard: live traffic table, per-entry request/response detail, a live service map, and the IFL filter bar. |
| **CLI** (`k8shark tap/clean/...`) | Deploys everything to the current cluster via an embedded Helm chart and port-forwards the dashboard. |

## Features

- **Real-time L7 traffic** — HTTP, DNS, Redis/Valkey (RESP2/RESP3, incl. pub/sub), Postgres, AMQP 0-9-1, and generic TCP/UDP/ICMP flows, paired request↔response with latency.
- **Userspace capture** — `AF_PACKET` via gopacket, TCP reassembly, no kernel modules or libpcap dependency.
- **Optional eBPF TLS capture** — uprobes on `SSL_read`/`SSL_write` (OpenSSL/boringssl) decrypt HTTPS/TLS traffic in-process, before/after encryption, without a private key. Runs alongside AF_PACKET; degrades gracefully (logs a warning, keeps plaintext capture) if the kernel lacks BTF or the process lacks privileges.
- **k8s endpoint enrichment** — the hub resolves captured `ip:port` to a pod or Service name (and namespace) when running in-cluster; a no-op outside a cluster.
- **IFL — the k8shark Filter Language** — a small query language evaluated **hub-side**, live (filter changes push over the same WebSocket, no reconnect):
  ```
  http.method == "POST" and response.status >= 500
  protocol == "dns" or dst.namespace == "kube-system"
  not (src.name contains "canary")
  "checkout"          # bare token = full-text match
  ```
  Operators: `== != contains > < >= <=`, plus `matches` (regex), `startswith`, `in (…)`, boolean `and / or / not`, parentheses. Depth- and length-bounded against pathological input. **Full field + operator reference: [docs/ifl.md](docs/ifl.md).**
- **Entry detail** — method/path/host/status, headers, body snippet, raw hex view, source→destination endpoints with k8s names.
- **Live service map** — service-to-service graph built from live flows.
- **Live stats** — total entries, entries/sec, worker count, per-protocol breakdown; click a protocol pill to filter by it.
- **Self-observable** — `/metrics` (Prometheus text) and `/healthz` on the hub.
- **Demo mode** — synthetic traffic generator (`--demo`, opt-in only) so the dashboard is populated for a first look, without privileged capture. A broken real capture never silently falls back to demo traffic — it logs an error and stays idle instead.

## Quick start

### Locally, no cluster (`make dev`)

```bash
make dev        # builds the UI, runs the hub (serving the UI) + a demo worker
# open http://localhost:8898
```

### On a cluster, via the CLI (`k8shark tap`)

```bash
make build                                          # native CLI binary -> bin/k8shark
make docker-buildx REGISTRY=ghcr.io/you/k8shark      # build + push both images, multi-arch
./bin/k8shark tap --set image.registry=ghcr.io/you/k8shark
# ... or try it with no real capture:
./bin/k8shark tap --demo
```

`tap` installs the hub, the worker DaemonSet and the front via an embedded
Helm chart, then port-forwards the dashboard to <http://localhost:8899> and
opens a browser. Remove everything with `k8shark clean`.

### On a cluster, via Helm directly

```bash
helm install k8shark ./helm/k8shark \
  --namespace k8shark --create-namespace \
  --set image.registry=ghcr.io/you/k8shark \
  --set image.tag=v0.1.0
```

Enable eBPF TLS capture (needs a node with BTF, i.e. `/sys/kernel/btf/vmlinux`):

```bash
helm upgrade k8shark ./helm/k8shark --reuse-values --set worker.tls.enabled=true
```

### On a cluster, via plain manifests (no Helm)

See [`deploy/`](deploy/) for a single-file `kubectl apply -k deploy/` example
rendered from the same chart — useful if you don't want a Helm dependency.
It documents both a kustomize-based and a `sed`-based way to substitute the
registry/tag, plus how to wire an `imagePullSecrets` for a private registry.

## CLI

| Command | Description |
|---------|-------------|
| `k8shark tap` | Deploy to the cluster and open the dashboard (`--demo` for synthetic traffic, `--set` for extra Helm values). |
| `k8shark clean` | Remove the release and namespace. |
| `k8shark proxy` | Port-forward the dashboard of an existing install. |
| `k8shark console` | Stream component logs (`--component hub\|worker\|front`). |
| `k8shark hub` | Run the hub server (used by the hub container). `--port`, `--serve-ui <dir>` for local dev. |
| `k8shark worker` | Run the node worker (used by the worker DaemonSet). See flags below. |
| `k8shark mcp` | Run an MCP server exposing captured traffic to AI agents (`get_stats`, `list_entries`, `get_entry`, `get_traffic_summary`, `get_timeline`, `diff_traffic`, `find_error_clusters`, `get_workers`, `list_filter_fields`, `list_namespaces`, `list_workloads`). `--hub-token` when the hub requires auth; `--print-config` prints a ready-to-paste client config block. **Setup guide: [docs/mcp.md](docs/mcp.md).** |
| `k8shark version` | Print the version. |

Worker flags of note: `--demo` / `--demo-rps` (synthetic traffic, opt-in
only), `--redis-ports` / `--valkey-ports` / `--amqp-ports` (extra ports for
those protocols), `--capture-bodies` / `--body-bytes` / `--raw-bytes`
(capture-depth bounds), `--redact-headers` (scrub credential-bearing HTTP
headers, on by default), `--enable-tls` / `--proc-root` (eBPF TLS capture),
`--pcap-file` (replay a pcap file through the dissectors instead of live
capture — offline analysis, works on any OS), `--hub-token` (hub auth).

Hub flags of note: `--buffer` (in-memory entry ring size), `--buffer-bytes` (serialized JSON history budget; not RSS), `--api-token`
(require a bearer token on `/api` and the WebSocket endpoints; also read from
`$K8SHARK_API_TOKEN`), `--worker-token` / `--admin-token` (distinct
credentials for the worker ingest channel and the mutating control endpoints;
each falls back to the API token when unset), `--allow-origin` (extra browser
Origins allowed on the API/WebSockets; default is same-origin only),
`--tls-cert` / `--tls-key` (serve HTTPS/wss; the worker takes `--hub-ca` to
verify a private-CA cert on its `wss://` hub connection).

## Configuration (Helm values)

| Value | Default | Description |
|-------|---------|-------------|
| `image.registry` | `ghcr.io/pablocolson` | Image registry/repo prefix. |
| `image.tag` | `latest` | Image tag — pin this for real deployments (`latest` + `IfNotPresent` silently no-ops on upgrade). |
| `imagePullSecrets` | `[]` | Pull-secret names (e.g. `[{name: my-secret}]`) added to all three workloads, for a private `image.registry`. |
| `hub.nodeSelector` / `worker.nodeSelector` / `front.nodeSelector` | `{}` | Per-component scheduling constraints (`affinity` and `tolerations` exist too). |
| `worker.tolerations` | `[{operator: Exists}]` | Defaults to tolerating every taint so the capture DaemonSet covers all nodes — narrow it to exclude nodes. |
| `hub.port` | `8898` | Hub listen port. |
| `hub.replicas` | `1` | Hub replica count (state is per-pod; there is no shared backing store). |
| `hub.bufferSize` | `0` | Entry ring size (`0` = 10000). ~10s of history at 1k entries/s — raise for busy clusters. |
| `hub.apiToken` | `""` | When set, `/api` + WebSockets require this bearer token; workers and the front proxy get it via a Secret. |
| `hub.workerToken` | `""` | Distinct token required on `/ws/worker` (entry ingest); the worker DaemonSet picks it up automatically. Falls back to `apiToken`. |
| `hub.adminToken` | `""` | Distinct token required on mutating API calls (capture pause/resume), also grants reads. Falls back to `apiToken`. |
| `hub.tls.enabled` | `false` | Serve the hub over HTTPS/wss from `hub.tls.secretName` (a `kubernetes.io/tls` Secret, cert-manager compatible). Workers, the front proxy, probes and scrape config all switch automatically. |
| `pdb.enabled` | `true` | PodDisruptionBudget protecting the hub during node drains. |
| `worker.demo` | `false` | Generate synthetic traffic instead of capturing (opt-in only). |
| `worker.iface` | `""` | Capture interface (`""` = any). |
| `worker.privileged` | `true` | AF_PACKET needs elevated privileges + host network. |
| `worker.valkeyPorts` / `worker.amqpPorts` | `[]` | Extra RESP/AMQP ports beyond the 6379/5672 defaults. |
| `worker.capture.*` | see values.yaml | Per-direction body/raw capture-depth bounds + header redaction (`redactHeaders`, default on). |
| `worker.tls.enabled` | `false` | Attach eBPF uprobes to OpenSSL/boringssl to decrypt TLS traffic. Needs `hostPID` + `BPF`/`PERFMON`/`SYS_ADMIN`/`SYS_RESOURCE`/`SYS_PTRACE` and a node with BTF. |
| `worker.tls.goTLS` | `false` | Go `crypto/tls` uprobes — not implemented yet. |
| `capture.onDemand.enabled` | `true` | Keep workers stopped until a UI capture session starts; the hub stops them automatically at expiry. Set `false` for legacy always-on capture. |
| `capture.onDemand.defaultDuration` / `maxDuration` | `15m` / `1h` | Default and bounded maximum duration for an on-demand session. |

See [`helm/k8shark/values.yaml`](helm/k8shark/values.yaml) for the full,
commented list.

### On-demand capture and Argo CD

Set `capture.onDemand.enabled=true` to run workers only during an expiring
dashboard session. The hub persists session intent and expiry on the worker
DaemonSet, reconciles expiry after a hub restart, and needs its included
namespaced Role limited to `get`/`patch` on that one DaemonSet. If the hub is
unavailable at the deadline, cleanup happens when it returns.

For Argo CD, ignore only these runtime-owned fields on `DaemonSet/k8shark-worker`
and enable `RespectIgnoreDifferences=true` on the Application sync options:

```yaml
ignoreDifferences:
  - group: apps
    kind: DaemonSet
    name: k8shark-worker
    jqPathExpressions:
      - .metadata.annotations["k8shark.io/capture-state"]
      - .metadata.annotations["k8shark.io/capture-expiry"]
      - .spec.template.spec.schedulingGates[] | select(.name == "k8shark.io/capture-stopped")
syncPolicy:
  syncOptions:
    - RespectIgnoreDifferences=true
```

Do not ignore the whole pod specification: image, resources, and all other
Helm scheduling configuration remain GitOps-managed.

## Protocols dissected

HTTP · DNS · Redis/Valkey (RESP2/RESP3, incl. pub/sub) · Postgres · AMQP
0-9-1 · generic TCP/UDP flows + ICMP. TLS-wrapped traffic dissects the same
way once decrypted by the eBPF layer — dispatch there is by content-sniff
rather than port, since the traffic has already left the network stack by
the time it's captured.

Adding a protocol is a self-contained change: a `dissect_<proto>.go` file, a
`Protocol` constant + `Payload` fields in `pkg/api/types.go`, filter fields in
`internal/hub/filter.go`, and a UI colour — see `CLAUDE.md` for the exact
checklist.

## Building

```bash
make build          # Go binary (native; on macOS uses the external linker + ad-hoc sign)
make ui              # React dashboard -> ui/dist
make docker-build    # both container images for $PLATFORM (default linux/amd64)
make docker-buildx   # multi-arch build + push (linux/amd64,linux/arm64)
make helm-lint       # lint the chart
make test            # Go unit tests
```

> **Live capture requires Linux.** `AF_PACKET` (and its cgo build) only exist
> on Linux, so real capture runs in-cluster or in the Linux container build.
> On macOS the worker builds and runs, but only ever produces demo traffic
> when `--demo` is passed; `go build ./...` excludes the afpacket file
> entirely on non-Linux.

## Scope vs. Kubeshark

k8shark is an original MVP inspired by Kubeshark's shape and workflow
(worker DaemonSet → hub → live filtered dashboard + service map + query
language) — not a fork, and not aiming for Kubeshark's full ~20-protocol
coverage or its enterprise features. It's a good fit if you want something
small, self-hostable, and easy to read end-to-end; reach for Kubeshark
itself if you need broader protocol support or its managed offering.

## Contributing

Issues and PRs welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). `CLAUDE.md`
documents the architecture and conventions in more depth if you're extending a
dissector or the filter language.

## License

[Apache License 2.0](LICENSE).
