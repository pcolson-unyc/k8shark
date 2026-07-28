import type { KeyboardEvent, PointerEvent as ReactPointerEvent, ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { curlCommand } from "../curl";
import { conversationClause, endpointClause } from "../iflClause";
import { rawBytes, renderHexDump } from "../rawView";
import type { Entry, L4Info, Payload, PGColumn, RawView } from "../types";

type TabId = "overview" | "request" | "response" | "headers" | "body" | "raw" | "l4";

// UI-11: the detail panel width is user-resizable and persisted, like the
// column selection (VISIBLE_COLUMNS_KEY). DEFAULT matches the old fixed width.
const DETAIL_WIDTH_KEY = "k8shark.detailWidth";
const DETAIL_WIDTH_DEFAULT = 440;
const DETAIL_WIDTH_MIN = 320;

function detailWidthMax(): number {
  return Math.round((typeof window !== "undefined" ? window.innerWidth : 1200) * 0.7);
}

function clampDetailWidth(w: number): number {
  return Math.max(DETAIL_WIDTH_MIN, Math.min(w, detailWidthMax()));
}

// usePanelWidth holds the persisted, drag-resizable panel width. The returned
// onResizeStart drives a pointer-capture drag on the panel's left edge (drag
// left = wider); onReset restores the default (bound to a double-click).
function usePanelWidth(): {
  width: number;
  onResizeStart: (e: ReactPointerEvent) => void;
  onReset: () => void;
} {
  const [width, setWidth] = useState<number>(() => {
    const raw = typeof localStorage !== "undefined" && localStorage.getItem(DETAIL_WIDTH_KEY);
    const parsed = raw ? Number(raw) : NaN;
    return Number.isFinite(parsed) ? clampDetailWidth(parsed) : DETAIL_WIDTH_DEFAULT;
  });

  const persist = useCallback((w: number) => {
    setWidth(w);
    try {
      localStorage.setItem(DETAIL_WIDTH_KEY, String(w));
    } catch {
      // storage unavailable (private mode / quota) — keep the in-memory width
    }
  }, []);

  const onResizeStart = useCallback(
    (e: ReactPointerEvent) => {
      e.preventDefault();
      const startX = e.clientX;
      const startWidth = width;
      const target = e.currentTarget as HTMLElement;
      target.setPointerCapture?.(e.pointerId);
      const onMove = (ev: PointerEvent) => persist(clampDetailWidth(startWidth + (startX - ev.clientX)));
      const onUp = (ev: PointerEvent) => {
        target.releasePointerCapture?.(ev.pointerId);
        target.removeEventListener("pointermove", onMove);
        target.removeEventListener("pointerup", onUp);
      };
      target.addEventListener("pointermove", onMove);
      target.addEventListener("pointerup", onUp);
    },
    [width, persist]
  );

  const onReset = useCallback(() => persist(DETAIL_WIDTH_DEFAULT), [persist]);

  return { width, onResizeStart, onReset };
}

export function EntryDetail({
  entry,
  onClose,
  onApply,
}: {
  entry: Entry;
  onClose: () => void;
  onApply?: (filter: string) => void;
}) {
  const tabs = useMemo(() => visibleTabs(entry), [entry]);
  const [tab, setTab] = useState<TabId>("overview");
  const tabRefs = useRef<Partial<Record<TabId, HTMLButtonElement | null>>>({});
  const { width, onResizeStart, onReset } = usePanelWidth();

  // Reset to Overview when switching entries so we never land on a now-empty tab.
  useEffect(() => setTab("overview"), [entry.id]);
  const active = tabs.includes(tab) ? tab : "overview";

  // Standard tablist keyboard behavior: arrow keys move (and activate, since
  // these are simple "select on move" tabs), Home/End jump to the ends.
  const onTabKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const idx = tabs.indexOf(active);
    let next = -1;
    if (e.key === "ArrowRight") next = (idx + 1) % tabs.length;
    else if (e.key === "ArrowLeft") next = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    else return;
    e.preventDefault();
    const nextTab = tabs[next];
    setTab(nextTab);
    tabRefs.current[nextTab]?.focus();
  };

  return (
    <aside className="detail" style={{ width }}>
      <div
        className="detail-resize"
        onPointerDown={onResizeStart}
        onDoubleClick={onReset}
        role="separator"
        aria-orientation="vertical"
        aria-label="resize detail panel (double-click to reset)"
        title="drag to resize · double-click to reset"
      />
      <div className="detail-head">
        <span className={`proto-badge big st-${entry.status}`}>{entry.protocol}</span>
        <span className="detail-title mono">{entry.request.summary}</span>
        {entry.protocol === "http" && <CurlButton entry={entry} />}
        <button className="icon-btn" onClick={onClose} title="close" aria-label="close">
          ✕
        </button>
      </div>

      <div className="detail-meta">
        <Meta k="status" v={String(entry.statusCode || entry.status || "—")} />
        <Meta k="latency" v={`${entry.elapsedMs} ms`} />
        <Meta k="node" v={entry.node} sub={entry.nodeIp} />
        <Meta k="time" v={new Date(entry.timestamp).toLocaleString([], { hour12: false })} />
      </div>

      {/* EXT-3: end-to-end trace/request id, with a pivot to every entry sharing
          it — mirrors the endpoint/conversation onApply actions below. */}
      {entry.traceId && (
        <div className="detail-meta detail-trace">
          <Meta k="trace" v={entry.traceId} />
          {onApply && (
            <button
              type="button"
              className="toggle"
              onClick={() => onApply(`trace.id == "${entry.traceId}"`)}
              title="view whole trace — filter to every entry sharing this trace/request id"
              aria-label="view whole trace — filter to every entry sharing this trace/request id"
            >
              view whole trace
            </button>
          )}
        </div>
      )}

      <div className="detail-flow">
        <EndpointCard title="source" ep={entry.src} onFilter={onApply && (() => onApply(endpointClause(entry.src)))} />
        <button
          type="button"
          className="arrow"
          disabled={!onApply}
          onClick={() => onApply?.(conversationClause(entry.src, entry.dst))}
          title="follow this conversation — filter to just this src/dst pair"
          aria-label="follow this conversation — filter to just this src/dst pair"
        >
          →
        </button>
        <EndpointCard
          title="destination"
          ep={entry.dst}
          onFilter={onApply && (() => onApply(endpointClause(entry.dst)))}
        />
      </div>

      <div className="tabs" role="tablist" aria-label="entry detail sections" onKeyDown={onTabKeyDown}>
        {tabs.map((t) => (
          <button
            key={t}
            ref={(el) => {
              tabRefs.current[t] = el;
            }}
            id={`tab-${t}`}
            role="tab"
            aria-selected={t === active}
            aria-controls={`tabpanel-${t}`}
            tabIndex={t === active ? 0 : -1}
            className={`tab${t === active ? " active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="tab-body" role="tabpanel" id={`tabpanel-${active}`} aria-labelledby={`tab-${active}`}>
        {active === "overview" && <OverviewTab entry={entry} />}
        {active === "request" && <MessageTab p={entry.request} protocol={entry.protocol} side="request" />}
        {active === "response" && <MessageTab p={entry.response} protocol={entry.protocol} side="response" />}
        {active === "headers" && <HeadersTab entry={entry} />}
        {active === "body" && <BodyTab entry={entry} />}
        {active === "raw" && <RawTab entry={entry} />}
        {active === "l4" && entry.l4 && <L4Tab l4={entry.l4} />}
      </div>
    </aside>
  );
}

// --- tab visibility ---------------------------------------------------------

function visibleTabs(e: Entry): TabId[] {
  const tabs: TabId[] = ["overview", "request", "response"];
  const isHTTP = e.protocol === "http";
  if (isHTTP && (hasHeaders(e.request) || hasHeaders(e.response))) tabs.push("headers");
  if (e.request.body || e.response.body) tabs.push("body");
  if (e.request.raw || e.response.raw) tabs.push("raw");
  if (e.l4) tabs.push("l4");
  return tabs;
}

const hasHeaders = (p: Payload) => !!p.headers && Object.keys(p.headers).length > 0;

// --- Overview ---------------------------------------------------------------

function OverviewTab({ entry }: { entry: Entry }) {
  const rows: Row[] = [];
  const { protocol: proto, request: rq, response: rs } = entry;
  if (proto === "http") {
    push(rows, "method", rq.method);
    push(rows, "path", rq.path);
    push(rows, "host", rq.host);
    push(rows, "status", rs.statusCode);
    push(rows, "content-type", rs.contentType);
  } else if (proto === "dns") {
    push(rows, "question", rq.question);
    push(rows, "type", rq.dns?.questions?.[0]?.type);
    push(rows, "answer", rs.answer);
    push(rows, "rcode", rs.dns?.rcode);
  } else if (proto === "redis" || proto === "valkey") {
    push(rows, "command", rq.command);
    push(rows, "db", rq.redis?.dbIndex);
    push(rows, "reply", rs.redis?.reply);
    push(rows, "reply type", rs.redis?.replyType);
  } else if (proto === "postgres") {
    push(rows, "query", rq.query);
    push(rows, "statement", rq.postgres?.statementName);
    push(rows, "tag", rs.postgres?.tag);
    push(rows, "tx", rs.postgres?.txStatus);
    push(rows, "rows", rs.rowCount);
    push(rows, "error", rs.postgres?.error?.code);
  } else if (proto === "mysql") {
    push(rows, "query", rq.query);
    push(rows, "command", rq.mysql?.command);
    push(rows, "rows", rs.rowCount);
    push(rows, "error code", rs.mysql?.errorCode);
    push(rows, "error", rs.mysql?.errorMessage);
  } else if (proto === "mongodb") {
    push(rows, "command", rq.mongo?.command);
    push(rows, "collection", rq.mongo?.collection);
    push(rows, "database", rq.mongo?.database);
    push(rows, "ok", rs.mongo?.ok ? "yes" : undefined);
    push(rows, "error", rs.mongo?.errmsg);
  } else if (proto === "kafka") {
    push(rows, "api", rq.kafka?.apiKey);
    push(rows, "version", rq.kafka?.apiVersion);
    push(rows, "topic", rq.kafka?.topic);
    push(rows, "client id", rq.kafka?.clientId);
    push(rows, "error code", rs.kafka?.errorCode);
  } else if (proto === "amqp") {
    push(rows, "class", rq.class);
    push(rows, "method", rq.method);
    push(rows, "exchange", rq.exchange);
    push(rows, "routing key", rq.routingKey);
    push(rows, "queue", rq.queue);
  } else if (proto === "ws") {
    push(rows, "opcode", rq.wsOpcode);
    push(rows, "preview", rq.body);
    push(rows, "size", rq.size ? `${rq.size} B` : undefined);
  } else {
    push(rows, "flags", rq.flags);
    push(rows, "packets", rq.packets);
    push(rows, "bytes", rq.bytes);
  }
  return (
    <Section title="overview">
      <KV rows={rows} />
    </Section>
  );
}

// --- Request / Response -----------------------------------------------------

function MessageTab({
  p,
  protocol,
  side,
}: {
  p: Payload;
  protocol: string;
  side: "request" | "response";
}) {
  const rows: Row[] = [];
  if (protocol === "http") {
    if (side === "request") {
      push(rows, "method", p.method);
      push(rows, "path", p.path);
      push(rows, "host", p.host);
      push(rows, "version", p.http?.version);
    } else {
      push(rows, "status", p.statusCode);
      push(rows, "version", p.http?.version);
      push(rows, "ttfb", p.http?.ttfbMs ? `${p.http.ttfbMs} ms` : undefined);
    }
    push(rows, "content-type", p.contentType);
    push(rows, "size", p.size ? `${p.size} B` : undefined);
  } else if (protocol === "postgres") {
    if (side === "request") {
      push(rows, "query", p.query);
      push(rows, "portal", p.postgres?.portal);
    } else {
      push(rows, "tag", p.postgres?.tag);
      push(rows, "rows", p.rowCount);
    }
  } else if (protocol === "redis" || protocol === "valkey") {
    if (side === "request") {
      push(rows, "command", p.command);
      push(rows, "pipeline depth", p.redis?.pipelineDepth);
    } else {
      push(rows, "reply", p.redis?.reply);
      push(rows, "reply type", p.redis?.replyType);
    }
  } else if (protocol === "mysql") {
    if (side === "request") {
      push(rows, "query", p.query);
      push(rows, "command", p.mysql?.command);
    } else {
      push(rows, "rows", p.rowCount);
      push(rows, "error code", p.mysql?.errorCode);
      push(rows, "error", p.mysql?.errorMessage);
    }
  } else if (protocol === "mongodb") {
    if (side === "request") {
      push(rows, "command", p.mongo?.command);
      push(rows, "collection", p.mongo?.collection);
      push(rows, "database", p.mongo?.database);
    } else {
      push(rows, "ok", p.mongo?.ok ? "yes" : undefined);
      push(rows, "error", p.mongo?.errmsg);
    }
  } else if (protocol === "kafka") {
    if (side === "request") {
      push(rows, "api", p.kafka?.apiKey);
      push(rows, "version", p.kafka?.apiVersion);
      push(rows, "topic", p.kafka?.topic);
      push(rows, "client id", p.kafka?.clientId);
      push(rows, "correlation id", p.kafka?.correlationId);
    } else {
      push(rows, "error code", p.kafka?.errorCode);
    }
  } else if (protocol === "dns" && side === "response") {
    push(rows, "rcode", p.dns?.rcode);
    push(rows, "authoritative", p.dns?.authoritative ? "yes" : undefined);
    push(rows, "recursion available", p.dns?.recursionAvailable ? "yes" : undefined);
  } else if (protocol === "amqp" && side === "request") {
    push(rows, "class", p.class);
    push(rows, "method", p.method);
    push(rows, "exchange", p.exchange);
    push(rows, "routing key", p.routingKey);
    push(rows, "queue", p.queue);
    push(rows, "delivery tag", p.deliveryTag);
  } else if (protocol === "ws" && side === "request") {
    push(rows, "opcode", p.wsOpcode);
    push(rows, "size", p.size ? `${p.size} B` : undefined);
  }

  return (
    <Section title={side}>
      <KV rows={rows} />

      {p.http?.query && Object.keys(p.http.query).length > 0 && (
        <MapBlock title="query params" m={p.http.query} />
      )}
      {p.redis?.args && p.redis.args.length > 0 && <ListBlock title="args" items={p.redis.args} />}
      {p.redis?.attributes && Object.keys(p.redis.attributes).length > 0 && (
        <MapBlock title="attributes" m={p.redis.attributes} />
      )}
      {p.postgres?.params && p.postgres.params.length > 0 && (
        <ListBlock title="bind params" items={p.postgres.params} />
      )}
      {p.postgres?.columns && p.postgres.columns.length > 0 && (
        <ColumnsTable cols={p.postgres.columns} />
      )}
      {p.postgres?.error && <PGErrorBlock err={p.postgres.error} />}
      {p.dns?.questions && p.dns.questions.length > 0 && (
        <RecordTable title="questions" recs={p.dns.questions.map((q) => ({ name: q.name, type: q.type, data: q.class || "" }))} />
      )}
      {p.dns?.answers && p.dns.answers.length > 0 && <RecordTable title="answers" recs={p.dns.answers} />}
      {p.dns?.authority && p.dns.authority.length > 0 && (
        <RecordTable title="authority" recs={p.dns.authority} />
      )}
      {p.dns?.additional && p.dns.additional.length > 0 && (
        <RecordTable title="additional" recs={p.dns.additional} />
      )}
    </Section>
  );
}

// --- Headers ----------------------------------------------------------------

function HeadersTab({ entry }: { entry: Entry }) {
  return (
    <Section title="headers">
      {hasHeaders(entry.request) && (
        <MapBlock title="request" m={entry.request.headers!} />
      )}
      {hasHeaders(entry.response) && (
        <MapBlock title="response" m={entry.response.headers!} />
      )}
    </Section>
  );
}

// --- Body -------------------------------------------------------------------

function BodyTab({ entry }: { entry: Entry }) {
  return (
    <Section title="body">
      {entry.request.body && <BodyBlock title="request" p={entry.request} />}
      {entry.response.body && <BodyBlock title="response" p={entry.response} />}
    </Section>
  );
}

function BodyBlock({ title, p }: { title: string; p: Payload }) {
  const pretty = useMemo(() => tryPrettyJSON(p.body), [p.body]);
  const displayed = pretty ?? p.body;
  return (
    <>
      <div className="subhead">
        {title}
        {p.truncated && <span className="chip trunc">truncated</span>}
        {displayed && <CopyButton text={displayed} label={`${title} body`} />}
      </div>
      {pretty ? (
        <pre className="body mono" dangerouslySetInnerHTML={{ __html: highlightJSON(pretty) }} />
      ) : (
        <pre className="body mono">{p.body}</pre>
      )}
    </>
  );
}

// tryPrettyJSON returns a pretty-printed (2-space indent) rendering of body
// when it parses as JSON, or null otherwise (plain/truncated/non-JSON
// bodies fall back to the raw <pre> text unchanged).
function tryPrettyJSON(body: string | undefined): string | null {
  if (!body) return null;
  const trimmed = body.trim();
  // Cheap pre-filter so we don't try/catch-parse every non-JSON body (HTML,
  // plain text, binary previews, ...).
  if (!/^[[{]|^"|^-?\d|^(true|false|null)\b/.test(trimmed)) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

// highlightJSON does a small regex-based tokenize-and-wrap over already
// pretty-printed JSON text — dependency-free, matching the app's existing
// "no charting/highlighting lib" approach (see ServiceMap.tsx). Safe against
// injection: HTML-escapes first, then only ever wraps matched substrings in
// a fixed <span class="..."> — no user-controlled markup is introduced.
function highlightJSON(json: string): string {
  const escaped = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return escaped.replace(
    /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let cls = "jn";
      if (match.startsWith('"')) cls = match.endsWith(":") ? "jk" : "js";
      else if (match === "true" || match === "false") cls = "jb";
      else if (match === "null") cls = "jz";
      return `<span class="${cls}">${match}</span>`;
    }
  );
}

// --- Raw --------------------------------------------------------------------

function RawTab({ entry }: { entry: Entry }) {
  return (
    <Section title="raw">
      {entry.request.raw && <RawBlock title="request" raw={entry.request.raw} />}
      {entry.response.raw && <RawBlock title="response" raw={entry.response.raw} />}
    </Section>
  );
}

// RawBlock renders the hexdump for one direction. The dump is built here, in
// the browser, rather than shipped pre-rendered from the worker: the text is
// ~4.94x the size of the bytes it describes, and only the one entry whose
// detail panel is open ever needs it, so rendering it worker-side meant paying
// that cost for every entry on every hop. useMemo keeps it to once per raw
// sample rather than once per re-render of the panel.
//
// raw.hex is still honoured for entries produced by a worker older than this
// hub, which pre-rendered the block and sent no bytes.
function RawBlock({ title, raw }: { title: string; raw: RawView }) {
  const dump = useMemo(() => (raw.data ? renderHexDump(rawBytes(raw)) : (raw.hex ?? "")), [raw]);
  return (
    <>
      <div className="subhead">
        {title} · first {raw.bytes ?? 0} B of stream
        {raw.truncated && <span className="chip trunc">truncated</span>}
        {dump && <CopyButton text={dump} label={`${title} raw hex`} />}
      </div>
      <pre className="hex">{dump}</pre>
    </>
  );
}

// --- L4 ---------------------------------------------------------------------

function L4Tab({ l4 }: { l4: L4Info }) {
  const rows: Row[] = [];
  push(rows, "src mac", l4.srcMac);
  push(rows, "dst mac", l4.dstMac);
  push(rows, "ip version", l4.ipVersion);
  push(rows, "ttl", l4.ttl);
  push(rows, "ip flags", l4.ipFlags);
  push(rows, "client flags", l4.clientTcpFlags);
  push(rows, "server flags", l4.serverTcpFlags);
  push(rows, "seq start", l4.seqStart);
  push(rows, "ack start", l4.ackStart);
  push(rows, "window", l4.window);
  push(rows, "mss", l4.mss);
  push(rows, "rtt", l4.rttMs ? `${l4.rttMs} ms` : undefined);
  push(rows, "retransmits", l4.retransmits);
  push(rows, "duration", l4.durationMs ? `${l4.durationMs} ms` : undefined);
  push(rows, "client bytes", l4.clientBytes);
  push(rows, "server bytes", l4.serverBytes);
  push(rows, "client packets", l4.clientPackets);
  push(rows, "server packets", l4.serverPackets);
  if (l4.tls) {
    push(rows, "tls sni", l4.tls.sni);
    push(rows, "tls alpn", l4.tls.alpn);
    push(rows, "tls version", l4.tls.version);
    push(rows, "tls cipher", l4.tls.cipher);
  }
  return (
    <Section title="l4">
      <KV rows={rows} />
      {l4.headerHex && (
        <>
          <div className="subhead">header</div>
          <pre className="hex">{l4.headerHex}</pre>
        </>
      )}
    </Section>
  );
}

// --- shared building blocks --------------------------------------------------

type Row = [string, string];

function push(rows: Row[], k: string, v: string | number | undefined) {
  if (v === undefined || v === null || v === "" || v === 0) return;
  rows.push([k, String(v)]);
}

function KV({ rows }: { rows: Row[] }) {
  if (rows.length === 0) return <div className="empty-note">no data</div>;
  return (
    <table className="kv">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <td className="kv-k">{k}</td>
            <td className="kv-v mono">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function MapBlock({ title, m }: { title: string; m: Record<string, string> }) {
  return (
    <>
      <div className="subhead">
        {title}
        <CopyButton text={Object.entries(m).map(([k, v]) => `${k}: ${v}`).join("\n")} label={title} />
      </div>
      <table className="kv">
        <tbody>
          {Object.entries(m).map(([k, v]) => (
            <tr key={k}>
              <td className="kv-k">{k}</td>
              <td className="kv-v mono">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function ListBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <>
      <div className="subhead">{title}</div>
      <ol className="arglist mono">
        {items.map((it, i) => (
          <li key={i}>{it}</li>
        ))}
      </ol>
    </>
  );
}

function ColumnsTable({ cols }: { cols: PGColumn[] }) {
  return (
    <>
      <div className="subhead">columns</div>
      <table className="kv">
        <tbody>
          {cols.map((c, i) => (
            <tr key={i}>
              <td className="kv-k">{c.name}</td>
              <td className="kv-v mono">{c.type || (c.typeOid ? `oid ${c.typeOid}` : "")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function RecordTable({ title, recs }: { title: string; recs: Array<{ name: string; type: string; ttl?: number; data: string }> }) {
  return (
    <>
      <div className="subhead">{title}</div>
      <table className="kv rec">
        <tbody>
          {recs.map((r, i) => (
            <tr key={i}>
              <td className="kv-k mono">{r.type}</td>
              <td className="kv-v mono">
                {r.name}
                {r.data ? ` → ${r.data}` : ""}
                {r.ttl ? ` (ttl ${r.ttl})` : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function PGErrorBlock({ err }: { err: NonNullable<Payload["postgres"]>["error"] }) {
  if (!err) return null;
  const rows: Row[] = [];
  push(rows, "severity", err.severity);
  push(rows, "code", err.code);
  push(rows, "message", err.message);
  push(rows, "detail", err.detail);
  push(rows, "hint", err.hint);
  push(rows, "where", err.where);
  return (
    <>
      <div className="subhead">error</div>
      <KV rows={rows} />
    </>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="section">
      <div className="section-title">{title}</div>
      {children}
    </div>
  );
}

function EndpointCard({
  title,
  ep,
  onFilter,
}: {
  title: string;
  ep: Entry["src"];
  onFilter?: () => void;
}) {
  return (
    <div className="ep-card">
      <div className="ep-title-row">
        <div className="ep-title">{title}</div>
        {onFilter && (
          <button
            type="button"
            className="icon-btn ep-filter-btn"
            onClick={onFilter}
            title={`filter on this ${title}`}
            aria-label={`filter on this ${title} (${ep.name || ep.ip})`}
          >
            ⌕
          </button>
        )}
      </div>
      <div className="ep-name mono">{ep.name || ep.ip}</div>
      <div className="ep-sub mono">
        {ep.namespace ? `${ep.namespace} · ` : ""}
        {ep.ip}:{ep.port}
      </div>
    </div>
  );
}

function Meta({ k, v, sub }: { k: string; v: string; sub?: string }) {
  return (
    <div className="meta-item">
      <span className="meta-k">{k}</span>
      <span className="meta-v mono">{v}</span>
      {sub && <span className="meta-v-sub mono">{sub}</span>}
    </div>
  );
}

function CurlButton({ entry }: { entry: Entry }) {
  const [copied, setCopied] = useState(false);
  const onClick = async () => {
    try {
      await navigator.clipboard.writeText(curlCommand(entry));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable or permission denied — nothing to recover.
    }
  };
  return (
    <button
      type="button"
      className="toggle"
      onClick={onClick}
      title="copy this request as a curl command"
      aria-label="copy this request as a curl command"
    >
      {copied ? "✓ copied" : "curl"}
      <span className="sr-only" aria-live="polite">
        {copied ? "copied to clipboard" : ""}
      </span>
    </button>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const onClick = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable or permission denied — nothing to recover.
    }
  };
  return (
    <button
      type="button"
      className="icon-btn copy-btn"
      onClick={onClick}
      title={`copy ${label}`}
      aria-label={`copy ${label}`}
    >
      {copied ? "✓" : "⧉"}
      <span className="sr-only" aria-live="polite">
        {copied ? "copied to clipboard" : ""}
      </span>
    </button>
  );
}
