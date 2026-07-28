import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Entry, Endpoint } from "../types";
import { endpointClause } from "../iflClause";

interface Node {
  id: string;
  label: string;
  ns: string;
  name?: string;
  ip: string;
  x: number;
  y: number;
  inCount: number;
  outCount: number;
  errIn: number;
}
interface Edge {
  from: string;
  to: string;
  count: number;
  errors: number;
  totalLatencyMs: number;
}

interface Tooltip {
  x: number;
  y: number;
  title: string;
  rows: Array<[string, string]>;
}

const WINDOW_OPTIONS = [200, 500, 800, 1500, 3000] as const;
const VB_DEFAULT = { x: 0, y: 0, w: 960, h: 640 };
const NODE_R = 22;

// How often the graph is re-aggregated from the live buffer. The map is a
// rolling aggregate over the last 200–3000 entries: at live rates its shape
// cannot change meaningfully between animation frames, but `entries` gets a
// brand-new identity on every rAF flush from useHub. Keying the graph memo on
// that array re-walked the whole window and reconciled every SVG element 60
// times a second (~48k entry-iterations/s at the 800-entry default) — enough
// to peg a core with the map view open. So the entries are held in a ref and
// rebuilt on a slow tick instead; 2 Hz is still far quicker than anyone can
// read a service graph.
const REBUILD_INTERVAL_MS = 500;

function nodeId(ep: Endpoint): string {
  return ep.name ? (ep.namespace ? `${ep.name}.${ep.namespace}` : ep.name) : ep.ip;
}

// Build a node/edge graph from the most recent `window` entries and lay nodes
// out on a ring, grouped by namespace so same-namespace services sit next to
// each other instead of scattering randomly. Intentionally dependency-free
// (no d3).
//
// This is the one genuinely hot loop in the front (up to 3000 entries per
// rebuild), so it avoids per-entry garbage: an index loop rather than
// entries.slice(0, window) (which copied the whole window every time), and a
// two-level from→to→edge Map rather than a `${from}→${to}` template-literal
// key (which allocated and hashed a string per entry). maxCount is folded in
// here too — it was Math.max(1, ...edges.map(e => e.count)) at the call site,
// which is both a second pass and a spread that blows the argument limit (and
// the stack) once a busy cluster produces tens of thousands of distinct edges.
function buildGraph(entries: Entry[], window: number): { nodes: Node[]; edges: Edge[]; maxCount: number } {
  const nodeMap = new Map<
    string,
    { ns: string; name?: string; ip: string; inCount: number; outCount: number; errIn: number }
  >();
  const edgeMap = new Map<string, Map<string, Edge>>();

  const touch = (ep: Endpoint) => {
    const id = nodeId(ep);
    let n = nodeMap.get(id);
    if (!n) {
      n = { ns: ep.namespace ?? "", name: ep.name, ip: ep.ip, inCount: 0, outCount: 0, errIn: 0 };
      nodeMap.set(id, n);
    }
    return { id, n };
  };

  const count = Math.min(entries.length, window);
  for (let i = 0; i < count; i++) {
    const e = entries[i];
    const { id: s, n: sn } = touch(e.src);
    const { id: d, n: dn } = touch(e.dst);
    const isError = e.status === "error";
    sn.outCount++;
    dn.inCount++;
    if (isError) dn.errIn++;

    let outEdges = edgeMap.get(s);
    if (!outEdges) {
      outEdges = new Map();
      edgeMap.set(s, outEdges);
    }
    let edge = outEdges.get(d);
    if (!edge) {
      edge = { from: s, to: d, count: 0, errors: 0, totalLatencyMs: 0 };
      outEdges.set(d, edge);
    }
    edge.count++;
    edge.totalLatencyMs += e.elapsedMs;
    if (isError) edge.errors++;
  }

  // Group by namespace (then id) so the ring reads as clusters, not a
  // shuffled hairball, once there are more than a handful of services.
  const ids = [...nodeMap.keys()].sort((a, b) => {
    const na = nodeMap.get(a)!.ns;
    const nb = nodeMap.get(b)!.ns;
    return na !== nb ? na.localeCompare(nb) : a.localeCompare(b);
  });

  const cx = 480;
  const cy = 320;
  const r = Math.min(280, 100 + ids.length * 14);
  const nodes: Node[] = ids.map((id, i) => {
    const a = (i / Math.max(ids.length, 1)) * Math.PI * 2 - Math.PI / 2;
    const nm = nodeMap.get(id)!;
    return {
      id,
      label: id,
      ns: nm.ns,
      name: nm.name,
      ip: nm.ip,
      x: cx + r * Math.cos(a),
      y: cy + r * Math.sin(a),
      inCount: nm.inCount,
      outCount: nm.outCount,
      errIn: nm.errIn,
    };
  });

  const edges: Edge[] = [];
  let maxCount = 1;
  for (const outEdges of edgeMap.values()) {
    for (const edge of outEdges.values()) {
      edges.push(edge);
      if (edge.count > maxCount) maxCount = edge.count;
    }
  }

  return { nodes, edges, maxCount };
}

const NS_COLORS = ["#4aa8ff", "#b07cff", "#37c98b", "#ffb454", "#ff6b6b", "#22d3ee"];
function nsColor(ns: string): string {
  let h = 0;
  for (let i = 0; i < ns.length; i++) h = (h * 31 + ns.charCodeAt(i)) & 0xffff;
  return NS_COLORS[h % NS_COLORS.length];
}

// Self-call loop: a small arc bulging above the node, since a straight line
// from a point to itself renders as nothing.
function loopPath(x: number, y: number): string {
  return `M ${x - NODE_R * 0.7} ${y - NODE_R * 0.7} C ${x - NODE_R * 2.4} ${y - NODE_R * 2.8}, ${
    x + NODE_R * 2.4
  } ${y - NODE_R * 2.8}, ${x + NODE_R * 0.7} ${y - NODE_R * 0.7}`;
}

export function ServiceMap({
  entries,
  onNodeClick,
}: {
  entries: Entry[];
  onNodeClick?: (clause: string) => void;
}) {
  const [windowSize, setWindowSize] = useState<number>(800);

  // The graph is rebuilt from entriesRef on a tick, not from the `entries`
  // prop identity — see REBUILD_INTERVAL_MS. The ref is written during render
  // so the next tick always aggregates the latest buffer; builtFromRef records
  // which buffer the current graph came from, so an idle stream ticks without
  // churning state (and through it the whole SVG) for an identical graph.
  const entriesRef = useRef(entries);
  entriesRef.current = entries;
  const builtFromRef = useRef<Entry[] | null>(null);
  const [rebuildTick, setRebuildTick] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      if (entriesRef.current !== builtFromRef.current) setRebuildTick((t) => t + 1);
    }, REBUILD_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  const { nodes, edges, maxCount } = useMemo(() => {
    builtFromRef.current = entriesRef.current;
    return buildGraph(entriesRef.current, windowSize);
    // rebuildTick is the whole point: it, not the entries identity, is what
    // paces the (expensive) re-aggregation. A window change rebuilds at once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rebuildTick, windowSize]);
  const pos = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const nsList = useMemo(() => [...new Set(nodes.map((n) => n.ns))].sort(), [nodes]);

  const [vb, setVb] = useState(VB_DEFAULT);
  const [hover, setHover] = useState<Tooltip | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ x: number; y: number } | null>(null);

  // Wheel-to-zoom, anchored on the cursor. Attached as a native (non-passive)
  // listener since React's synthetic onWheel is passive by default and can't
  // preventDefault (which we need to stop the page from scrolling too).
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheelNative = (ev: WheelEvent) => {
      ev.preventDefault();
      const rect = el.getBoundingClientRect();
      const px = (ev.clientX - rect.left) / rect.width;
      const py = (ev.clientY - rect.top) / rect.height;
      const factor = ev.deltaY > 0 ? 1.12 : 1 / 1.12;
      setVb((v) => {
        const w = Math.min(2400, Math.max(200, v.w * factor));
        const h = w * (VB_DEFAULT.h / VB_DEFAULT.w);
        const cx = v.x + px * v.w;
        const cy = v.y + py * v.h;
        return { x: cx - px * w, y: cy - py * h, w, h };
      });
    };
    el.addEventListener("wheel", onWheelNative, { passive: false });
    return () => el.removeEventListener("wheel", onWheelNative);
  }, []);

  const onMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    dragRef.current = { x: e.clientX, y: e.clientY };
  };
  const onMouseMoveSvg = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!dragRef.current) return;
    const rect = svgRef.current!.getBoundingClientRect();
    const dx = ((e.clientX - dragRef.current.x) * vb.w) / rect.width;
    const dy = ((e.clientY - dragRef.current.y) * vb.h) / rect.height;
    dragRef.current = { x: e.clientX, y: e.clientY };
    setVb((v) => ({ ...v, x: v.x - dx, y: v.y - dy }));
  };
  const endDrag = () => {
    dragRef.current = null;
  };

  // Stable identities so the memo() on MapEdge/MapNode holds: hovering or
  // panning re-renders this component on every mousemove, and without the memo
  // that reconciled all ~1000 edge/node elements just to move a tooltip div.
  const showTooltip = useCallback((e: React.MouseEvent, title: string, rows: Array<[string, string]>) => {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect) return;
    setHover({ x: e.clientX - rect.left, y: e.clientY - rect.top, title, rows });
  }, []);
  const hideTooltip = useCallback(() => setHover(null), []);

  if (nodes.length === 0) {
    return <div className="map-empty">No traffic yet — the service map builds itself from live flows.</div>;
  }

  return (
    <div className="map-wrap">
      <div className="map-toolbar">
        <span className="label">window</span>
        <div className="view-switch">
          {WINDOW_OPTIONS.map((w) => (
            <button key={w} className={windowSize === w ? "active" : ""} onClick={() => setWindowSize(w)}>
              {w}
            </button>
          ))}
        </div>
        <span className="map-toolbar-hint">{nodes.length} services · {edges.length} links · scroll to zoom, drag to pan</span>
        <button type="button" className="toggle" onClick={() => setVb(VB_DEFAULT)}>
          reset view
        </button>
      </div>

      <div className="map-svg-area" ref={wrapRef}>
        <svg
          ref={svgRef}
          viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
          className="map-svg"
          preserveAspectRatio="xMidYMid meet"
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMoveSvg}
          onMouseUp={endDrag}
          onMouseLeave={endDrag}
        >
          <defs>
            <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" fill="var(--text-faint)" />
            </marker>
            <marker id="arrow-err" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" fill="var(--err)" />
            </marker>
          </defs>

          {edges.map((e) => {
            const a = pos.get(e.from);
            const b = pos.get(e.to);
            if (!a || !b) return null;
            return (
              <MapEdge
                key={`${e.from}-${e.to}`}
                edge={e}
                a={a}
                b={b}
                maxCount={maxCount}
                onShowTooltip={showTooltip}
                onHideTooltip={hideTooltip}
              />
            );
          })}

          {nodes.map((n) => (
            <MapNode
              key={n.id}
              n={n}
              onShowTooltip={showTooltip}
              onHideTooltip={hideTooltip}
              onNodeClick={onNodeClick}
            />
          ))}
        </svg>

        {hover && (
          <div className="map-tooltip" style={{ left: hover.x + 14, top: hover.y + 14 }}>
            <div className="tt-title">{hover.title}</div>
            {hover.rows.map(([k, v]) => (
              <div className="tt-row" key={k}>
                <span>{k}</span>
                <b>{v}</b>
              </div>
            ))}
          </div>
        )}

        {nsList.length > 0 && (
          <div className="map-legend">
            {nsList.map((ns) => (
              <div className="map-legend-item" key={ns || "(none)"}>
                <span className="map-legend-dot" style={{ background: nsColor(ns) }} />
                {ns || "(no namespace)"}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

type ShowTooltip = (e: React.MouseEvent, title: string, rows: Array<[string, string]>) => void;

// MapEdge / MapNode are memo()'d for one reason: hovering (tooltip) and
// dragging (viewBox) re-render ServiceMap on every single mousemove, and both
// pieces of state live above the graph. Without the memo each of those
// re-renders re-created and reconciled every element in the SVG — a thousand
// of them on a busy cluster — to move one absolutely-positioned div or change
// one viewBox attribute. Their props all come from the graph memo (node/edge
// objects, both stable between rebuilds) or from useCallback'd handlers, so
// they only re-render when the graph is actually rebuilt.
const MapEdge = memo(function MapEdge({
  edge,
  a,
  b,
  maxCount,
  onShowTooltip,
  onHideTooltip,
}: {
  edge: Edge;
  a: Node;
  b: Node;
  maxCount: number;
  onShowTooltip: ShowTooltip;
  onHideTooltip: () => void;
}) {
  const err = edge.errors > 0;
  const w = 0.6 + (edge.count / maxCount) * 4;
  const avgMs = Math.round(edge.totalLatencyMs / edge.count);
  const rows: Array<[string, string]> = [
    ["calls", String(edge.count)],
    ["avg latency", `${avgMs} ms`],
    ["errors", String(edge.errors)],
  ];
  const tt = (ev: React.MouseEvent) => onShowTooltip(ev, `${a.label} → ${b.label}`, rows);

  if (a === b) {
    return (
      <g>
        <path
          d={loopPath(a.x, a.y)}
          fill="none"
          stroke={err ? "var(--err)" : "var(--map-edge-default)"}
          strokeWidth={w}
          strokeOpacity={0.9}
        />
        <path
          d={loopPath(a.x, a.y)}
          fill="none"
          stroke="transparent"
          strokeWidth={14}
          onMouseEnter={tt}
          onMouseMove={tt}
          onMouseLeave={onHideTooltip}
        />
        <text x={a.x} y={a.y - NODE_R * 2.5} textAnchor="middle" className="map-label map-loop-count">
          ×{edge.count}
        </text>
      </g>
    );
  }

  return (
    <g>
      <line
        x1={a.x}
        y1={a.y}
        x2={b.x}
        y2={b.y}
        stroke={err ? "var(--err)" : "var(--map-edge-default)"}
        strokeWidth={w}
        strokeOpacity={err ? 0.9 : 0.55}
        markerEnd={err ? "url(#arrow-err)" : "url(#arrow)"}
      />
      <line
        x1={a.x}
        y1={a.y}
        x2={b.x}
        y2={b.y}
        stroke="transparent"
        strokeWidth={14}
        onMouseEnter={tt}
        onMouseMove={tt}
        onMouseLeave={onHideTooltip}
      />
    </g>
  );
});

const MapNode = memo(function MapNode({
  n,
  onShowTooltip,
  onHideTooltip,
  onNodeClick,
}: {
  n: Node;
  onShowTooltip: ShowTooltip;
  onHideTooltip: () => void;
  onNodeClick?: (clause: string) => void;
}) {
  const errPct = n.inCount ? Math.round((n.errIn / n.inCount) * 100) : 0;
  const rows: Array<[string, string]> = [
    ["namespace", n.ns || "—"],
    ["in", String(n.inCount)],
    ["out", String(n.outCount)],
    ["errors", `${n.errIn} (${errPct}%)`],
  ];
  const tt = (ev: React.MouseEvent) => onShowTooltip(ev, n.label, rows);
  const activate = () => onNodeClick?.(endpointClause(n));
  // Mouse users get the rich hover tooltip; keyboard/AT users get the same
  // numbers folded into the accessible name instead, since a cursor-anchored
  // tooltip has no meaningful position on focus.
  const a11yLabel = `${n.label}, ${n.ns || "no namespace"}, ${n.inCount} in, ${n.outCount} out, ${errPct}% errors. Activate to filter by this service.`;

  return (
    <g
      className="map-node"
      role="button"
      tabIndex={0}
      aria-label={a11yLabel}
      onMouseEnter={tt}
      onMouseMove={tt}
      onMouseLeave={onHideTooltip}
      onClick={activate}
      onKeyDown={(ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          activate();
        }
      }}
    >
      <circle cx={n.x} cy={n.y} r={NODE_R} fill="var(--map-node-fill)" stroke={nsColor(n.ns)} strokeWidth={2.5} />
      <text x={n.x} y={n.y + 38} textAnchor="middle" className="map-label">
        {n.label}
      </text>
    </g>
  );
});
