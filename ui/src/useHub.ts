import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Entry, Envelope, Stats, StatsPoint } from "./types";

export const MAX_ENTRIES = 2000;

// Mirrors the hub's statsHistoryCap (server.go) so the client-side rolling
// history the front appends to (on top of the hydrated server history) stays
// bounded the same way.
const STATS_HISTORY_CAP = 300;

// Reconnect backoff: exponential with jitter, capped, reset on a healthy open.
const BACKOFF_BASE = 1000;
const BACKOFF_FACTOR = 2;
const BACKOFF_MAX = 15000;

// Flush cadence used in place of requestAnimationFrame while the document is
// hidden. Browsers throttle background setTimeout (typically to ~1/s) but,
// unlike rAF, never fully suspend it — see the comment on scheduleFlush.
const HIDDEN_FLUSH_INTERVAL_MS = 250;

// wsURL builds the hub WebSocket URL from the current origin. Works behind
// nginx (in-cluster) and behind the vite dev proxy (local).
function wsURL(filter: string): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const q = filter ? `?filter=${encodeURIComponent(filter)}` : "";
  return `${proto}//${location.host}/ws${q}`;
}

export interface HistoricalRange {
  since: string;
  until: string;
}

export interface HubState {
  entries: Entry[];
  stats: Stats | null;
  connected: boolean;
  paused: boolean;
  pausedCount: number;
  setPaused: (p: boolean) => void;
  clear: () => void;
  applyFilter: (f: string) => void;
  filterError: string | null;
  truncated: boolean;
  loadOlder: () => void;
  loadingOlder: boolean;
  noMoreHistory: boolean;
  statsHistory: StatsPoint[];
  historicalRange: HistoricalRange | null;
  loadingRange: boolean;
  loadRange: (since: string, until: string) => void;
  returnToLive: () => void;
}

// flushUpdater builds the setEntries updater one flush uses: prepend this
// frame's batch (already newest-first) and trim to the cap. Factored out of
// flush() — and exported — purely so it can be invoked repeatedly in a test:
// React treats an updater as a pure function of `prev` and may call it more
// than once for a single update, so it must not mutate the captured batch.
// (This used to end up doing `batch.reverse().concat(prev)`, which silently
// re-ordered the batch oldest-first on the second call.)
export function flushUpdater(batch: Entry[], cap: number): (prev: Entry[]) => Entry[] {
  return (prev) => {
    const next = batch.concat(prev);
    if (next.length > cap) next.length = cap;
    return next;
  };
}

// useHub owns the live connection: it streams entries, keeps a bounded rolling
// buffer, tracks stats, and pushes filter changes to the server so filtering
// happens hub-side (matching Kubeshark's model).
export function useHub(initialFilter: string): HubState {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  // Entries that arrived while paused, dropped rather than buffered — surfaced
  // as a count so pausing doesn't silently hide how much traffic went by.
  const [pausedCount, setPausedCount] = useState(0);
  const [filterError, setFilterError] = useState<string | null>(null);
  // True once the client-side buffer has evicted an entry for exceeding
  // MAX_ENTRIES, so the UI can say "showing latest N" instead of implying a
  // complete result set.
  const [truncated, setTruncated] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [noMoreHistory, setNoMoreHistory] = useState(false);
  const [statsHistory, setStatsHistory] = useState<StatsPoint[]>([]);
  // Set while the table is showing a brushed-in-the-timeline snapshot
  // (/api/entries?since&until) instead of the live tail. The live WS
  // connection stays open throughout (paused, so its entries are dropped
  // rather than mixed in) — returnToLive() just re-triggers a fresh replay.
  const [historicalRange, setHistoricalRange] = useState<HistoricalRange | null>(null);
  const [loadingRange, setLoadingRange] = useState(false);
  // The effective cap live flushes trim to. Starts at MAX_ENTRIES but is
  // raised by loadOlder() so a deliberate "load more history" click doesn't
  // get silently trimmed back away by the next live-traffic flush.
  const capRef = useRef(MAX_ENTRIES);

  // Counter baseline captured on clear(): the header then shows counts "since
  // clear" (server totals minus this) instead of "since hub start". statsRef
  // mirrors stats so clear() can snapshot without re-creating on every update.
  const [baseline, setBaseline] = useState<StatsBaseline | null>(null);
  const statsRef = useRef<Stats | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const filterRef = useRef(initialFilter);
  const backoffRef = useRef(BACKOFF_BASE);

  // Coalesce arriving entries: buffer them and flush to state once per animation
  // frame so a burst of messages triggers a single re-render, not one per entry.
  //
  // Chromium-family browsers fully suspend requestAnimationFrame callbacks for a
  // hidden document (backgrounded tab/window) rather than merely throttling them.
  // If a flush were scheduled via rAF right as the tab goes hidden, it would never
  // fire: frameRef.current stays non-null, scheduleFlush's guard keeps early-
  // returning, and entries pile up in bufRef unflushed for as long as the tab
  // stays hidden. setTimeout is throttled but not suspended in the background
  // (browsers cap it to ~1/s), so we fall back to it whenever the document isn't
  // visible and switch back to rAF once it is.
  const bufRef = useRef<Entry[]>([]);
  const frameRef = useRef<number | null>(null);
  const frameKindRef = useRef<"raf" | "timeout">("raf");

  // Mirrors the last committed entries.length so flush() can decide whether a
  // batch overflows the cap *outside* the setEntries updater. React treats an
  // updater as a pure function of `prev` and is free to call it more than once
  // for the same update (<StrictMode> deliberately double-invokes it in dev),
  // so the updater must neither mutate its inputs nor call another setState —
  // see flush() below. Worst case this is one flush stale (React commits
  // between frames, so in practice it isn't), which would only delay the
  // "showing latest N" note by a frame.
  const entriesLenRef = useRef(0);
  entriesLenRef.current = entries.length;

  const cancelScheduledFlush = useCallback(() => {
    if (frameRef.current === null) return;
    if (frameKindRef.current === "raf") cancelAnimationFrame(frameRef.current);
    else clearTimeout(frameRef.current);
    frameRef.current = null;
  }, []);

  const scheduleFlush = useCallback(() => {
    if (frameRef.current !== null) return;
    const flush = () => {
      frameRef.current = null;
      const buf = bufRef.current;
      if (buf.length === 0) return;
      bufRef.current = [];
      // buf holds this frame's entries oldest-first; newest goes to the front.
      // Reversed here rather than inside the updater because reverse() mutates
      // in place: a second invocation of the updater (StrictMode, dev) would
      // flip the batch back to oldest-first and render it upside down.
      buf.reverse();
      // Likewise hoisted out of the updater — queueing a further state update
      // from inside one is a side effect in what must be a pure function.
      if (entriesLenRef.current + buf.length > capRef.current) setTruncated(true);
      setEntries(flushUpdater(buf, capRef.current));
    };
    if (document.visibilityState === "hidden") {
      frameKindRef.current = "timeout";
      frameRef.current = setTimeout(flush, HIDDEN_FLUSH_INTERVAL_MS) as unknown as number;
    } else {
      frameKindRef.current = "raf";
      frameRef.current = requestAnimationFrame(flush);
    }
  }, []);

  const connect = useCallback((filter: string) => {
    wsRef.current?.close();
    const ws = new WebSocket(wsURL(filter));
    wsRef.current = ws;
    ws.onopen = () => {
      setConnected(true);
      backoffRef.current = BACKOFF_BASE; // healthy connection resets the backoff
    };
    ws.onerror = (ev) => {
      console.error("hub websocket error", ev);
    };
    ws.onclose = () => {
      setConnected(false);
      // exponential backoff + jitter, capped, unless this socket was replaced
      const delay = backoffRef.current + Math.random() * BACKOFF_BASE;
      backoffRef.current = Math.min(backoffRef.current * BACKOFF_FACTOR, BACKOFF_MAX);
      setTimeout(() => {
        if (wsRef.current === ws) connect(filterRef.current);
      }, delay);
    };
    ws.onmessage = (ev) => {
      let msg: Envelope;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return; // ignore a malformed frame rather than throwing in onmessage
      }
      if (msg.type === "stats" && msg.stats) {
        statsRef.current = msg.stats;
        setStats(msg.stats);
        const point: StatsPoint = {
          timestamp: new Date().toISOString(),
          entriesPerSec: msg.stats.entriesPerSec,
          totalEntries: msg.stats.totalEntries,
        };
        setStatsHistory((prev) => {
          const next = prev.concat(point);
          if (next.length > STATS_HISTORY_CAP) next.shift();
          return next;
        });
      } else if (msg.type === "entry" && msg.entry) {
        if (pausedRef.current) {
          setPausedCount((c) => c + 1);
          return;
        }
        bufRef.current.push(msg.entry);
        scheduleFlush();
      } else if (msg.type === "entryBatch" && msg.entries) {
        // A batch is equivalent to its entries arriving as individual frames,
        // oldest first — feed them through the same buffer/pause path.
        const batch = msg.entries;
        if (pausedRef.current) {
          setPausedCount((c) => c + batch.length);
          return;
        }
        for (const e of batch) bufRef.current.push(e);
        scheduleFlush();
      } else if (msg.type === "filterError") {
        setFilterError(msg.error ?? "invalid filter");
      }
    };
  }, [scheduleFlush]);

  // Hydrate history once from the hub's rolling buffer so a fresh page load
  // shows a trend immediately instead of an empty sparkline that only fills
  // in as live "stats" ticks arrive over the next several minutes.
  useEffect(() => {
    fetch("/api/stats/history")
      .then((r) => (r.ok ? r.json() : []))
      .then((points: StatsPoint[]) => setStatsHistory(points))
      .catch(() => {});
  }, []);

  useEffect(() => {
    connect(filterRef.current);
    return () => {
      const ws = wsRef.current;
      wsRef.current = null;
      ws?.close();
      cancelScheduledFlush();
    };
  }, [connect, cancelScheduledFlush]);

  // Keep the scheduled flush mechanism matched to the current visibility
  // state, in both directions: a timeout fallback still pending after the tab
  // comes back to the foreground shouldn't make the user wait out the rest of
  // its (throttled, up to ~1s) interval, and — symmetrically — a rAF still
  // pending right as the tab goes to the background must be migrated to the
  // timeout fallback, since that rAF may never fire once hidden (the whole
  // reason scheduleFlush avoids rAF while hidden in the first place). Either
  // way, cancel and reschedule immediately rather than leaving a stale/stuck
  // timer in place.
  useEffect(() => {
    const onVisibilityChange = () => {
      if (frameRef.current === null) return;
      const wantKind = document.visibilityState === "hidden" ? "timeout" : "raf";
      if (frameKindRef.current === wantKind) return;
      cancelScheduledFlush();
      scheduleFlush();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, [cancelScheduledFlush, scheduleFlush]);

  // Wraps setPaused so resuming clears the "arrived while paused" count —
  // otherwise it would keep climbing from the previous pause window.
  const togglePause = useCallback((p: boolean) => {
    setPaused(p);
    if (!p) setPausedCount(0);
  }, []);

  const applyFilter = useCallback((f: string) => {
    filterRef.current = f;
    setFilterError(null);
    setTruncated(false);
    setNoMoreHistory(false);
    capRef.current = MAX_ENTRIES;
    // The hub does not replay history on a live filter swap, so clear what's shown.
    bufRef.current = [];
    setEntries([]);
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      // Update the server-side filter in place over the existing socket.
      ws.send(JSON.stringify({ type: "filter", filter: f }));
    } else {
      // Socket is closed/connecting — (re)connect with the filter in the URL.
      connect(f);
    }
  }, [connect]);

  // Loads a brushed timeline selection: pauses the live stream (so its
  // entries are dropped, not mixed into the snapshot) and replaces the shown
  // entries with the [since, until) window from the REST history endpoint.
  const loadRange = useCallback((since: string, until: string) => {
    setPaused(true);
    setLoadingRange(true);
    const q = new URLSearchParams({ since, until, limit: "1000" });
    if (filterRef.current) q.set("filter", filterRef.current);
    fetch(`/api/entries?${q}`)
      .then((r) => (r.ok ? r.json() : []))
      .then((snapshot: Entry[]) => {
        bufRef.current = [];
        setEntries(snapshot);
        setTruncated(false);
        setNoMoreHistory(false);
        setHistoricalRange({ since, until });
      })
      .catch(() => {
        // Transient fetch failure — historicalRange stays unset, so the UI
        // stays in whatever state it was (still paused; the user can retry).
      })
      .finally(() => setLoadingRange(false));
  }, []);

  // Leaves historical-snapshot mode: re-applying the current filter makes the
  // hub replay its recent buffer fresh over the existing socket (the same
  // mechanism a live filter change already uses), then un-pauses.
  const returnToLive = useCallback(() => {
    setHistoricalRange(null);
    applyFilter(filterRef.current);
    togglePause(false);
  }, [applyFilter, togglePause]);

  const clear = useCallback(() => {
    bufRef.current = [];
    setEntries([]);
    setTruncated(false);
    setNoMoreHistory(false);
    capRef.current = MAX_ENTRIES;
    // Reset the header counters too: snapshot the current totals as the new
    // baseline (workers/rate are live and stay untouched).
    const s = statsRef.current;
    setBaseline(s ? { total: s.totalEntries, byProto: { ...s.byProtocol } } : null);
  }, []);

  // Pages further back than the WS replay/live buffer via the REST history
  // endpoint, anchored on the oldest entry currently shown. Appended results
  // don't get MAX_ENTRIES-trimmed away by the next live flush (capRef is
  // raised to cover them) since the user explicitly asked to see more.
  //
  // Anchors on the entry's Seq (before_seq) when present rather than its id
  // (before): Seq is a plain numeric comparison the hub can apply even once
  // the anchoring entry itself has aged out of the ring buffer, whereas an
  // id-based anchor that's no longer present can't be located at all. Falls
  // back to id for an entry from a hub that predates Seq (seq === 0/absent).
  const loadOlder = useCallback(() => {
    const oldest = entries[entries.length - 1];
    if (!oldest || loadingOlder) return;
    setLoadingOlder(true);
    const q = new URLSearchParams(
      oldest.seq ? { before_seq: String(oldest.seq), limit: "200" } : { before: oldest.id, limit: "200" }
    );
    if (filterRef.current) q.set("filter", filterRef.current);
    fetch(`/api/entries?${q}`)
      .then((r) => (r.ok ? r.json() : []))
      .then((older: Entry[]) => {
        if (older.length === 0) {
          setNoMoreHistory(true);
          return;
        }
        capRef.current += older.length;
        setEntries((cur) => cur.concat(older));
      })
      .catch(() => {
        // Transient fetch failure — the button just stays clickable to retry.
      })
      .finally(() => setLoadingOlder(false));
  }, [entries, loadingOlder]);

  const displayStats = useMemo(() => applyBaseline(stats, baseline), [stats, baseline]);

  return {
    entries,
    stats: displayStats,
    connected,
    paused,
    pausedCount,
    setPaused: togglePause,
    clear,
    applyFilter,
    filterError,
    truncated,
    loadOlder,
    loadingOlder,
    noMoreHistory,
    statsHistory,
    historicalRange,
    loadingRange,
    loadRange,
    returnToLive,
  };
}

interface StatsBaseline {
  total: number;
  byProto: Record<string, number>;
}

// applyBaseline subtracts the counts captured at the last clear() so the header
// reads "since clear". Protocols with no traffic since clear drop out; rate and
// workers are live values and pass through unchanged.
function applyBaseline(s: Stats | null, base: StatsBaseline | null): Stats | null {
  if (!s || !base) return s;
  const byProtocol: Record<string, number> = {};
  for (const [p, n] of Object.entries(s.byProtocol)) {
    const d = n - (base.byProto[p] ?? 0);
    if (d > 0) byProtocol[p] = d;
  }
  return { ...s, totalEntries: Math.max(0, s.totalEntries - base.total), byProtocol };
}
