import type { CSSProperties, ReactNode } from "react";
import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { isTypingTarget } from "../dom";
import type { Entry } from "../types";
import { PROTO_COLORS } from "../constants";

// Matches the row height content-visibility used to assume before real
// virtualization replaced it (styles.css .row).
const ROW_HEIGHT = 29;

type SortKey = "proto" | "status" | "latency" | "time" | "node" | "bytes" | "packets";
type SortDir = "asc" | "desc";
interface SortState {
  key: SortKey;
  dir: SortDir;
}

interface ColumnDef {
  key: string;
  label: string;
  className: string;
  sortKey?: SortKey;
  mono?: boolean;
}

// node/bytes/packets are present on every entry but weren't previously shown
// anywhere in the table — optional columns, hidden by default.
const ALL_COLUMNS: ColumnDef[] = [
  { key: "proto", label: "proto", className: "col-proto", sortKey: "proto" },
  { key: "status", label: "status", className: "col-status", sortKey: "status" },
  { key: "summary", label: "summary", className: "col-summary", mono: true },
  { key: "source", label: "source", className: "col-src", mono: true },
  { key: "destination", label: "destination", className: "col-dst", mono: true },
  { key: "latency", label: "latency", className: "col-lat", sortKey: "latency", mono: true },
  { key: "time", label: "time", className: "col-time", sortKey: "time", mono: true },
  { key: "node", label: "node", className: "col-node", sortKey: "node", mono: true },
  { key: "bytes", label: "bytes", className: "col-bytes", sortKey: "bytes", mono: true },
  { key: "packets", label: "packets", className: "col-packets", sortKey: "packets", mono: true },
];
const ALWAYS_ON = new Set(["proto", "status"]);
const DEFAULT_VISIBLE = ["proto", "status", "summary", "source", "destination", "latency", "time"];
const VISIBLE_COLUMNS_KEY = "k8shark.columns";

function loadVisibleColumns(): Set<string> {
  try {
    const raw = localStorage.getItem(VISIBLE_COLUMNS_KEY);
    if (raw) return new Set(JSON.parse(raw));
  } catch {
    // corrupt/inaccessible storage — fall through to defaults
  }
  return new Set(DEFAULT_VISIBLE);
}

function sortValue(e: Entry, key: SortKey): number | string {
  switch (key) {
    case "proto":
      return e.protocol;
    case "status":
      return e.status || "";
    case "latency":
      return e.elapsedMs;
    case "time":
      return new Date(e.timestamp).getTime();
    case "node":
      return e.node || "";
    case "bytes":
      return e.request.bytes ?? 0;
    case "packets":
      return e.request.packets ?? 0;
  }
}

function compareEntries(a: Entry, b: Entry, key: SortKey): number {
  const va = sortValue(a, key);
  const vb = sortValue(b, key);
  if (typeof va === "number" && typeof vb === "number") return va - vb;
  return String(va).localeCompare(String(vb));
}

// cellContent runs once per visible cell per render — with the row window and
// a live feed that's on the order of a thousand calls a second — so anything
// it would otherwise allocate per call is hoisted to module scope: one frozen
// style object per protocol (a fresh literal is a new prop identity every
// time, which forces the <span> to re-apply its style), and one shared
// Intl.DateTimeFormat, since toLocaleTimeString constructs (and, at best,
// cache-looks-up) a formatter on every single call.
const PROTO_BADGE_STYLES: Record<string, CSSProperties> = Object.fromEntries(
  Object.entries(PROTO_COLORS).map(([proto, color]) => [proto, { background: color }])
);
const UNKNOWN_PROTO_BADGE_STYLE: CSSProperties = { background: "#888" };

// Exactly the options Date.prototype.toLocaleTimeString([], { hour12: false })
// resolves to (it defaults hour/minute/second to "numeric" when none of the
// time components are given), so the rendered text is unchanged — see the
// byte-identical assertion in TrafficTable.test.tsx.
const TIME_FORMAT = new Intl.DateTimeFormat([], {
  hour12: false,
  hour: "numeric",
  minute: "numeric",
  second: "numeric",
});

function cellContent(key: string, e: Entry): ReactNode {
  switch (key) {
    case "proto":
      return (
        <span className="proto-badge" style={PROTO_BADGE_STYLES[e.protocol] ?? UNKNOWN_PROTO_BADGE_STYLE}>
          {e.protocol}
        </span>
      );
    case "status":
      return <StatusBadge entry={e} />;
    case "summary":
      return e.request.summary || "—";
    case "source":
      return endpoint(e.src);
    case "destination":
      return endpoint(e.dst);
    case "latency":
      return `${e.elapsedMs}ms`;
    case "time":
      return time(e.timestamp);
    case "node":
      return e.node || "—";
    case "bytes":
      return e.request.bytes ? String(e.request.bytes) : "—";
    case "packets":
      return e.request.packets ? String(e.request.packets) : "—";
    default:
      return null;
  }
}

interface Props {
  entries: Entry[];
  selectedId: string | null;
  onSelect: (e: Entry) => void;
  onLoadOlder: () => void;
  loadingOlder: boolean;
  noMoreHistory: boolean;
  pinnedIds: Set<string>;
  onTogglePin: (e: Entry) => void;
  onCompare: () => void;
}

export const TrafficTable = memo(function TrafficTable({
  entries,
  selectedId,
  onSelect,
  onLoadOlder,
  loadingOlder,
  noMoreHistory,
  pinnedIds,
  onTogglePin,
  onCompare,
}: Props) {
  const [visible, setVisible] = useState<Set<string>>(loadVisibleColumns);
  const [sort, setSort] = useState<SortState | null>(null);
  // UI-8: snapshot of the buffer taken when a sort turns on — see the comment
  // above sortedFrozen for why the stream is frozen while sorting.
  const [frozenBase, setFrozenBase] = useState<Entry[] | null>(null);

  useEffect(() => {
    localStorage.setItem(VISIBLE_COLUMNS_KEY, JSON.stringify([...visible]));
  }, [visible]);

  const toggleColumn = (key: string) => {
    if (ALWAYS_ON.has(key)) return;
    setVisible((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const onHeaderClick = (key: SortKey) => {
    setSort((prev) => {
      if (!prev || prev.key !== key) return { key, dir: "asc" };
      if (prev.dir === "asc") return { key, dir: "desc" };
      return null;
    });
  };

  const columns = useMemo(() => ALL_COLUMNS.filter((c) => visible.has(c.key)), [visible]);

  // UI-8: re-sorting the whole buffer on every rAF flush is O(n log n) per
  // frame, and n is unbounded once "load older" has grown the buffer. Plain
  // memoization can't tame it: live streaming hands us a brand-new `entries`
  // array (newest prepended) every single frame, so the sort's input changes
  // every frame regardless of what the memo is keyed on. Instead we freeze the
  // stream while a sort is active — snapshot the buffer the instant the sort
  // turns on and sort *that* once; live arrivals keep flowing into `entries`
  // but aren't merged into the sorted view until the user syncs (banner) or
  // clears the sort. frozenBase is derived during render (React's "adjust state
  // when a prop/state changes" pattern) so it stays in lockstep with `sort`
  // within a single render: set the moment sort becomes truthy, cleared the
  // moment it's null.
  if (sort && frozenBase === null) setFrozenBase(entries);
  else if (!sort && frozenBase !== null) setFrozenBase(null);
  // entries is wiped wholesale on Clear / a filter change / a loaded range
  // (see the scroll-compensation effect below). While sorted, displayEntries
  // is frozenBase's stale snapshot rather than entries itself, so that wipe
  // otherwise goes unnoticed here — the table would keep showing pre-wipe
  // rows under a "stream frozen" banner forever. Dropping the sort drops
  // frozenBase with it (the branch above) and falls back to the now-empty
  // entries.
  else if (sort && entries.length === 0) setSort(null);

  // Keyed on [sort, frozenBase] — deliberately NOT on `entries` — so a live
  // flush (new `entries` ref every frame) never re-triggers the sort. It runs
  // once per freeze, and again only when the sort key/dir changes or the
  // snapshot is refreshed via syncFrozen.
  const sortedFrozen = useMemo(() => {
    if (!sort || !frozenBase) return null;
    const copy = frozenBase.slice();
    copy.sort((a, b) => compareEntries(a, b, sort.key) * (sort.dir === "asc" ? 1 : -1));
    return copy;
  }, [sort, frozenBase]);

  const displayEntries = sortedFrozen ?? entries;

  // How many live entries have streamed in above the frozen snapshot (surfaced
  // in the "stream frozen" banner). The snapshot's old top sits exactly after
  // the freshly-prepended entries, so findIndex scans only the new ones —
  // O(new), not O(n).
  const frozenNewCount = useMemo(() => {
    if (!frozenBase) return 0;
    const topId = frozenBase[0]?.id;
    if (!topId) return entries.length;
    const idx = entries.findIndex((e) => e.id === topId);
    return idx === -1 ? entries.length : idx;
  }, [entries, frozenBase]);

  // Merge the live buffer into the frozen view and re-sort it (banner click).
  const syncFrozen = () => setFrozenBase(entries);

  // Real DOM windowing: only rows actually in (or near) the viewport get
  // mounted, unlike the old content-visibility:auto trick which still kept
  // every row in the DOM for React to reconcile. Table semantics (sticky
  // thead, real <tr>/<td>) are preserved via the padding-row technique
  // instead of absolutely-positioned rows, which table layout doesn't
  // support well.
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowVirtualizer = useVirtualizer({
    count: displayEntries.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });
  const virtualRows = rowVirtualizer.getVirtualItems();
  const paddingTop = virtualRows.length > 0 ? virtualRows[0].start : 0;
  const paddingBottom =
    virtualRows.length > 0 ? rowVirtualizer.getTotalSize() - virtualRows[virtualRows.length - 1].end : 0;
  const colSpan = columns.length + 1;

  // ArrowUp/ArrowDown triage a stream of entries one row at a time (Wireshark/
  // DevTools-style) without needing to click into the table first — mirrors
  // App.tsx's other global shortcuts ("/", space, Escape), but has to live
  // here since displayEntries (the active sort order) and the virtualizer
  // are local to this component. No selection yet -> jumps to the first row;
  // otherwise moves by one, clamped at the ends (no wraparound).
  //
  // What the handler reads is held in a ref rather than listed as effect
  // dependencies: displayEntries gets a brand-new identity on every rAF flush
  // of the live stream, so depending on it directly tore down and re-added a
  // global keydown listener ~60 times a second for a handler whose behaviour
  // never changes. The ref is written during render, so the listener always
  // sees the latest committed values. (rowVirtualizer is *not* in that
  // category — useVirtualizer hands back one stable instance for the lifetime
  // of the component — so it stays a real dependency.)
  const keyNavRef = useRef({ displayEntries, selectedId, onSelect });
  keyNavRef.current = { displayEntries, selectedId, onSelect };

  useEffect(() => {
    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
      if (isTypingTarget(ev.target)) return;
      const { displayEntries: rows, selectedId: curId, onSelect: select } = keyNavRef.current;
      if (rows.length === 0) return;
      const curIdx = curId ? rows.findIndex((e) => e.id === curId) : -1;
      const next =
        curIdx === -1
          ? 0
          : ev.key === "ArrowDown"
            ? Math.min(curIdx + 1, rows.length - 1)
            : Math.max(curIdx - 1, 0);
      if (next === curIdx) return;
      ev.preventDefault();
      select(rows[next]);
      rowVirtualizer.scrollToIndex(next);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [rowVirtualizer]);

  // Live entries are prepended to the front of the list (newest first), so
  // without this every flush shifts whatever the user is currently reading
  // further down the page — the single biggest irritant of the real-time
  // view. topIdRef tracks the previous top-of-list id; when new rows appear
  // above it and the user has scrolled away from the very top (still
  // reading, not following live), compensate scrollTop by exactly their
  // height so the row under the user's eye doesn't move, and count them for
  // the "N new entries" pill below. Runs in a layout effect so the
  // compensation lands before the browser paints the shifted rows.
  const topIdRef = useRef<string | null>(null);
  const [newCount, setNewCount] = useState(0);

  // A live feed can flush dozens of times a second, so without care this
  // effect writes scrollTop just as often. Doing that while the user (or, on
  // a trackpad, the browser's own momentum coast) is mid-scroll races the
  // native scroll animation: each write can look like new input and restart
  // its deceleration, so the view never settles — "scrolling never stops"
  // until capture is paused. lastUserScrollAtRef timestamps the most recent
  // scroll event NOT caused by our own write (ignoreNextScrollRef flags
  // ours); while one happened within SCROLL_SETTLE_MS we bank the owed rows
  // in pendingRowsRef instead of touching scrollTop, and apply the banked
  // total (plus whatever's arrived since) the moment things go quiet.
  const SCROLL_SETTLE_MS = 150;
  const lastUserScrollAtRef = useRef(0);
  const ignoreNextScrollRef = useRef(false);
  const pendingRowsRef = useRef(0);

  useLayoutEffect(() => {
    const newTopId = displayEntries[0]?.id ?? null;

    // A sort recomputes the whole order rather than prepending — "entries
    // arrived above where I was reading" isn't a meaningful concept once
    // sorted, so there's nothing to compensate or count.
    if (sort || newTopId === null) {
      topIdRef.current = newTopId;
      setNewCount(0);
      pendingRowsRef.current = 0;
      // The buffer was wiped wholesale (Clear, a filter change, a loaded
      // range) rather than just streamed into. Leaving scrollTop wherever it
      // was points the viewport at an offset the now-empty/rebuilding list
      // has no content for — new rows landing while compensation is still
      // measured against that stale position read as arriving "in the
      // middle" of the view instead of at the top.
      if (newTopId === null && scrollRef.current) scrollRef.current.scrollTop = 0;
      return;
    }

    const prevTopId = topIdRef.current;
    topIdRef.current = newTopId;
    const el = scrollRef.current;
    if (!prevTopId || prevTopId === newTopId || !el) return;

    const prependedCount = displayEntries.findIndex((e) => e.id === prevTopId);
    if (prependedCount <= 0) return; // not found (buffer reset) or nothing prepended

    if (el.scrollTop > 0) {
      pendingRowsRef.current += prependedCount;
      const scrolling = Date.now() - lastUserScrollAtRef.current < SCROLL_SETTLE_MS;
      if (scrolling) return; // bank it — a native scroll animation may still be in flight

      const before = el.scrollTop;
      ignoreNextScrollRef.current = true;
      el.scrollTop = before + pendingRowsRef.current * ROW_HEIGHT;
      // Pinned at the bottom of a capped buffer, the compensating scroll has
      // nowhere left to go — the browser clamps the write and the visible
      // rows don't actually move. Count only what really scrolled, or the
      // pill climbs forever (thousands of "new entries") even though the
      // user is sitting still at the end of the list.
      const movedRows = Math.round((el.scrollTop - before) / ROW_HEIGHT);
      if (movedRows > 0) setNewCount((n) => n + movedRows);
      pendingRowsRef.current = 0;
    }
  }, [displayEntries, sort]);

  const scrollToTop = () => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
    setNewCount(0);
  };

  return (
    <div className="table-wrap-outer">
      <div className="table-toolbar">
        <ColumnPicker visible={visible} onToggle={toggleColumn} />
        {pinnedIds.size > 0 && (
          <button type="button" className="chip" onClick={onCompare} disabled={pinnedIds.size !== 2}>
            {pinnedIds.size === 2 ? "compare pinned (2)" : `pinned ${pinnedIds.size}/2 — pick one more`}
          </button>
        )}
        {sort && (
          <span className="table-toolbar-hint">
            sorted by {sort.key} ({sort.dir}) — click the header again to change, a third click resets
          </span>
        )}
      </div>
      {!sort && newCount > 0 && (
        <button type="button" className="new-entries-pill" onClick={scrollToTop}>
          ↑ {newCount} new {newCount === 1 ? "entry" : "entries"}
        </button>
      )}
      {sort && (
        <button type="button" className="new-entries-pill" onClick={syncFrozen}>
          sort active — stream frozen{frozenNewCount > 0 ? `, ${frozenNewCount} new` : ""} · click to sync
        </button>
      )}
      <div
        className="table-wrap"
        ref={scrollRef}
        onScroll={(e) => {
          if (e.currentTarget.scrollTop <= 0) setNewCount(0);
          if (ignoreNextScrollRef.current) {
            ignoreNextScrollRef.current = false;
          } else {
            lastUserScrollAtRef.current = Date.now();
          }
        }}
      >
        <table className="traffic">
          <thead>
            <tr>
              <th className="col-pin" title="pin up to two entries to compare"></th>
              {columns.map((c) => {
                const active = !!sort && !!c.sortKey && sort.key === c.sortKey;
                return (
                  <th
                    key={c.key}
                    className={c.className}
                    onClick={c.sortKey ? () => onHeaderClick(c.sortKey!) : undefined}
                    aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
                    style={c.sortKey ? { cursor: "pointer" } : undefined}
                  >
                    {c.label}
                    {active && <span className="sort-arrow">{sort!.dir === "asc" ? " ▲" : " ▼"}</span>}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr className="empty">
                <td colSpan={colSpan}>Waiting for traffic… (workers stream matching entries here in real time)</td>
              </tr>
            )}
            {paddingTop > 0 && (
              <tr aria-hidden="true">
                <td colSpan={colSpan} style={{ height: paddingTop, padding: 0, border: "none" }} />
              </tr>
            )}
            {virtualRows.map((vRow) => {
              const e = displayEntries[vRow.index];
              return (
                <Row
                  key={e.id}
                  e={e}
                  columns={columns}
                  selected={e.id === selectedId}
                  onSelect={onSelect}
                  pinned={pinnedIds.has(e.id)}
                  onTogglePin={onTogglePin}
                />
              );
            })}
            {paddingBottom > 0 && (
              <tr aria-hidden="true">
                <td colSpan={colSpan} style={{ height: paddingBottom, padding: 0, border: "none" }} />
              </tr>
            )}
            {entries.length > 0 && (
              <tr className="load-older">
                <td colSpan={colSpan}>
                  {noMoreHistory ? (
                    <span className="load-older-note">no more history</span>
                  ) : (
                    <button type="button" className="chip" onClick={onLoadOlder} disabled={loadingOlder}>
                      {loadingOlder ? "loading…" : "load older"}
                    </button>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
});

function ColumnPicker({ visible, onToggle }: { visible: Set<string>; onToggle: (key: string) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDocMouseDown = (ev: MouseEvent) => {
      if (ref.current && !ref.current.contains(ev.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDocMouseDown);
    return () => document.removeEventListener("mousedown", onDocMouseDown);
  }, [open]);

  return (
    <div className="col-picker" ref={ref}>
      <button type="button" className="chip" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="true">
        columns ▾
      </button>
      {open && (
        <div className="col-picker-menu" role="menu">
          {ALL_COLUMNS.filter((c) => !ALWAYS_ON.has(c.key)).map((c) => (
            <label key={c.key} className="col-picker-item">
              <input type="checkbox" checked={visible.has(c.key)} onChange={() => onToggle(c.key)} />
              {c.label}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

const Row = memo(function Row({
  e,
  columns,
  selected,
  onSelect,
  pinned,
  onTogglePin,
}: {
  e: Entry;
  columns: ColumnDef[];
  selected: boolean;
  onSelect: (e: Entry) => void;
  pinned: boolean;
  onTogglePin: (e: Entry) => void;
}) {
  return (
    <tr
      className={`row ${selected ? "sel" : ""} st-${e.status || "na"}`}
      role="button"
      tabIndex={0}
      onClick={() => onSelect(e)}
      onKeyDown={(ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          onSelect(e);
        }
      }}
    >
      <td className="col-pin" onClick={(ev) => ev.stopPropagation()}>
        <input
          type="checkbox"
          checked={pinned}
          onChange={() => onTogglePin(e)}
          title="pin to compare"
          aria-label={`pin ${e.request.summary || e.id} to compare`}
        />
      </td>
      {columns.map((c) => (
        <td key={c.key} className={`${c.className}${c.mono ? " mono" : ""}`}>
          {cellContent(c.key, e)}
        </td>
      ))}
    </tr>
  );
});

function StatusBadge({ entry }: { entry: Entry }) {
  if (entry.protocol === "http") {
    return <span className={`code st-${entry.status}`}>{entry.statusCode || "—"}</span>;
  }
  return <span className={`code st-${entry.status}`}>{entry.status || "ok"}</span>;
}

function endpoint(ep: { name?: string; ip: string; port: number; namespace?: string }): string {
  if (ep.name) return ep.namespace ? `${ep.name}.${ep.namespace}` : ep.name;
  return `${ep.ip}:${ep.port}`;
}

function time(ts: string): string {
  const d = new Date(ts);
  // The one place the hoisted formatter is NOT equivalent to the
  // toLocaleTimeString call it replaced: on an Invalid Date, toLocaleTimeString
  // returns the string "Invalid Date", while Intl.DateTimeFormat's format()
  // throws a RangeError (ECMA-402, PartitionDateTimePattern step 1). A single
  // entry with an unparseable timestamp landing in the row window would throw
  // during render, and there's no error boundary above the table — React would
  // unmount the whole App subtree, i.e. a blank page instead of one junk cell.
  // Degrade to the raw timestamp instead.
  if (Number.isNaN(d.getTime())) return ts;
  return TIME_FORMAT.format(d) + "." + String(d.getMilliseconds()).padStart(3, "0");
}
