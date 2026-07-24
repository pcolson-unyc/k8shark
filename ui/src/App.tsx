import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useHub } from "./useHub";
import { StatsHeader } from "./components/StatsHeader";
import { FilterBar } from "./components/FilterBar";
import { Timeline } from "./components/Timeline";
import { TrafficTable } from "./components/TrafficTable";
import { EntryDetail } from "./components/EntryDetail";
import { ServiceMap } from "./components/ServiceMap";
import { TopView } from "./components/TopView";
import { CompareView } from "./components/CompareView";
import { KonamiShark } from "./components/KonamiShark";
import { isTypingTarget } from "./dom";
import type { Entry } from "./types";

type View = "list" | "map" | "top";

// parseView maps the ?view= query param to a View, defaulting to the list.
function parseView(search: string): View {
  const v = new URLSearchParams(search).get("view");
  return v === "map" || v === "top" ? v : "list";
}

const PROTO_CLAUSE_RE = /\bprotocol\s*==\s*"?([\w.-]+)"?/i;
const STATUS_CLAUSE_RE = /\bstatus\s*==\s*"?([\w.-]+)"?/i;

// Extracts the value a "<field> == x" clause (matched by re) pins the filter
// to, wherever it appears in the expression (not just when it's the whole
// filter) — shared by the protocol pills and the status chips.
function activeFieldValue(filter: string, re: RegExp): string | null {
  const m = filter.match(re);
  return m ? m[1] : null;
}

// Toggles a "<field> == value" clause matched by re: adds it (joined with
// "and") if absent, swaps the value if a different one is already pinned, or
// removes it — plus one adjacent connective — if it's already the active
// one. Preserves the rest of a compound filter instead of clobbering it.
function toggleFieldFilter(filter: string, re: RegExp, field: string, value: string): string {
  const m = re.exec(filter);
  if (!m) {
    const trimmed = filter.trim();
    return trimmed ? `${trimmed} and ${field} == ${value}` : `${field} == ${value}`;
  }
  if (m[1].toLowerCase() !== value.toLowerCase()) {
    return filter.slice(0, m.index) + `${field} == ${value}` + filter.slice(m.index + m[0].length);
  }
  const before = filter.slice(0, m.index).replace(/\s*\b(and|or)\s*$/i, "").trimEnd();
  const after = filter.slice(m.index + m[0].length).replace(/^\s*\b(and|or)\s*/i, "").trimStart();
  return before && after ? `${before} and ${after}` : before || after;
}

export function App() {
  const [filter, setFilter] = useState(() => new URLSearchParams(location.search).get("filter") ?? "");
  const hub = useHub(filter);
  const { paused, setPaused } = hub;
  const [selected, setSelected] = useState<Entry | null>(null);
  const [view, setView] = useState<View>(() => parseView(location.search));
  const [pinned, setPinned] = useState<Entry[]>([]);
  const [showCompare, setShowCompare] = useState(false);

  // Selecting a row to read its detail auto-pauses the live stream (unless
  // already paused), so the table doesn't keep scrolling out from under
  // whatever you're analyzing; closing the panel resumes it. autoPausedRef
  // tracks whether the *current* pause came from that auto-pause rather than
  // an explicit user choice, so closing the panel only resumes what selecting
  // it paused — a pause the user set manually (button, spacebar) before or
  // during selection is left alone.
  const autoPausedRef = useRef(false);

  const selectEntry = useCallback(
    (e: Entry) => {
      if (!paused) {
        autoPausedRef.current = true;
        setPaused(true);
      }
      setSelected(e);
    },
    [paused, setPaused]
  );

  const closeSelection = useCallback(() => {
    setSelected(null);
    if (autoPausedRef.current) {
      autoPausedRef.current = false;
      setPaused(false);
    }
  }, [setPaused]);

  // Any explicit pause/resume (button or spacebar) takes ownership away from
  // the auto-pause bookkeeping above, so closing the detail panel afterward
  // won't override what the user just chose.
  const togglePauseManual = useCallback(() => {
    autoPausedRef.current = false;
    setPaused(!paused);
  }, [paused, setPaused]);

  // Pin up to two entries for the compare view; pinning a third drops the
  // oldest pin. Pinning holds a snapshot of the entry, not just its id, so a
  // pin survives the entry aging out of the live buffer.
  const togglePin = (e: Entry) => {
    setPinned((prev) => {
      if (prev.some((p) => p.id === e.id)) return prev.filter((p) => p.id !== e.id);
      if (prev.length >= 2) return [prev[1], e];
      return [...prev, e];
    });
  };

  const onApply = (f: string) => {
    setFilter(f);
    hub.applyFilter(f);
    closeSelection();
  };

  // Resolve a ?entry=<id> permalink on first load. Not necessarily in the
  // live/replayed buffer yet (or ever, if it aged out) — fetch it directly.
  useEffect(() => {
    const id = new URLSearchParams(location.search).get("entry");
    if (!id) return;
    fetch(`/api/entry/${encodeURIComponent(id)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((e) => e && selectEntry(e))
      .catch(() => {});
    // selectEntry is intentionally omitted: this must run exactly once, at
    // mount, against the URL as it was on page load. selectEntry's identity
    // changes with hub.paused, so including it would re-run this on every
    // later pause/resume — re-fetching the same permalink and, worse,
    // re-triggering auto-pause each time the user manually resumes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep the URL in sync with filter/view/selection so the current view is
  // bookmarkable and shareable, without piling up history entries.
  useEffect(() => {
    const params = new URLSearchParams();
    if (filter) params.set("filter", filter);
    if (view !== "list") params.set("view", view);
    if (selected) params.set("entry", selected.id);
    const qs = params.toString();
    history.replaceState(null, "", qs ? `${location.pathname}?${qs}` : location.pathname);
  }, [filter, view, selected]);

  const activeProto = useMemo(() => activeFieldValue(filter, PROTO_CLAUSE_RE), [filter]);
  const activeStatus = useMemo(() => activeFieldValue(filter, STATUS_CLAUSE_RE), [filter]);

  // Click a protocol pill / status chip to add/swap/remove its clause in the
  // filter.
  const onProtoClick = (proto: string) => {
    onApply(toggleFieldFilter(filter, PROTO_CLAUSE_RE, "protocol", proto));
  };
  const onStatusClick = (status: string) => {
    onApply(toggleFieldFilter(filter, STATUS_CLAUSE_RE, "status", status));
  };

  // Global shortcuts: "/" focuses the filter (unless already typing
  // somewhere), space toggles pause (only when nothing specific has focus,
  // so it doesn't fight a focused row/button's own Space handling), Escape
  // closes the detail panel.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "/" && !isTypingTarget(e.target)) {
        e.preventDefault();
        document.getElementById("filter-input")?.focus();
      } else if (e.key === " " && document.activeElement === document.body) {
        e.preventDefault();
        autoPausedRef.current = false;
        setPaused(!paused);
      } else if (e.key === "Escape") {
        closeSelection();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [paused, setPaused, closeSelection]);

  // Index the live buffer by id once per change so the selected-entry lookup
  // below is O(1) instead of an entries.find() linear scan on every render —
  // the buffer can hold 10k+ entries and hub.entries gets a fresh identity on
  // every rAF flush, so the scan otherwise re-ran each frame (UI-8).
  const entriesById = useMemo(() => {
    const byId = new Map<string, Entry>();
    for (const e of hub.entries) byId.set(e.id, e);
    return byId;
  }, [hub.entries]);

  // Keep the selected entry object in sync with the freshest list reference.
  const selectedLive = useMemo(
    () => (selected ? entriesById.get(selected.id) ?? selected : null),
    [selected, entriesById]
  );

  const pinnedIds = useMemo(() => new Set(pinned.map((p) => p.id)), [pinned]);

  return (
    <div className="app">
      <KonamiShark />
      <StatsHeader
        stats={hub.stats}
        statsHistory={hub.statsHistory}
        connected={hub.connected}
        onProtoClick={onProtoClick}
        activeProto={activeProto}
        onStatusClick={onStatusClick}
        activeStatus={activeStatus}
      />
      <FilterBar
        value={filter}
        onApply={onApply}
        paused={hub.paused}
        pausedCount={hub.pausedCount}
        onTogglePause={togglePauseManual}
        onClear={hub.clear}
        view={view}
        onViewChange={setView}
        count={hub.entries.length}
        truncated={hub.truncated}
        filterError={hub.filterError}
        entries={hub.entries}
        historicalRange={hub.historicalRange}
        onReturnToLive={hub.returnToLive}
      />
      <Timeline filter={filter} onRangeSelect={hub.loadRange} />
      {view === "list" ? (
        <div className="main split">
          <TrafficTable
            entries={hub.entries}
            selectedId={selectedLive?.id ?? null}
            onSelect={selectEntry}
            onLoadOlder={hub.loadOlder}
            loadingOlder={hub.loadingOlder}
            noMoreHistory={hub.noMoreHistory}
            pinnedIds={pinnedIds}
            onTogglePin={togglePin}
            onCompare={() => setShowCompare(true)}
          />
          {selectedLive && (
            <EntryDetail entry={selectedLive} onClose={closeSelection} onApply={onApply} />
          )}
          {showCompare && pinned.length === 2 && (
            <CompareView a={pinned[0]} b={pinned[1]} onClose={() => setShowCompare(false)} />
          )}
        </div>
      ) : view === "map" ? (
        <div className="main">
          <ServiceMap
            entries={hub.entries}
            onNodeClick={(clause) => {
              onApply(clause);
              setView("list");
            }}
          />
        </div>
      ) : (
        <div className="main">
          <TopView
            filter={filter}
            onApply={(clause) => {
              onApply(clause);
              setView("list");
            }}
          />
        </div>
      )}
    </div>
  );
}
