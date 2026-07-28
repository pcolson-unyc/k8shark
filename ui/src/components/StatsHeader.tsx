import { memo } from "react";
import type { Stats, StatsPoint } from "../types";
import { PROTO_COLORS } from "../constants";
import { Sparkline } from "./Sparkline";
import { useTheme } from "../useTheme";
import { useWorkers } from "../useWorkers";

const STATUS_ORDER = ["success", "warning", "error"] as const;

// memo()'d: everything the header shows changes at most once a second (the
// hub's stats tick), but its parent re-renders with every rAF flush of the
// live entry stream. The memo only holds if the callbacks App passes down are
// themselves stable — see the useCallback()s around onProtoClick/onStatusClick
// there.
export const StatsHeader = memo(function StatsHeader({
  stats,
  statsHistory,
  connected,
  onProtoClick,
  activeProto,
  onStatusClick,
  activeStatus,
}: {
  stats: Stats | null;
  statsHistory: StatsPoint[];
  connected: boolean;
  onProtoClick?: (proto: string) => void;
  activeProto?: string | null;
  onStatusClick?: (status: string) => void;
  activeStatus?: string | null;
}) {
  const { theme, toggleTheme } = useTheme();
  const { workers, setCapturePaused } = useWorkers();
  const connectedWorkers = workers.filter((w) => w.connected);
  const capturePaused = connectedWorkers.length > 0 && connectedWorkers.every((w) => w.capturePaused);

  return (
    <header className="header">
      <div className="brand">
        <span className="logo">🦈</span>
        <span className="brand-name">k8shark</span>
      </div>

      <div className="stat-group">
        <Stat label="entries" value={stats ? fmt(stats.totalEntries) : "—"} />
        <Stat label="entries/s" value={stats ? stats.entriesPerSec.toFixed(1) : "—"} />
        <Stat label="workers" value={stats ? String(stats.workers) : "—"} />
      </div>

      <Sparkline points={statsHistory} />

      {stats && (
        <div className="status-chips">
          {STATUS_ORDER.filter((s) => stats.byStatus[s]).map((s) => (
            <button
              key={s}
              type="button"
              className={`status-chip st-${s}${activeStatus === s ? " active" : ""}`}
              onClick={() => onStatusClick?.(s)}
              title={`Filter: status == ${s}`}
              aria-pressed={activeStatus === s}
            >
              {fmt(stats.byStatus[s])} {s}
            </button>
          ))}
        </div>
      )}

      <div className="proto-pills">
        {stats &&
          Object.entries(stats.byProtocol)
            .sort((a, b) => b[1] - a[1])
            .map(([p, n]) => (
              <button
                key={p}
                type="button"
                className={`pill${activeProto === p ? " active" : ""}`}
                style={{ borderColor: PROTO_COLORS[p] ?? "#888" }}
                onClick={() => onProtoClick?.(p)}
                title={`Filter: protocol == ${p}`}
                aria-pressed={activeProto === p}
              >
                <span className="dot" style={{ background: PROTO_COLORS[p] ?? "#888" }} />
                {p} <b>{fmt(n)}</b>
              </button>
            ))}
      </div>

      {!!stats?.broadcastDropped && (
        <span
          className="health-warn"
          title={`${stats.broadcastDropped} entries dropped because this client couldn't keep up with the live stream (send buffer full) since the hub started. Traffic capture itself is unaffected — only this dashboard's view of it fell behind.`}
        >
          ⚠ {fmt(stats.broadcastDropped)} dropped
        </span>
      )}

      <div className={`conn ${connected ? "on" : "off"}`} aria-live="polite">
        <span className="conn-dot" />
        {connected ? "live" : "reconnecting…"}
      </div>

      <button
        type="button"
        className={`toggle capture-toggle${capturePaused ? " active" : ""}`}
        onClick={() => setCapturePaused(!capturePaused)}
        disabled={connectedWorkers.length === 0}
        title={
          connectedWorkers.length === 0
            ? "no workers connected"
            : capturePaused
              ? `resume capture on ${connectedWorkers.length === 1 ? "the connected node" : `all ${connectedWorkers.length} connected nodes`}`
              : `pause capture on ${connectedWorkers.length === 1 ? "the connected node" : `all ${connectedWorkers.length} connected nodes`} — the worker stays connected, it just stops turning what it reads into entries`
        }
      >
        {capturePaused ? "▶ resume capture" : "⏸ pause capture"}
      </button>

      <button
        type="button"
        className="icon-btn theme-toggle"
        onClick={toggleTheme}
        title={theme === "dark" ? "switch to light mode" : "switch to dark mode"}
        aria-label={theme === "dark" ? "switch to light mode" : "switch to dark mode"}
      >
        {theme === "dark" ? "☀️" : "🌙"}
      </button>
    </header>
  );
});

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function fmt(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "k";
  return String(n);
}
