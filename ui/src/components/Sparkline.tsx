import { memo, useMemo } from "react";
import type { StatsPoint } from "../types";

const WIDTH = 90;
const HEIGHT = 28;
const PAD = 2;

// A dependency-free inline-SVG sparkline of entries/sec over time (matches
// ServiceMap's "no charting lib" approach). Renders an empty placeholder
// until there are at least two points to draw a line between.
//
// memo()'d, and the geometry memoised on the points array: `points` is the
// stats history, which only grows when a "stats" frame arrives (about once a
// second, capped at 300 samples), but its parent re-renders with the live
// entry stream. Rebuilding the polyline is two toFixed() calls per point —
// trivial once a second, ~36k string formats a second at 60fps.
export const Sparkline = memo(function Sparkline({ points }: { points: StatsPoint[] }) {
  const geometry = useMemo(() => {
    if (points.length < 2) return null;
    const rates = points.map((p) => p.entriesPerSec);
    const max = Math.max(1, ...rates);
    const step = WIDTH / (points.length - 1);
    const y = (r: number) => HEIGHT - PAD - (r / max) * (HEIGHT - PAD * 2);
    const last = rates[rates.length - 1];
    return {
      coords: rates.map((r, i) => `${(i * step).toFixed(1)},${y(r).toFixed(1)}`).join(" "),
      last,
      lastY: y(last),
    };
  }, [points]);

  if (!geometry) {
    return <svg className="sparkline" width={WIDTH} height={HEIGHT} aria-hidden="true" />;
  }

  return (
    <svg
      className="sparkline"
      width={WIDTH}
      height={HEIGHT}
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      role="img"
      aria-label={`entries per second trend over the last ${points.length} samples, most recent ${geometry.last.toFixed(1)}/s`}
    >
      <polyline points={geometry.coords} fill="none" stroke="var(--accent)" strokeWidth={1.5} strokeLinejoin="round" />
      <circle cx={WIDTH} cy={geometry.lastY} r={2.2} fill="var(--accent)" />
    </svg>
  );
});
