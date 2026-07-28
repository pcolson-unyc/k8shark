import { memo, useRef, useState } from "react";
import { useTimeline } from "../useTimeline";
import type { TimelineBucket } from "../types";

const VB_W = 1000;
const VB_H = 64;
const BAR_GAP = 1;

interface Tooltip {
  x: number;
  y: number;
  bucket: TimelineBucket;
}

interface Props {
  filter: string;
  onRangeSelect: (since: string, until: string) => void;
}

// Timeline is a dependency-free inline-SVG stacked histogram of recent
// traffic (matches ServiceMap/Sparkline's "no charting lib" approach):
// success/warning/error counts per bucket, with a mouse-drag brush to select
// a sub-range. Releasing the drag reports the selected window's [since,
// until) as ISO timestamps — the caller decides what to do with it (this
// component has no opinion on live vs. historical viewing).
//
// memo()'d: both props are stable (a filter string and a useCallback), while
// App re-renders on every rAF flush of the live entry stream. The buckets this
// draws come from its own polling hook and change every few seconds at most,
// so without the memo the whole histogram was reconciled ~60 times a second
// for nothing.
export const Timeline = memo(function Timeline({ filter, onRangeSelect }: Props) {
  const { buckets, bucketSeconds } = useTimeline(filter);
  const svgRef = useRef<SVGSVGElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [drag, setDrag] = useState<{ start: number; end: number } | null>(null);
  const [hover, setHover] = useState<Tooltip | null>(null);

  const barW = buckets.length > 0 ? VB_W / buckets.length : 0;
  const maxEntries = Math.max(1, ...buckets.map((b) => b.entries));
  const scale = (VB_H - 2) / maxEntries;

  const indexAt = (clientX: number): number => {
    const rect = svgRef.current!.getBoundingClientRect();
    const frac = (clientX - rect.left) / rect.width;
    return Math.min(buckets.length - 1, Math.max(0, Math.floor(frac * buckets.length)));
  };

  const onMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (buckets.length === 0) return;
    const i = indexAt(e.clientX);
    setDrag({ start: i, end: i });
  };
  const onMouseMoveSvg = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!drag) return;
    setDrag((d) => (d ? { ...d, end: indexAt(e.clientX) } : d));
  };
  const endDrag = () => {
    setDrag((d) => {
      if (d) {
        const lo = Math.min(d.start, d.end);
        const hi = Math.max(d.start, d.end);
        const since = buckets[lo]?.start;
        const untilBucket = buckets[hi];
        if (since && untilBucket) {
          const until = new Date(new Date(untilBucket.start).getTime() + bucketSeconds * 1000).toISOString();
          onRangeSelect(since, until);
        }
      }
      return null;
    });
  };

  const showTooltip = (e: React.MouseEvent, bucket: TimelineBucket) => {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect) return;
    setHover({ x: e.clientX - rect.left, y: e.clientY - rect.top, bucket });
  };

  if (buckets.length === 0) {
    return null; // nothing meaningful to draw yet
  }

  return (
    <div className="timeline-wrap" ref={wrapRef}>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        preserveAspectRatio="none"
        className="timeline-svg"
        role="img"
        aria-label={`traffic histogram, ${buckets.length} buckets of ${bucketSeconds}s — drag to select a time range`}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMoveSvg}
        onMouseUp={endDrag}
        onMouseLeave={() => {
          endDrag();
          setHover(null);
        }}
      >
        {buckets.map((b, i) => {
          const success = Math.max(0, b.entries - b.errors - b.warnings);
          const successH = success * scale;
          const warnH = b.warnings * scale;
          const errH = b.errors * scale;
          const x = i * barW;
          const w = Math.max(0, barW - BAR_GAP);
          return (
            <g
              key={b.start}
              onMouseEnter={(e) => showTooltip(e, b)}
              onMouseMove={(e) => showTooltip(e, b)}
            >
              {/* Invisible full-height hit target so hovering the gap above short bars still shows the tooltip. */}
              <rect x={x} y={0} width={w} height={VB_H} fill="transparent" />
              <rect x={x} y={VB_H - successH - warnH - errH} width={w} height={successH} fill="var(--ok)" />
              <rect x={x} y={VB_H - warnH - errH} width={w} height={warnH} fill="var(--warn)" />
              <rect x={x} y={VB_H - errH} width={w} height={errH} fill="var(--err)" />
            </g>
          );
        })}
        {drag && (
          <rect
            x={Math.min(drag.start, drag.end) * barW}
            y={0}
            width={(Math.abs(drag.end - drag.start) + 1) * barW}
            height={VB_H}
            className="timeline-brush"
          />
        )}
      </svg>

      {hover && (
        <div className="timeline-tooltip" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          <div className="tt-title">{new Date(hover.bucket.start).toLocaleTimeString([], { hour12: false })}</div>
          <div className="tt-row">
            <span>entries</span>
            <b>{hover.bucket.entries}</b>
          </div>
          <div className="tt-row">
            <span>errors</span>
            <b>{hover.bucket.errors}</b>
          </div>
          <div className="tt-row">
            <span>warnings</span>
            <b>{hover.bucket.warnings}</b>
          </div>
        </div>
      )}
    </div>
  );
});
