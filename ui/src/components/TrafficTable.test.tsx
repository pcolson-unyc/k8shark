import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TrafficTable } from "./TrafficTable";
import type { Entry } from "../types";

function entry(overrides: Partial<Entry> & { id: string }): Entry {
  return {
    protocol: "http",
    timestamp: "2026-01-01T00:00:00.000Z",
    elapsedMs: 10,
    node: "node-1",
    src: { ip: "10.0.0.1", port: 1234, name: "frontend" },
    dst: { ip: "10.0.0.2", port: 80, name: "backend" },
    request: { summary: "GET /" },
    response: {},
    status: "success",
    statusCode: 200,
    ...overrides,
  };
}

const baseProps = {
  selectedId: null,
  onSelect: vi.fn(),
  onLoadOlder: vi.fn(),
  loadingOlder: false,
  noMoreHistory: false,
  pinnedIds: new Set<string>(),
  onTogglePin: vi.fn(),
  onCompare: vi.fn(),
};

beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});

describe("TrafficTable", () => {
  it("shows the empty state when there are no entries", () => {
    render(<TrafficTable {...baseProps} entries={[]} />);
    expect(screen.getByText(/waiting for traffic/i)).toBeInTheDocument();
  });

  it("renders a row per entry and calls onSelect on click", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const entries = [entry({ id: "a", request: { summary: "GET /a" } }), entry({ id: "b", request: { summary: "GET /b" } })];
    render(<TrafficTable {...baseProps} entries={entries} onSelect={onSelect} />);

    expect(screen.getByText("GET /a")).toBeInTheDocument();
    expect(screen.getByText("GET /b")).toBeInTheDocument();

    await user.click(screen.getByText("GET /a"));
    expect(onSelect).toHaveBeenCalledWith(entries[0]);
  });

  it("sorts by latency ascending, then descending, then resets on a third click", async () => {
    const user = userEvent.setup();
    const entries = [
      entry({ id: "slow", elapsedMs: 300, request: { summary: "slow" } }),
      entry({ id: "fast", elapsedMs: 10, request: { summary: "fast" } }),
      entry({ id: "mid", elapsedMs: 100, request: { summary: "mid" } }),
    ];
    render(<TrafficTable {...baseProps} entries={entries} />);

    const summaries = () => Array.from(document.querySelectorAll("td.col-summary")).map((td) => td.textContent);

    const latencyHeader = screen.getByText("latency");
    await user.click(latencyHeader);
    expect(summaries()).toEqual(["fast", "mid", "slow"]);

    await user.click(latencyHeader);
    expect(summaries()).toEqual(["slow", "mid", "fast"]);

    await user.click(latencyHeader);
    // Reset to arrival order (the order passed in via `entries`).
    expect(summaries()).toEqual(["slow", "fast", "mid"]);
  });

  it("toggles optional columns via the column picker and persists the choice", async () => {
    const user = userEvent.setup();
    render(<TrafficTable {...baseProps} entries={[entry({ id: "a" })]} />);

    expect(screen.queryByRole("columnheader", { name: "node" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /columns/i }));
    await user.click(screen.getByRole("checkbox", { name: "node" }));
    expect(screen.getByRole("columnheader", { name: "node" })).toBeInTheDocument();

    const stored = JSON.parse(localStorage.getItem("k8shark.columns") || "[]");
    expect(stored).toContain("node");
  });

  it("shows a compare trigger once two entries are pinned, and it fires onCompare", async () => {
    const user = userEvent.setup();
    const onCompare = vi.fn();
    const entries = [entry({ id: "a" }), entry({ id: "b" })];
    render(<TrafficTable {...baseProps} entries={entries} pinnedIds={new Set(["a", "b"])} onCompare={onCompare} />);

    const trigger = screen.getByRole("button", { name: /compare pinned \(2\)/i });
    expect(trigger).toBeEnabled();
    await user.click(trigger);
    expect(onCompare).toHaveBeenCalled();
  });

  it("disables the compare trigger with only one entry pinned", () => {
    const entries = [entry({ id: "a" }), entry({ id: "b" })];
    render(<TrafficTable {...baseProps} entries={entries} pinnedIds={new Set(["a"])} />);
    expect(screen.getByRole("button", { name: /pinned 1\/2/i })).toBeDisabled();
  });

  describe("ArrowUp/ArrowDown row navigation", () => {
    const entries = [
      entry({ id: "a", request: { summary: "GET /a" } }),
      entry({ id: "b", request: { summary: "GET /b" } }),
      entry({ id: "c", request: { summary: "GET /c" } }),
    ];

    it("selects the first entry on ArrowDown when nothing is selected", async () => {
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(<TrafficTable {...baseProps} entries={entries} selectedId={null} onSelect={onSelect} />);
      await user.keyboard("{ArrowDown}");
      expect(onSelect).toHaveBeenCalledWith(entries[0]);
    });

    it("moves to the next entry on ArrowDown", async () => {
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(<TrafficTable {...baseProps} entries={entries} selectedId="b" onSelect={onSelect} />);
      await user.keyboard("{ArrowDown}");
      expect(onSelect).toHaveBeenLastCalledWith(entries[2]);
    });

    it("moves to the previous entry on ArrowUp", async () => {
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(<TrafficTable {...baseProps} entries={entries} selectedId="b" onSelect={onSelect} />);
      await user.keyboard("{ArrowUp}");
      expect(onSelect).toHaveBeenLastCalledWith(entries[0]);
    });

    it("does not call onSelect past the last entry", async () => {
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(<TrafficTable {...baseProps} entries={entries} selectedId="c" onSelect={onSelect} />);
      await user.keyboard("{ArrowDown}");
      expect(onSelect).not.toHaveBeenCalled();
    });

    it("does not call onSelect before the first entry", async () => {
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(<TrafficTable {...baseProps} entries={entries} selectedId="a" onSelect={onSelect} />);
      await user.keyboard("{ArrowUp}");
      expect(onSelect).not.toHaveBeenCalled();
    });

    const bySpeed = [
      entry({ id: "slow", elapsedMs: 300, request: { summary: "slow" } }),
      entry({ id: "fast", elapsedMs: 10, request: { summary: "fast" } }),
      entry({ id: "mid", elapsedMs: 100, request: { summary: "mid" } }),
    ];

    it("with nothing selected, ArrowDown jumps to the first entry in sorted order", async () => {
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(<TrafficTable {...baseProps} entries={bySpeed} selectedId={null} onSelect={onSelect} />);
      await user.click(screen.getByText("latency")); // sorts ascending: fast, mid, slow
      await user.keyboard("{ArrowDown}");
      expect(onSelect).toHaveBeenLastCalledWith(bySpeed[1]); // "fast" is fastest/first
    });

    it("moves according to the active sort order, not arrival order", async () => {
      // bySpeed's arrival order is [slow, fast, mid]; sorted ascending by
      // latency it's [fast, mid, slow] — "slow" is first on arrival but last
      // once sorted, so its neighbors differ between the two orderings.
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(<TrafficTable {...baseProps} entries={bySpeed} selectedId="slow" onSelect={onSelect} />);
      await user.click(screen.getByText("latency")); // sorts ascending: fast, mid, slow

      await user.keyboard("{ArrowDown}"); // "slow" is last in sorted order -> clamped, no-op
      expect(onSelect).not.toHaveBeenCalled();

      await user.keyboard("{ArrowUp}"); // previous-in-sorted-order is "mid", not arrival's "fast"
      expect(onSelect).toHaveBeenLastCalledWith(bySpeed[2]);
    });

    it("ignores arrow keys while typing in an input", async () => {
      const user = userEvent.setup();
      const onSelect = vi.fn();
      render(
        <>
          <input aria-label="some other input" />
          <TrafficTable {...baseProps} entries={entries} selectedId={null} onSelect={onSelect} />
        </>
      );
      await user.click(screen.getByLabelText("some other input"));
      await user.keyboard("{ArrowDown}");
      expect(onSelect).not.toHaveBeenCalled();
    });
  });

  // ROW_HEIGHT isn't exported; 29 mirrors the private const in TrafficTable.tsx.
  const ROW_HEIGHT = 29;

  describe("scroll anchoring on new (prepended) entries", () => {
    it("compensates scrollTop and shows a pill when scrolled away from the top", () => {
      const initial = [entry({ id: "b" }), entry({ id: "c" }), entry({ id: "d" })];
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);

      const scrollEl = document.querySelector(".table-wrap") as HTMLDivElement;
      scrollEl.scrollTop = 100; // user has scrolled down, away from the live edge

      // Live flush prepends one new entry ahead of the previous top ("b").
      const withNew = [entry({ id: "a" }), ...initial];
      rerender(<TrafficTable {...baseProps} entries={withNew} />);

      expect(scrollEl.scrollTop).toBe(100 + ROW_HEIGHT);
      expect(screen.getByText("↑ 1 new entry")).toBeInTheDocument();
    });

    it("does not compensate or show a pill when already at the top (following live)", () => {
      const initial = [entry({ id: "b" }), entry({ id: "c" })];
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);

      const scrollEl = document.querySelector(".table-wrap") as HTMLDivElement;
      scrollEl.scrollTop = 0;

      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "a" }), ...initial]} />);

      expect(scrollEl.scrollTop).toBe(0);
      expect(screen.queryByText(/new entr/)).not.toBeInTheDocument();
    });

    it("accumulates the count across multiple prepends and clicking the pill scrolls to top", async () => {
      const user = userEvent.setup();
      const initial = [entry({ id: "c" }), entry({ id: "d" })];
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);
      const scrollEl = document.querySelector(".table-wrap") as HTMLDivElement;
      scrollEl.scrollTop = 50;

      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "b" }), ...initial]} />);
      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "a" }), entry({ id: "b" }), ...initial]} />);

      expect(screen.getByText("↑ 2 new entries")).toBeInTheDocument();

      await user.click(screen.getByText("↑ 2 new entries"));
      expect(scrollEl.scrollTop).toBe(0);
      expect(screen.queryByText(/new entr/)).not.toBeInTheDocument();
    });

    it("does not show the pill while a column sort is active", () => {
      const initial = [entry({ id: "b" }), entry({ id: "c" })];
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);
      const scrollEl = document.querySelector(".table-wrap") as HTMLDivElement;

      // Sort by latency so displayEntries no longer just mirrors arrival order.
      const latencyHeader = screen.getByText("latency");
      latencyHeader.click();
      scrollEl.scrollTop = 100;

      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "a" }), ...initial]} />);

      expect(screen.queryByText(/new entr/)).not.toBeInTheDocument();
    });

    it("counts only the actual scroll delta when clamped at the bottom, not the raw prepended count", () => {
      const initial = [entry({ id: "b" }), entry({ id: "c" }), entry({ id: "d" })];
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);
      const scrollEl = document.querySelector(".table-wrap") as HTMLDivElement;

      // jsdom's scrollTop is a plain unclamped number; simulate what a real
      // browser does once the buffer is at its cap and the total scroll
      // height stops growing — writing past the max silently clamps back to
      // it instead of taking the write, which is how a user pinned at the
      // live edge of a full, churning buffer actually behaves.
      const MAX = 100;
      let actual = MAX;
      Object.defineProperty(scrollEl, "scrollTop", {
        get: () => actual,
        set: (v: number) => {
          actual = Math.min(v, MAX);
        },
        configurable: true,
      });

      // One prepend while already pinned at MAX — the compensating write has
      // nowhere to go, so nothing actually moved.
      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "a" }), ...initial]} />);

      expect(scrollEl.scrollTop).toBe(MAX);
      expect(screen.queryByText(/new entr/)).not.toBeInTheDocument();
    });

    it("resets the pill count when the user manually scrolls back to the top", () => {
      const initial = [entry({ id: "b" }), entry({ id: "c" })];
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);
      const scrollEl = document.querySelector(".table-wrap") as HTMLDivElement;
      scrollEl.scrollTop = 100;

      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "a" }), ...initial]} />);
      expect(screen.getByText("↑ 1 new entry")).toBeInTheDocument();

      scrollEl.scrollTop = 0;
      fireEvent.scroll(scrollEl);
      expect(screen.queryByText(/new entr/)).not.toBeInTheDocument();
    });

    // Regression: Clear (or a filter change / range load) resets `entries`
    // to [] without touching scroll position. Left scrolled deep into the
    // old list, the viewport pointed at an offset the emptied/rebuilding
    // list had no content for — read by the user as old rows lingering or
    // new ones landing "in the middle" instead of at the top.
    it("resets scrollTop when entries is wiped wholesale (Clear / filter change)", () => {
      const initial = [entry({ id: "b" }), entry({ id: "c" }), entry({ id: "d" })];
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);
      const scrollEl = document.querySelector(".table-wrap") as HTMLDivElement;
      scrollEl.scrollTop = 5000; // scrolled well away from the top

      rerender(<TrafficTable {...baseProps} entries={[]} />);
      expect(scrollEl.scrollTop).toBe(0);

      // New traffic then streams back in from a clean baseline: no leftover
      // "new entries" pill implying there's old content above to catch up to.
      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "e" })]} />);
      expect(screen.queryByText(/new entr/)).not.toBeInTheDocument();
    });
  });

  // UI-8: with a column sort active, the old code copied and re-sorted the
  // whole buffer on every rAF flush. The fix freezes the stream while sorting
  // (snapshot sorted once) so live arrivals don't re-trigger the sort — proven
  // here by asserting the displayed order stays put as new entries stream in.
  describe("sort freeze under live streaming (UI-8)", () => {
    const summaries = () => Array.from(document.querySelectorAll("td.col-summary")).map((td) => td.textContent);
    const bySpeed = () => [
      entry({ id: "slow", elapsedMs: 300, request: { summary: "slow" } }),
      entry({ id: "fast", elapsedMs: 10, request: { summary: "fast" } }),
      entry({ id: "mid", elapsedMs: 100, request: { summary: "mid" } }),
    ];

    it("keeps the sorted order stable across a re-render that does not change entries", async () => {
      const user = userEvent.setup();
      const entries = bySpeed();
      const { rerender } = render(<TrafficTable {...baseProps} entries={entries} />);

      await user.click(screen.getByText("latency"));
      expect(summaries()).toEqual(["fast", "mid", "slow"]);

      // A re-render driven by an unrelated prop (same entries identity) must not
      // reorder — the sort is memoized, not recomputed on every render.
      rerender(<TrafficTable {...baseProps} entries={entries} loadingOlder={true} />);
      expect(summaries()).toEqual(["fast", "mid", "slow"]);
    });

    it("freezes the sorted view when new entries stream in, and shows a frozen banner", async () => {
      const user = userEvent.setup();
      const initial = bySpeed();
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);

      await user.click(screen.getByText("latency")); // asc: fast, mid, slow
      expect(summaries()).toEqual(["fast", "mid", "slow"]);

      // Live flush prepends a brand-new fastest entry. Frozen while sorting, the
      // displayed order must NOT change (no re-sort) and the banner counts it.
      const withNew = [entry({ id: "zippy", elapsedMs: 1, request: { summary: "zippy" } }), ...initial];
      rerender(<TrafficTable {...baseProps} entries={withNew} />);

      expect(summaries()).toEqual(["fast", "mid", "slow"]); // unchanged — frozen
      expect(screen.getByRole("button", { name: /stream frozen/i })).toHaveTextContent(/1 new/);
    });

    it("syncing the frozen snapshot pulls in and re-sorts the new entries", async () => {
      const user = userEvent.setup();
      const initial = bySpeed();
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);

      await user.click(screen.getByText("latency"));
      const withNew = [entry({ id: "zippy", elapsedMs: 1, request: { summary: "zippy" } }), ...initial];
      rerender(<TrafficTable {...baseProps} entries={withNew} />);
      expect(summaries()).toEqual(["fast", "mid", "slow"]); // still frozen

      await user.click(screen.getByRole("button", { name: /stream frozen/i }));
      expect(summaries()).toEqual(["zippy", "fast", "mid", "slow"]); // merged + re-sorted asc
    });

    it("clearing the sort resumes the live order including entries that arrived while frozen", async () => {
      const user = userEvent.setup();
      const initial = bySpeed();
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);

      const latencyHeader = screen.getByText("latency");
      await user.click(latencyHeader); // asc
      const withNew = [entry({ id: "zippy", elapsedMs: 1, request: { summary: "zippy" } }), ...initial];
      rerender(<TrafficTable {...baseProps} entries={withNew} />);

      await user.click(latencyHeader); // desc
      await user.click(latencyHeader); // reset — unfreeze
      // Back to arrival order of the *current* live buffer, banner gone.
      expect(summaries()).toEqual(["zippy", "slow", "fast", "mid"]);
      expect(screen.queryByRole("button", { name: /stream frozen/i })).not.toBeInTheDocument();
    });

    // Regression: Clear (or a filter change) wipes `entries` wholesale, but a
    // frozen sort's displayed rows come from frozenBase, not entries — so the
    // wipe went unnoticed and pre-Clear rows kept showing under a permanently
    // stale "stream frozen" banner. Especially visible with capture paused,
    // since nothing ever arrives afterward to reveal the staleness via a
    // rising "N new" count.
    it("drops the sort (and its frozen snapshot) when entries is wiped wholesale, instead of showing stale rows forever", async () => {
      const user = userEvent.setup();
      const initial = bySpeed();
      const { rerender } = render(<TrafficTable {...baseProps} entries={initial} />);

      await user.click(screen.getByText("latency")); // asc: fast, mid, slow
      expect(summaries()).toEqual(["fast", "mid", "slow"]);

      rerender(<TrafficTable {...baseProps} entries={[]} />);
      expect(summaries()).toEqual([]);
      expect(screen.getByText(/Waiting for traffic/)).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /stream frozen/i })).not.toBeInTheDocument();

      // Normal live behavior resumes for whatever streams in next.
      rerender(<TrafficTable {...baseProps} entries={[entry({ id: "fresh" })]} />);
      expect(summaries()).toEqual(["GET /"]);
    });
  });

  // Loosely covers the App-side selectedLive fix (UI-8): the table must stay
  // correct with a large buffer. App.tsx's O(1) Map lookup isn't reachable from
  // this component test file, but selection-by-id at scale is.
  it("selects the right row by id in a large entries buffer", () => {
    const big = Array.from({ length: 5000 }, (_, i) => entry({ id: `e${i}`, request: { summary: `sum-${i}` } }));
    render(<TrafficTable {...baseProps} entries={big} selectedId="e0" />);
    const selected = document.querySelector("tr.row.sel");
    expect(selected).not.toBeNull();
    expect(selected).toHaveTextContent("sum-0");
  });
});
