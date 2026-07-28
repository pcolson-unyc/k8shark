import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ServiceMap } from "./ServiceMap";
import type { Entry } from "../types";

function entry(overrides: Partial<Entry> & { id: string }): Entry {
  return {
    protocol: "http",
    timestamp: "2026-01-01T00:00:00.000Z",
    elapsedMs: 10,
    node: "node-1",
    src: { ip: "10.0.0.1", port: 1234, name: "frontend", namespace: "shop" },
    dst: { ip: "10.0.0.2", port: 80, name: "backend", namespace: "shop" },
    request: { summary: "GET /" },
    response: {},
    status: "success",
    statusCode: 200,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ServiceMap", () => {
  it("shows a placeholder when there's no traffic yet", () => {
    render(<ServiceMap entries={[]} />);
    expect(screen.getByText(/no traffic yet/i)).toBeInTheDocument();
  });

  it("renders a node per distinct service and a legend entry per namespace", () => {
    render(<ServiceMap entries={[entry({ id: "a" })]} />);
    expect(screen.getByText("frontend.shop")).toBeInTheDocument();
    expect(screen.getByText("backend.shop")).toBeInTheDocument();
    expect(screen.getByText("shop")).toBeInTheDocument(); // legend
  });

  it("calls onNodeClick with a name-based filter clause on click", async () => {
    const user = userEvent.setup();
    const onNodeClick = vi.fn();
    render(<ServiceMap entries={[entry({ id: "a" })]} onNodeClick={onNodeClick} />);

    await user.click(screen.getByRole("button", { name: /frontend\.shop/i }));
    expect(onNodeClick).toHaveBeenCalledWith('dst.name == "frontend" or src.name == "frontend"');
  });

  it("falls back to an ip-based clause when the node has no resolved name", async () => {
    const user = userEvent.setup();
    const onNodeClick = vi.fn();
    const noName = entry({ id: "a", src: { ip: "10.0.9.9", port: 1 } });
    render(<ServiceMap entries={[noName]} onNodeClick={onNodeClick} />);

    await user.click(screen.getByRole("button", { name: /10\.0\.9\.9/i }));
    expect(onNodeClick).toHaveBeenCalledWith('dst.ip == "10.0.9.9" or src.ip == "10.0.9.9"');
  });

  it("activates a node with the keyboard (Enter), same as a click", async () => {
    const user = userEvent.setup();
    const onNodeClick = vi.fn();
    render(<ServiceMap entries={[entry({ id: "a" })]} onNodeClick={onNodeClick} />);

    screen.getByRole("button", { name: /frontend\.shop/i }).focus();
    await user.keyboard("{Enter}");
    expect(onNodeClick).toHaveBeenCalledWith('dst.name == "frontend" or src.name == "frontend"');
  });

  it("renders a self-loop count instead of dropping a service's calls to itself", () => {
    const selfCall = entry({
      id: "a",
      src: { ip: "10.0.0.1", port: 1, name: "cache", namespace: "shop" },
      dst: { ip: "10.0.0.1", port: 1, name: "cache", namespace: "shop" },
    });
    render(<ServiceMap entries={[selfCall]} />);
    expect(screen.getByText("×1")).toBeInTheDocument();
  });

  // The graph is deliberately no longer keyed on the `entries` array identity
  // (useHub hands down a brand-new array every animation frame); it rebuilds
  // from a ref on a slow tick instead. That's invisible in normal use but very
  // visible if it breaks — the map would silently freeze on its first frame —
  // so pin both halves: no rebuild on identity alone, a rebuild on the tick.
  it("re-aggregates newly arrived entries on the rebuild tick", () => {
    vi.useFakeTimers();
    try {
      const first = [entry({ id: "a" })];
      const { rerender } = render(<ServiceMap entries={first} />);
      expect(screen.getByText("frontend.shop")).toBeInTheDocument();
      expect(screen.queryByText("cache.shop")).not.toBeInTheDocument();

      const withCache = [
        entry({ id: "b", src: { ip: "10.0.0.9", port: 5, name: "cache", namespace: "shop" } }),
        ...first,
      ];
      rerender(<ServiceMap entries={withCache} />);

      act(() => {
        vi.advanceTimersByTime(600);
      });
      expect(screen.getByText("cache.shop")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  // Edge aggregation moved from a single map keyed on a `${from}→${to}` string
  // to a nested from→to→edge map. Same grouping, no string keys — these pin the
  // grouping so a mis-nested lookup can't silently split or merge edges.
  it("aggregates repeated calls between the same pair into a single edge", () => {
    render(<ServiceMap entries={[entry({ id: "a" }), entry({ id: "b" }), entry({ id: "c" })]} />);
    expect(screen.getByText(/2 services · 1 links/)).toBeInTheDocument();
  });

  it("keeps each direction between a pair as its own edge", () => {
    const forward = entry({ id: "a" });
    const back = entry({ id: "b", src: forward.dst, dst: forward.src });
    render(<ServiceMap entries={[forward, back]} />);
    expect(screen.getByText(/2 services · 2 links/)).toBeInTheDocument();
  });

  it("counts every call of a self-loop into one edge", () => {
    const self = { ip: "10.0.0.1", port: 1, name: "cache", namespace: "shop" };
    const selfCall = (id: string) => entry({ id, src: self, dst: self });
    render(<ServiceMap entries={[selfCall("a"), selfCall("b"), selfCall("c")]} />);
    expect(screen.getByText("×3")).toBeInTheDocument();
  });

  it("switches the entry window via the toolbar buttons", async () => {
    const user = userEvent.setup();
    render(<ServiceMap entries={[entry({ id: "a" })]} />);
    const btn800 = screen.getByRole("button", { name: "800" });
    expect(btn800).toHaveClass("active");
    await user.click(screen.getByRole("button", { name: "200" }));
    expect(screen.getByRole("button", { name: "200" })).toHaveClass("active");
    expect(btn800).not.toHaveClass("active");
  });
});
