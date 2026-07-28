// @vitest-environment jsdom
//
// Regression coverage for the hidden-tab flush freeze: scheduleFlush() in
// useHub.ts used to coalesce incoming entries purely via requestAnimationFrame.
// Chromium-family browsers fully suspend rAF callbacks for a hidden document
// (not merely throttle them), so once a flush was scheduled while the tab was
// hidden it would never fire — entries piled up in the internal buffer and the
// traffic table froze until (sometimes never, in practice) the tab regained
// visibility. See useHub.ts's scheduleFlush comment for the fix: fall back to
// setTimeout while hidden, and catch up immediately via a visibilitychange
// listener once the tab is visible again.
//
// This test drives useHub with a fully-controlled fake WebSocket and a fake
// requestAnimationFrame that only ever *captures* its callback (it is never
// auto-invoked), which deterministically reproduces "the browser suspended
// rAF because the document is hidden" without relying on real browser timing.
import { act } from "react-dom/test-utils";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushUpdater, useHub, type HubState } from "./useHub";
import type { Entry, Envelope } from "./types";

class FakeWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  readyState = FakeWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;

  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
  }

  send() {}
  close() {
    this.readyState = FakeWebSocket.CLOSED;
  }

  emit(msg: Envelope) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }
}

function fakeEntry(id: string): Entry {
  return {
    id,
    protocol: "http",
    timestamp: new Date().toISOString(),
    elapsedMs: 1,
    node: "n1",
    src: { ip: "10.0.0.1", port: 1234 },
    dst: { ip: "10.0.0.2", port: 80 },
    request: {},
    response: {},
    status: "success",
    statusCode: 200,
  };
}

function setVisibility(state: "visible" | "hidden") {
  Object.defineProperty(document, "visibilityState", {
    value: state,
    configurable: true,
  });
}

describe("useHub background-tab flush", () => {
  let container: HTMLDivElement;
  let root: Root;
  let latest: HubState | null;
  let rafCallbacks: FrameRequestCallback[];
  let rafStub: ReturnType<typeof vi.fn>;
  let cafStub: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    setVisibility("visible");
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);

    rafCallbacks = [];
    rafStub = vi.fn((cb: FrameRequestCallback) => {
      rafCallbacks.push(cb);
      return rafCallbacks.length;
    });
    cafStub = vi.fn();
    vi.stubGlobal("requestAnimationFrame", rafStub);
    vi.stubGlobal("cancelAnimationFrame", cafStub);

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    latest = null;

    function Harness() {
      latest = useHub("");
      return null;
    }
    act(() => {
      root.render(<Harness />);
    });
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("flushes buffered entries via setTimeout while the document is hidden, never touching rAF", () => {
    setVisibility("hidden");
    const ws = FakeWebSocket.instances[0];

    act(() => {
      ws.emit({ type: "entry", entry: fakeEntry("e1") });
      ws.emit({ type: "entry", entry: fakeEntry("e2") });
      ws.emit({ type: "entry", entry: fakeEntry("e3") });
    });

    // Buffered but not yet flushed into React state.
    expect(latest?.entries).toHaveLength(0);
    // Old buggy behavior would have scheduled via requestAnimationFrame here;
    // the fix must not, since a hidden document may suspend it indefinitely.
    expect(rafStub).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(1000);
    });

    expect(latest?.entries.map((e) => e.id)).toEqual(["e3", "e2", "e1"]);
  });

  it("still coalesces via requestAnimationFrame while the document is visible", () => {
    const ws = FakeWebSocket.instances[0];

    act(() => {
      ws.emit({ type: "entry", entry: fakeEntry("e1") });
    });

    expect(rafStub).toHaveBeenCalledTimes(1);
    expect(latest?.entries).toHaveLength(0);

    act(() => {
      rafCallbacks[0](0);
    });

    expect(latest?.entries.map((e) => e.id)).toEqual(["e1"]);
  });

  it("treats an entryBatch frame as its entries in order, through the same buffer path", () => {
    const ws = FakeWebSocket.instances[0];

    act(() => {
      ws.emit({
        type: "entryBatch",
        entries: [fakeEntry("b1"), fakeEntry("b2"), fakeEntry("b3")],
      });
    });

    // Buffered like individual frames, not yet flushed into React state.
    expect(latest?.entries).toHaveLength(0);

    act(() => {
      rafCallbacks[0](0);
    });

    // Newest first after flush, so the batch's oldest ends up last.
    expect(latest?.entries.map((e) => e.id)).toEqual(["b3", "b2", "b1"]);
  });

  it("migrates a rAF flush already pending when the tab goes hidden to the timeout fallback, instead of leaving it stuck", () => {
    const ws = FakeWebSocket.instances[0];

    // Entry arrives while visible -> schedules via rAF, exactly as continuous
    // live traffic would (there's essentially always a flush in flight).
    act(() => {
      ws.emit({ type: "entry", entry: fakeEntry("e1") });
    });
    expect(rafStub).toHaveBeenCalledTimes(1);

    // Tab is backgrounded before that rAF ever fires — the scenario the whole
    // fix exists for. Without migrating the pending rAF, it would simply never
    // run once the document is hidden (rAF is suspended, not just throttled),
    // and entries would pile up in bufRef forever.
    setVisibility("hidden");
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });

    // The stale rAF was cancelled and replaced by a timeout fallback.
    expect(cafStub).toHaveBeenCalledTimes(1);
    expect(rafStub).toHaveBeenCalledTimes(1); // no second rAF scheduled

    act(() => {
      vi.advanceTimersByTime(1000);
    });

    expect(latest?.entries.map((e) => e.id)).toEqual(["e1"]);
  });

  it("catches up immediately on visibilitychange instead of waiting out the background timer", () => {
    setVisibility("hidden");
    const ws = FakeWebSocket.instances[0];

    act(() => {
      ws.emit({ type: "entry", entry: fakeEntry("e1") });
    });
    expect(latest?.entries).toHaveLength(0);
    expect(rafStub).not.toHaveBeenCalled();

    // Tab is foregrounded again before the hidden-mode timeout has fired.
    setVisibility("visible");
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });

    // The pending background timeout was cancelled and replaced by rAF.
    expect(rafStub).toHaveBeenCalledTimes(1);

    act(() => {
      rafCallbacks[0](0);
    });
    expect(latest?.entries.map((e) => e.id)).toEqual(["e1"]);
  });
});

// Regression coverage for the flush updater's purity. The buffered batch used
// to be reversed *inside* the setEntries updater (`buf.reverse().concat(prev)`),
// which mutates buf in place. React treats an updater as a pure function of
// `prev` and is free to invoke it more than once for a single update — which is
// exactly what <StrictMode> (main.tsx wraps the whole app in it) does in
// development — so the second invocation un-reversed the batch and committed a
// whole frame's worth of entries oldest-first.
//
// Driven against flushUpdater directly rather than through <StrictMode>: which
// updates React chooses to replay is a version- and scheduling-dependent
// implementation detail, so a StrictMode render is not a test that reliably
// fails when the mutation comes back. Calling the updater twice is.
describe("useHub flush updater", () => {
  it("yields the same newest-first order however many times it is invoked", () => {
    // flush() hands the updater a batch that is already newest-first.
    const batch = [fakeEntry("s3"), fakeEntry("s2"), fakeEntry("s1")];
    const update = flushUpdater(batch, 100);

    const first = update([]);
    const second = update([]);

    expect(first.map((e) => e.id)).toEqual(["s3", "s2", "s1"]);
    expect(second.map((e) => e.id)).toEqual(["s3", "s2", "s1"]);
    // ...and the batch itself is untouched, so a third caller sees it intact.
    expect(batch.map((e) => e.id)).toEqual(["s3", "s2", "s1"]);
  });

  it("prepends to the existing buffer and trims to the cap, newest kept", () => {
    const update = flushUpdater([fakeEntry("new2"), fakeEntry("new1")], 3);
    const next = update([fakeEntry("old1"), fakeEntry("old2"), fakeEntry("old3")]);
    expect(next.map((e) => e.id)).toEqual(["new2", "new1", "old1"]);
  });
});
