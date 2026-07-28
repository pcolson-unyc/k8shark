import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FilterBar } from "./FilterBar";
import type { Entry } from "../types";

const baseProps = {
  value: "",
  onApply: vi.fn(),
  paused: false,
  pausedCount: 0,
  onTogglePause: vi.fn(),
  onClear: vi.fn(),
  view: "list" as const,
  onViewChange: vi.fn(),
  count: 0,
  truncated: false,
  filterError: null,
  entries: [] as Entry[],
  historicalRange: null,
  onReturnToLive: vi.fn(),
};

beforeEach(() => {
  vi.clearAllMocks();
  // recent-filter history (UI-6) persists across mounts via localStorage;
  // clear it so tests don't leak into each other.
  localStorage.clear();
  // useFields() hits GET /api/fields on mount; stub it out so tests don't
  // depend on (or wait on) a real network call.
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({ fields: [] }) }))
  );
});

describe("FilterBar", () => {
  it("submits the trimmed draft on Apply", async () => {
    const user = userEvent.setup();
    const onApply = vi.fn();
    render(<FilterBar {...baseProps} onApply={onApply} />);

    await user.type(screen.getByRole("combobox", { name: /ifl filter/i }), '  protocol == "http"  ');
    await user.click(screen.getByRole("button", { name: /apply/i }));

    expect(onApply).toHaveBeenCalledWith('protocol == "http"');
  });

  it("submits on Enter even when the value just typed still matches a suggestion", async () => {
    // Regression test: right after typing a value's closing quote, the caret
    // is still inside the "value" token, so the autocomplete re-offers
    // tracked values matching what's already been typed — trivially
    // including the exact value itself. That leaves the dropdown open with
    // an (unnavigated) item any time the typed value happens to prefix-match
    // a known one. Enter used to always intercept that case (silently
    // picking item 0) instead of submitting, so applying a filter by typing
    // it and pressing Enter — the obvious way to do it — could silently do
    // nothing.
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              fields: [{ name: "protocol", type: "enum", operators: ["==", "!="], values: [{ value: "http", count: 10 }] }],
            }),
        })
      )
    );
    const user = userEvent.setup();
    const onApply = vi.fn();
    render(<FilterBar {...baseProps} onApply={onApply} />);

    const input = screen.getByRole("combobox", { name: /ifl filter/i });
    await user.type(input, 'protocol == "http"');
    expect(screen.getByRole("listbox")).toBeInTheDocument(); // dropdown is open, unnavigated
    expect(screen.getByRole("option")).toHaveTextContent("http");

    await user.keyboard("{Enter}");

    expect(onApply).toHaveBeenCalledWith('protocol == "http"');
  });

  it("applies an example chip verbatim", async () => {
    const user = userEvent.setup();
    const onApply = vi.fn();
    render(<FilterBar {...baseProps} onApply={onApply} />);

    await user.click(screen.getByRole("button", { name: 'response.status >= 500' }));
    expect(onApply).toHaveBeenCalledWith("response.status >= 500");
  });

  it("offers a previously applied filter in the recent-history dropdown, and applies it on click", async () => {
    const user = userEvent.setup();
    const onApply = vi.fn();
    render(<FilterBar {...baseProps} onApply={onApply} />);

    await user.click(screen.getByRole("button", { name: 'dst.namespace == "shop"' }));
    onApply.mockClear();

    // value stays "" in this isolated test (nothing re-flows the applied
    // filter back down as the parent normally would), so the input is still
    // empty -- focusing it should now offer the just-used filter as history.
    await user.click(screen.getByRole("combobox", { name: /ifl filter/i }));
    const option = await screen.findByRole("option", { name: 'dst.namespace == "shop"' });

    await user.click(option);
    expect(onApply).toHaveBeenCalledWith('dst.namespace == "shop"');
  });

  it("deduplicates repeated filters in the recent history instead of listing them twice", async () => {
    const user = userEvent.setup();
    render(<FilterBar {...baseProps} />);

    const chip = screen.getByRole("button", { name: 'response.status >= 500' });
    await user.click(chip);
    await user.click(chip);

    await user.click(screen.getByRole("combobox", { name: /ifl filter/i }));
    expect(await screen.findAllByRole("option", { name: "response.status >= 500" })).toHaveLength(1);
  });

  it("shows Resume with the paused count once paused, and Pause otherwise", () => {
    const { rerender } = render(<FilterBar {...baseProps} paused={false} />);
    expect(screen.getByRole("button", { name: /pause/i })).toBeInTheDocument();

    rerender(<FilterBar {...baseProps} paused pausedCount={7} />);
    expect(screen.getByRole("button", { name: /resume \(7 new\)/i })).toBeInTheDocument();
  });

  it("calls onTogglePause / onClear from their buttons", async () => {
    const user = userEvent.setup();
    const onTogglePause = vi.fn();
    const onClear = vi.fn();
    render(<FilterBar {...baseProps} onTogglePause={onTogglePause} onClear={onClear} />);

    await user.click(screen.getByRole("button", { name: /pause/i }));
    expect(onTogglePause).toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: /clear/i }));
    expect(onClear).toHaveBeenCalled();
  });

  it("switches view via the List/Map toggle", async () => {
    const user = userEvent.setup();
    const onViewChange = vi.fn();
    render(<FilterBar {...baseProps} onViewChange={onViewChange} />);

    await user.click(screen.getByRole("button", { name: "Map" }));
    expect(onViewChange).toHaveBeenCalledWith("map");
  });

  it("renders the filter error banner when set, as an aria-live alert", () => {
    render(<FilterBar {...baseProps} filterError='unexpected token "("' />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent('unexpected token "("');
  });

  it("shows the truncation note alongside the shown count", () => {
    render(<FilterBar {...baseProps} count={2000} truncated />);
    expect(screen.getByText(/2000 shown/)).toHaveTextContent(/showing latest 2000/);
  });

  it("disables export with no entries, and triggers a download once there are some", async () => {
    const user = userEvent.setup();
    const createObjectURL = vi.fn(() => "blob:mock");
    vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL: vi.fn() });
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    const { rerender } = render(<FilterBar {...baseProps} entries={[]} />);
    expect(screen.getByRole("button", { name: /export/i })).toBeDisabled();

    const sample: Entry[] = [
      {
        id: "e1",
        protocol: "http",
        timestamp: "2026-01-01T00:00:00.000Z",
        elapsedMs: 5,
        node: "n",
        src: { ip: "10.0.0.1", port: 1 },
        dst: { ip: "10.0.0.2", port: 2 },
        request: { summary: "GET /" },
        response: {},
        status: "success",
        statusCode: 200,
      },
    ];
    rerender(<FilterBar {...baseProps} entries={sample} count={1} />);
    const exportBtn = screen.getByRole("button", { name: /export/i });
    expect(exportBtn).toBeEnabled();

    await user.click(exportBtn);
    await user.click(screen.getByRole("button", { name: /as json/i }));

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(clickSpy).toHaveBeenCalledTimes(1);
  });

  // PCAP export is the one export that does not come from the in-page buffer:
  // the hub synthesizes the same file from its whole ring buffer, so the
  // download isn't capped at whatever MAX_ENTRIES this tab happens to hold.
  describe("PCAP export", () => {
    const sample: Entry[] = [
      {
        id: "e1",
        protocol: "http",
        timestamp: "2026-01-01T00:00:00.000Z",
        elapsedMs: 5,
        node: "n",
        src: { ip: "10.0.0.1", port: 1 },
        dst: { ip: "10.0.0.2", port: 2 },
        request: { summary: "GET /" },
        response: {},
        status: "success",
        statusCode: 200,
      },
    ];

    function stubDownload() {
      const createObjectURL = vi.fn(() => "blob:mock");
      vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL: vi.fn() });
      const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
      return { createObjectURL, clickSpy };
    }

    // Also stubs GET /api/fields, which useFields() hits on mount.
    function stubFetch(pcapResponse: Partial<Response>) {
      const fetchMock = vi.fn((url: string) =>
        url.startsWith("/api/pcap")
          ? Promise.resolve(pcapResponse)
          : Promise.resolve({ ok: true, json: () => Promise.resolve({ fields: [] }) })
      );
      vi.stubGlobal("fetch", fetchMock);
      return fetchMock;
    }

    it("downloads what the hub serves, scoped to the active filter", async () => {
      const user = userEvent.setup();
      const fetchMock = stubFetch({ ok: true, blob: () => Promise.resolve(new Blob([new Uint8Array([0xd4, 0xc3])])) });
      const { createObjectURL } = stubDownload();

      render(<FilterBar {...baseProps} entries={sample} count={1} value='protocol == "http"' />);
      await user.click(screen.getByRole("button", { name: /export/i }));
      await user.click(screen.getByRole("button", { name: /as pcap/i }));

      await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
      expect(fetchMock).toHaveBeenCalledWith("/api/pcap?filter=protocol+%3D%3D+%22http%22");
    });

    it("passes the brushed window through when viewing a historical range", async () => {
      const user = userEvent.setup();
      const fetchMock = stubFetch({ ok: true, blob: () => Promise.resolve(new Blob()) });
      const { createObjectURL } = stubDownload();
      const historicalRange = { since: "2026-01-01T12:00:00.000Z", until: "2026-01-01T12:05:00.000Z" };

      render(<FilterBar {...baseProps} entries={sample} count={1} historicalRange={historicalRange} />);
      await user.click(screen.getByRole("button", { name: /export/i }));
      await user.click(screen.getByRole("button", { name: /as pcap/i }));

      await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/pcap?since=2026-01-01T12%3A00%3A00.000Z&until=2026-01-01T12%3A05%3A00.000Z"
      );
    });

    it("falls back to synthesizing locally when the hub has no /api/pcap (older hub)", async () => {
      const user = userEvent.setup();
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const fetchMock = stubFetch({ ok: false, status: 404 });
      const { createObjectURL, clickSpy } = stubDownload();

      render(<FilterBar {...baseProps} entries={sample} count={1} />);
      await user.click(screen.getByRole("button", { name: /export/i }));
      await user.click(screen.getByRole("button", { name: /as pcap/i }));

      await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
      expect(fetchMock).toHaveBeenCalledWith("/api/pcap");
      expect(clickSpy).toHaveBeenCalledTimes(1); // the file was still produced
      warn.mockRestore();
    });
  });

  it("shows a back-to-live button instead of Pause while viewing a historical range", async () => {
    const user = userEvent.setup();
    const onReturnToLive = vi.fn();
    render(
      <FilterBar
        {...baseProps}
        historicalRange={{ since: "2026-01-01T12:00:00.000Z", until: "2026-01-01T12:05:00.000Z" }}
        onReturnToLive={onReturnToLive}
      />
    );

    expect(screen.queryByRole("button", { name: /pause/i })).not.toBeInTheDocument();
    const backBtn = screen.getByRole("button", { name: /back to live/i });
    await user.click(backBtn);
    expect(onReturnToLive).toHaveBeenCalledTimes(1);
  });
});
