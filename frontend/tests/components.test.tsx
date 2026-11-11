import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { DataTable } from "@/components/data-table";
import { Dialog, SeverityBadge, StatusBadge } from "@/components/ui";

const push = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/",
  useParams: () => ({}),
}));

function wrap(ui: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

interface Row { id: string; name: string; risk: number }
const columns = [
  { key: "name", header: "Name", sortable: true },
  { key: "risk", header: "Risk", sortable: true, render: (r: Row) => <b>{r.risk}</b> },
];

function pageOf(total: number, page: number, size: number) {
  const items = Array.from({ length: Math.min(size, total - (page - 1) * size) }, (_, i) => ({ id: `r${(page - 1) * size + i}`, name: `Asset ${(page - 1) * size + i}`, risk: 90 - i }));
  return new Response(JSON.stringify({ items, total, page, page_size: size }), { status: 200 });
}

describe("DataTable", () => {
  it("requests pages, sorting, search and filters from the server", async () => {
    const fetchMock = vi.fn((url: string) => {
      const params = new URL(url, "http://x").searchParams;
      return Promise.resolve(pageOf(60, Number(params.get("page")), Number(params.get("page_size"))));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    wrap(<DataTable<Row> path="/assets" columns={columns} searchable defaultSort={{ key: "risk", order: "desc" }} filters={[{ key: "exposure", label: "Exposure", options: ["internet", "internal"] }]} rowHref={(r) => `/assets/${r.id}`} />);

    expect(await screen.findByText("Asset 0")).toBeInTheDocument();
    expect(screen.getByText("1–25 of 60")).toBeInTheDocument();
    expect(fetchMock.mock.calls[0][0]).toContain("sort=risk&order=desc");
    expect(screen.getByRole("columnheader", { name: /Risk/ })).toHaveAttribute("aria-sort", "descending");

    await user.click(screen.getByRole("button", { name: "Next page" }));
    expect(await screen.findByText("Asset 25")).toBeInTheDocument();
    expect(screen.getByText("Page 2 of 3")).toBeInTheDocument();

    await user.click(within(screen.getByRole("columnheader", { name: /Name/ })).getByRole("button"));
    await waitFor(() => expect(fetchMock.mock.lastCall?.[0]).toMatch(/page=1.*sort=name/));

    await user.selectOptions(screen.getByLabelText("Exposure"), "internet");
    await waitFor(() => expect(fetchMock.mock.lastCall?.[0]).toContain("exposure=internet"));

    await user.type(screen.getByLabelText("Search"), "portal");
    await waitFor(() => expect(fetchMock.mock.lastCall?.[0]).toContain("q=portal"), { timeout: 1500 });

    await user.click((await screen.findAllByRole("row"))[1]);
    expect(push).toHaveBeenCalledWith(expect.stringMatching(/^\/assets\/r\d+$/));
  });

  it("shows an empty state when the server returns no rows", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(pageOf(0, 1, 25))));
    wrap(<DataTable<Row> path="/assets" columns={columns} empty={{ title: "No assets match", body: "Run a discovery." }} />);
    expect(await screen.findByText("No assets match")).toBeInTheDocument();
    expect(screen.getByText("Run a discovery.")).toBeInTheDocument();
  });

  it("shows the server's error message with a retry action instead of an empty table", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "forbidden", message: "You do not have permission to perform this action" } }), { status: 403 }))
      .mockResolvedValueOnce(pageOf(1, 1, 25));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    wrap(<DataTable<Row> path="/assets" columns={columns} />);
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("You do not have permission to perform this action")).toBeInTheDocument();
    expect(screen.queryByText("Nothing to show")).not.toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Asset 0")).toBeInTheDocument();
  });
});

describe("UI primitives", () => {
  it("renders severity and status labels in readable form", () => {
    render(<><SeverityBadge value="critical" /><StatusBadge value="pending_validation" /><StatusBadge value={null} /></>);
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("Pending validation")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("dialog renders content only while open and closes from its button", async () => {
    const onClose = vi.fn();
    const { rerender } = render(<Dialog open={false} onClose={onClose} title="Add asset">body</Dialog>);
    expect(screen.queryByText("body")).not.toBeInTheDocument();
    rerender(<Dialog open onClose={onClose} title="Add asset">body</Dialog>);
    expect(screen.getByText("body")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalled();
  });
});
