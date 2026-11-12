import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { DataTable } from "@/components/data-table";
import { describeRule, RuleBuilder } from "@/features/rule-builder";

const replace = vi.fn();
let search = new URLSearchParams();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace }),
  useSearchParams: () => search,
  usePathname: () => "/findings",
  useParams: () => ({}),
}));

function wrap(ui: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("policy rules", () => {
  it("describes rules in plain language", () => {
    expect(describeRule({})).toBe("everything");
    expect(describeRule({ all: [{ field: "type", op: "in", value: ["rag_application", "vector_database"] }, { field: "ai.auth_required", op: "is_true" }] }))
      .toBe("type is one of rag_application, vector_database and ai.auth_required is yes");
    expect(describeRule({ not: { field: "exposure", op: "eq", value: "internet" } })).toBe("not (exposure equals internet)");
  });

  it("builds a combined rule from rows", async () => {
    const onChange = vi.fn();
    render(<RuleBuilder initial={{ field: "exposure", op: "eq", value: "internet" }} fields={["exposure", "risk_score"]} operators={["eq", "gte", "is_true"]} emptyLabel="none" onChange={onChange} />);
    await userEvent.click(screen.getByRole("button", { name: /add condition/i }));
    const fields = screen.getAllByLabelText("Field");
    fireEvent.change(fields[1], { target: { value: "risk_score" } });
    fireEvent.change(screen.getAllByLabelText("Operator")[1], { target: { value: "gte" } });
    fireEvent.change(screen.getAllByLabelText("Value")[1], { target: { value: "70" } });
    expect(onChange).toHaveBeenLastCalledWith({ all: [{ field: "exposure", op: "eq", value: "internet" }, { field: "risk_score", op: "gte", value: 70 }] });
  });

  it("falls back to JSON for nested rules", () => {
    render(<RuleBuilder initial={{ not: { field: "exposure", op: "eq", value: "internet" } }} fields={[]} operators={[]} emptyLabel="none" onChange={vi.fn()} />);
    expect(screen.getByRole("textbox")).toHaveValue(JSON.stringify({ not: { field: "exposure", op: "eq", value: "internet" } }, null, 2));
  });
});

describe("table state in the address bar", () => {
  it("reads filters and deep-link parameters from the URL and writes changes back", async () => {
    search = new URLSearchParams("source=import:trivy&status=new&tab=x");
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 25 }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    wrap(<DataTable path="/findings" urlState passthrough={[{ key: "source", label: "Source" }]}
                    filters={[{ key: "status", label: "Status", options: ["new", "closed"] }]} columns={[{ key: "title", header: "Title" }]} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const url = String((fetchMock.mock.calls[0] as unknown[])[0]);
    expect(url).toContain("source=import%3Atrivy");
    expect(url).toContain("status=new");
    expect(url).not.toContain("tab=");
    expect(screen.getByText("import:trivy")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "closed" } });
    expect(replace).toHaveBeenLastCalledWith(expect.stringContaining("status=closed"), { scroll: false });
    vi.unstubAllGlobals();
  });
});

describe("labels", async () => {
  const { titleCase } = await import("@/lib/format");
  it("keeps acronyms readable", () => {
    expect(titleCase("llm_endpoint")).toBe("LLM endpoint");
    expect(titleCase("ai_application")).toBe("AI application");
    expect(titleCase("rag_application")).toBe("RAG application");
    expect(titleCase("pending_validation")).toBe("Pending validation");
    expect(titleCase(null)).toBe("—");
  });
});
