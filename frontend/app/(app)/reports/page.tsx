"use client";

import { Download } from "lucide-react";
import { type FormEvent } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Button, Card, Field, Input, PageHeader, Select, StatusBadge } from "@/components/ui";
import { downloadUrl, errorMessage } from "@/lib/api";
import { formatBytes, formatDate } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export default function ReportsPage() {
  const { data: me } = useMe();
  const { data: types } = useGet<Obj>("/reports/types");
  const create = useAction<Obj>("POST", "/reports");
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = Object.fromEntries(new FormData(e.currentTarget)) as Obj;
    create.mutate({
      type: form.type, format: form.format, title: form.title || null,
      date_from: form.date_from ? new Date(form.date_from).toISOString() : null,
      date_to: form.date_to ? new Date(`${form.date_to}T23:59:59`).toISOString() : null,
    });
  };
  return (
    <>
      <PageHeader title="Reports" description="Generated from live data by a background worker. Every report states its generation time, scope, methodology and limitations. PDF is a summary view; XLSX, CSV and JSON contain complete data." />
      {can(me, "reports:generate") && (
        <Card title="Generate report" className="mb-4">
          {create.error && <div className="mb-3"><Alert tone="critical">{errorMessage(create.error)}</Alert></div>}
          <form onSubmit={submit} className="grid items-end gap-3 sm:grid-cols-2 lg:grid-cols-6">
            <Field label="Report"><Select name="type" required>{Object.entries((types?.types ?? {}) as Record<string, string>).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</Select></Field>
            <Field label="Format"><Select name="format" defaultValue="pdf">{["pdf", "xlsx", "csv", "json"].map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}</Select></Field>
            <Field label="From (first seen)"><Input type="date" name="date_from" /></Field>
            <Field label="To"><Input type="date" name="date_to" /></Field>
            <Field label="Title (optional)"><Input name="title" maxLength={300} /></Field>
            <Button type="submit" variant="primary" loading={create.isPending}>Generate</Button>
          </form>
        </Card>
      )}
      <DataTable<Obj>
        path="/reports" refetchInterval={4000}
        empty={{ title: "No reports generated" }}
        columns={[
          { key: "title", header: "Report", render: (r) => <span className="font-medium">{r.title}</span> },
          { key: "format", header: "Format", render: (r) => <span className="text-xs uppercase">{r.format}</span> },
          { key: "period", header: "Period", render: (r) => <span className="text-xs">{r.params?.date_from || r.params?.date_to ? `${formatDate(r.params.date_from)} – ${formatDate(r.params.date_to)}` : "All time"}</span> },
          { key: "status", header: "Status", render: (r) => <span className="flex items-center gap-2"><StatusBadge value={r.status} />{r.error && <span className="text-xs text-critical">{r.error}</span>}</span> },
          { key: "generated_at", header: "Generated", render: (r) => <span className="text-xs">{formatDate(r.generated_at, true)}</span> },
          { key: "size_bytes", header: "Size", render: (r) => <span className="tabular text-xs">{formatBytes(r.size_bytes)}</span> },
          { key: "sha256", header: "SHA-256", render: (r) => <span className="font-mono text-xs text-muted" title={r.sha256 ?? ""}>{r.sha256 ? `${r.sha256.slice(0, 12)}…` : "—"}</span> },
          { key: "download", header: "", render: (r) => r.status === "ready" ? <a href={downloadUrl(`/reports/${r.id}/download`)} className="inline-flex items-center gap-1 text-xs text-accent hover:underline"><Download className="h-3.5 w-3.5" /> Download</a> : null },
        ]}
      />
    </>
  );
}
