"use client";

import Link from "next/link";
import { DataTable, type Column } from "@/components/data-table";
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui";
import type { Params } from "@/lib/api";
import { formatDate, titleCase } from "@/lib/format";
import type { Finding } from "@/types/api";

export const findingColumns: Column<Finding>[] = [
  {
    key: "title", header: "Finding", sortable: true, className: "max-w-md",
    render: (f) => (
      <div className="min-w-0">
        <Link href={`/findings/${f.id}`} onClick={(e) => e.stopPropagation()} className="block truncate font-medium hover:underline">
          {f.title}
        </Link>
        <div className="truncate text-xs text-muted">
          {f.asset_name} · {titleCase(f.asset_type)}
          {f.vulnerability_external_id && ` · ${f.vulnerability_external_id}`}
        </div>
      </div>
    ),
  },
  {
    key: "risk_score", header: "Risk", sortable: true,
    render: (f) => (
      <div className="flex items-center gap-2">
        <span className="tabular w-8 text-right font-medium">{f.risk_score.toFixed(0)}</span>
        <SeverityBadge value={f.risk_level} />
      </div>
    ),
  },
  { key: "severity", header: "Severity", render: (f) => <SeverityBadge value={f.severity} /> },
  { key: "status", header: "Status", sortable: true, render: (f) => <StatusBadge value={f.status} /> },
  { key: "domain", header: "Domain", render: (f) => <span className="text-xs text-muted">{titleCase(f.domain)}</span> },
  {
    key: "due_at", header: "Due", sortable: true,
    render: (f) => (
      <span className="flex items-center gap-1.5 whitespace-nowrap text-xs">
        {formatDate(f.due_at)}
        {f.overdue && <Badge tone="critical">Overdue</Badge>}
        {f.kev && <Badge tone="critical">KEV</Badge>}
      </span>
    ),
  },
];

export function FindingsTable({ params, pageSize }: { params?: Params; pageSize?: number }) {
  return (
    <DataTable<Finding>
      path="/findings"
      params={params}
      columns={findingColumns}
      pageSize={pageSize}
      searchable
      searchPlaceholder="Search title, asset, rule or CVE"
      defaultSort={{ key: "risk_score", order: "desc" }}
      filters={[
        { key: "risk_level", label: "Risk", options: ["critical", "high", "medium", "low", "info"] },
        { key: "status", label: "Status", options: ["new", "triaged", "assigned", "in_progress", "pending_validation", "remediated", "accepted_risk", "false_positive", "closed"] },
      ]}
      toggles={[
        { key: "open_only", label: "Open only" },
        { key: "overdue", label: "Past SLA" },
        { key: "kev", label: "Known exploited" },
      ]}
      rowHref={(f) => `/findings/${f.id}`}
      empty={{ title: "No findings match", body: "Findings appear here after an assessment runs or scanner results are imported." }}
    />
  );
}
