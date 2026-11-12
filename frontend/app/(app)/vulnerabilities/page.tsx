"use client";

import { useState } from "react";
import { DataTable } from "@/components/data-table";
import Link from "next/link";
import { Badge, Dialog, KeyValue, PageHeader, StatusBadge, Tabs } from "@/components/ui";
import { useGet } from "@/lib/hooks";
import { AssessmentsPanel } from "@/features/assessments";
import { FindingsTable } from "@/features/findings-table";
import { formatDate } from "@/lib/format";
import type { Obj } from "@/types/api";

export default function VulnerabilitiesPage() {
  const [tab, setTab] = useState<"catalogue" | "findings" | "assessments">("catalogue");
  const [selected, setSelected] = useState<Obj | null>(null);
  const { data: detail } = useGet<Obj>(selected ? `/intel/vulnerabilities/${selected.id}` : null);
  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="Known vulnerabilities (CVE, GHSA, OSV) affecting your assets, enriched with CVSS, EPSS and CISA KEV. Severity, exploit likelihood and known exploitation are kept as separate inputs to risk."
      />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "catalogue", label: "Affecting your assets" }, { id: "findings", label: "Vulnerability findings" }, { id: "assessments", label: "Scans and imports" }]} />
      {tab === "catalogue" && (
        <DataTable<Obj>
          path="/intel/vulnerabilities"
          urlState
          searchable
          searchPlaceholder="Search CVE or title"
          toggles={[{ key: "kev", label: "Known exploited only" }]}
          empty={{ title: "No vulnerabilities affect inventoried assets", body: "Import scanner results or an SBOM, or run a vulnerability scan." }}
          columns={[
            { key: "external_id", header: "ID", render: (v) => <button className="font-mono text-xs font-medium text-accent hover:underline" onClick={() => setSelected(v)}>{v.external_id}</button> },
            { key: "title", header: "Title", className: "max-w-sm", render: (v) => <span className="block truncate">{v.title || "—"}</span> },
            { key: "cvss_score", header: "CVSS", render: (v) => <span className="tabular">{v.cvss_score ?? "—"}</span> },
            { key: "epss_score", header: "EPSS", render: (v) => <span className="tabular">{v.epss_score == null ? "—" : `${(v.epss_score * 100).toFixed(1)}%`}</span> },
            { key: "kev", header: "Exploitation", render: (v) => (v.kev ? <Badge tone="critical">CISA KEV</Badge> : v.exploit_available ? <Badge tone="high">Public exploit</Badge> : <span className="text-xs text-muted">No known</span>) },
            { key: "affected_assets", header: "Affected assets", render: (v) => <span className="tabular">{v.affected_assets}</span> },
            { key: "source", header: "Source", render: (v) => <span className="text-xs text-muted">{v.source}</span> },
          ]}
        />
      )}
      {tab === "findings" && <FindingsTable params={{ domain: ["vulnerability", "supply_chain", "container"] }} />}
      {tab === "assessments" && <AssessmentsPanel module="vulnerabilities" allowImport />}
      <Dialog open={!!selected} onClose={() => setSelected(null)} title={selected?.external_id ?? ""} wide>
        {selected && (
          <div className="space-y-3">
            <p className="text-sm">{selected.description || selected.title || "No description has been synchronised for this identifier yet."}</p>
            <KeyValue items={[
              ["CVSS", selected.cvss_score ? `${selected.cvss_score} (${selected.cvss_vector ?? "no vector"})` : "Not synchronised"],
              ["EPSS", selected.epss_score == null ? "Not synchronised" : `${(selected.epss_score * 100).toFixed(2)}% (percentile ${(selected.epss_percentile * 100).toFixed(1)})`],
              ["CISA KEV", selected.kev ? `Yes, added ${formatDate(selected.kev_date_added)}; due ${formatDate(selected.kev_due_date)}` : "No"],
              ["Weaknesses", selected.cwe_ids?.join(", ") || "—"],
              ["Fixed versions", selected.fixed_versions?.join(", ") || "—"],
              ["Aliases", selected.aliases?.join(", ") || "—"],
              ["Published", formatDate(selected.published_at)],
              ["Catalogue source", selected.source],
            ]} />
            {detail && detail.findings?.length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-muted">Affected assets ({detail.affected_assets})</div>
                <ul className="max-h-48 space-y-1 overflow-y-auto text-xs">
                  {detail.findings.map((f: Obj) => (
                    <li key={f.id} className="flex items-center justify-between gap-2">
                      <Link href={`/findings/${f.id}`} className="truncate hover:underline">{f.asset_name}</Link>
                      <span className="flex items-center gap-1"><StatusBadge value={f.status} /><span className="tabular">{f.risk_score.toFixed(0)}</span></span>
                    </li>))}
                </ul>
              </div>
            )}
            {selected.references?.length > 0 && (
              <ul className="space-y-0.5 text-xs">{selected.references.slice(0, 10).map((r: Obj) => <li key={r.url} className="truncate"><a href={r.url} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">{r.url}</a></li>)}</ul>
            )}
          </div>
        )}
      </Dialog>
    </>
  );
}
