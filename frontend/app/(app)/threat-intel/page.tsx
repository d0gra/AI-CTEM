"use client";

import { useState } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Card, EmptyState, PageHeader, Skeleton, Tabs } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export default function ThreatIntelPage() {
  const { data: me } = useMe();
  const { data: sources } = useGet<Obj[]>("/intel/sources", undefined, { refetchInterval: 8000 });
  const { data: exposure } = useGet<Obj[]>("/intel/technique-exposure");
  const sync = useAction<{ source: string }, Obj>("POST", (b) => `/intel/sync?source=${b.source}`);
  const [tab, setTab] = useState<"sources" | "exposure" | "items">("sources");
  return (
    <>
      <PageHeader title="Threat Intelligence" description="Vulnerability and adversary-technique intelligence from public sources, stored with source attribution and timestamps and correlated with your assets, findings and attack paths. Nothing is synthesised." />
      {sync.error && <div className="mb-3"><Alert tone="critical">{errorMessage(sync.error)}</Alert></div>}
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "sources", label: "Sources" }, { id: "exposure", label: "Technique exposure", count: exposure?.length }, { id: "items", label: "Catalogue" }]} />
      {tab === "sources" && (
        <Card>
          {!sources ? <Skeleton className="h-24" /> : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted"><tr><th className="py-1 font-medium">Source</th><th className="font-medium">Last successful sync</th><th className="font-medium">Records</th><th className="font-medium">State</th><th /></tr></thead>
              <tbody>{sources.map((s) => (
                <tr key={s.source} className="border-t border-border">
                  <td className="py-2 font-medium">{titleCase(s.source)}</td>
                  <td className="text-xs">{s.last_success_at ? `${formatDate(s.last_success_at, true)} (${relativeTime(s.last_success_at)})` : "Never"}</td>
                  <td className="tabular text-xs">{s.records || s.intel_items || 0}</td>
                  <td className="max-w-xs text-xs">{s.last_error ? <span className="text-critical">{s.last_error}</span> : s.last_success_at ? <Badge tone="ok">OK</Badge> : <Badge>Not synchronised</Badge>}</td>
                  <td className="text-right">{s.syncable ? can(me, "intel:sync") && <Button size="sm" loading={sync.isPending && sync.variables?.source === s.source} onClick={() => sync.mutate({ source: s.source })}>Sync now</Button> : <span className="text-xs text-muted">Queried on demand</span>}</td>
                </tr>))}</tbody>
            </table>
          )}
          <p className="mt-3 text-xs text-muted">KEV and EPSS are refreshed daily by workers. EPSS and NVD enrich only vulnerabilities present in your catalogue. A failed sync is recorded here, never hidden.</p>
        </Card>
      )}
      {tab === "exposure" && (
        <Card title="Techniques present in your environment">
          {!exposure?.length ? <EmptyState title="No technique exposure">Techniques appear when attack paths exist or AI findings are mapped to MITRE ATLAS.</EmptyState> : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted"><tr><th className="py-1 font-medium">Technique</th><th className="font-medium">Name</th><th className="font-medium">Attack paths</th><th className="font-medium">Findings</th></tr></thead>
              <tbody>{exposure.map((t) => (
                <tr key={t.technique} className="border-t border-border">
                  <td className="py-1.5 font-mono text-xs">{t.url ? <a className="text-accent hover:underline" href={t.url} target="_blank" rel="noreferrer noopener">{t.technique}</a> : t.technique}</td>
                  <td className="text-xs">{t.name ?? <span className="text-muted">Synchronise ATT&amp;CK / ATLAS to resolve names</span>}</td>
                  <td className="tabular">{t.attack_paths}</td><td className="tabular">{t.findings}</td>
                </tr>))}</tbody>
            </table>
          )}
        </Card>
      )}
      {tab === "items" && (
        <DataTable<Obj>
          path="/intel/items" searchable searchPlaceholder="Search identifier or title"
          filters={[{ key: "source", label: "Source", options: ["cisa_kev", "mitre_attack", "mitre_atlas"] }, { key: "kind", label: "Kind", options: ["exploited_vulnerability", "technique", "tactic", "mitigation", "case_study"] }]}
          empty={{ title: "Catalogue is empty", body: "Synchronise a source to populate it." }}
          columns={[
            { key: "external_id", header: "ID", render: (i) => <a className="font-mono text-xs text-accent hover:underline" href={i.source_url} target="_blank" rel="noreferrer noopener">{i.external_id}</a> },
            { key: "title", header: "Title", className: "max-w-md", render: (i) => <span className="block truncate">{i.title}</span> },
            { key: "kind", header: "Kind", render: (i) => <Badge>{titleCase(i.kind)}</Badge> },
            { key: "source", header: "Source", render: (i) => <span className="text-xs">{titleCase(i.source)}</span> },
            { key: "published_at", header: "Published", render: (i) => <span className="text-xs">{formatDate(i.published_at)}</span> },
            { key: "fetched_at", header: "Fetched", render: (i) => <span className="text-xs text-muted">{relativeTime(i.fetched_at)}</span> },
          ]}
        />
      )}
    </>
  );
}
