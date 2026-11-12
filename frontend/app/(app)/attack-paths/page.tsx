"use client";

import { RefreshCw } from "lucide-react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, PageHeader, SeverityBadge, StatusBadge } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import { can, useAction, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export default function AttackPathsPage() {
  const { data: me } = useMe();
  const compute = useAction<Obj>("POST", "/attack-paths/compute");
  return (
    <>
      <PageHeader
        title="Attack Paths"
        description="Routes from internet-exposed or attacker-writable entry points to critical or sensitive assets. Every step is a recorded relationship; a path is reported only when an open finding gives the attacker a foothold."
        actions={can(me, "attack_paths:compute") && <Button onClick={() => compute.mutate({})} loading={compute.isPending}><RefreshCw className="h-4 w-4" /> Recompute</Button>}
      />
      {compute.error && <div className="mb-3"><Alert tone="critical">{errorMessage(compute.error)}</Alert></div>}
      {compute.isSuccess && <div className="mb-3"><Alert tone="ok">Recomputation queued. Results update when the background job completes.</Alert></div>}
      <DataTable<Obj>
        urlState
        path="/attack-paths"
        refetchInterval={10_000}
        filters={[
          { key: "classification", label: "Evidence", options: ["verified", "probable", "theoretical"] },
          { key: "severity", label: "Severity", options: ["critical", "high", "medium", "low"] },
          { key: "involves_ai", label: "Scope", options: [{ value: "true", label: "Involves AI" }, { value: "false", label: "No AI" }] },
        ]}
        rowHref={(p) => `/attack-paths/${p.id}`}
        empty={{ title: "No attack paths", body: "Paths appear when an exposed asset with an open finding has recorded relationships leading to a critical or sensitive asset." }}
        columns={[
          { key: "title", header: "Path", className: "max-w-lg", render: (p) => <span className="block truncate font-medium">{p.title}</span> },
          { key: "score", header: "Score", render: (p) => <span className="tabular font-medium">{p.score.toFixed(0)}</span> },
          { key: "severity", header: "Severity", render: (p) => <SeverityBadge value={p.severity} /> },
          { key: "classification", header: "Evidence", render: (p) => <StatusBadge value={p.classification} /> },
          { key: "steps", header: "Steps", render: (p) => <span className="tabular">{p.steps}</span> },
          { key: "involves_ai", header: "", render: (p) => (p.involves_ai ? <Badge tone="low">AI</Badge> : null) },
          { key: "last_computed_at", header: "Computed", render: (p) => <span className="text-xs text-muted">{relativeTime(p.last_computed_at)}</span> },
        ]}
      />
    </>
  );
}
