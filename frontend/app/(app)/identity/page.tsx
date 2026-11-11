"use client";

import Link from "next/link";
import { DataTable } from "@/components/data-table";
import { Badge, PageHeader, StatusBadge } from "@/components/ui";
import { FindingsTable } from "@/features/findings-table";
import { relativeTime } from "@/lib/format";
import type { Asset } from "@/types/api";

export default function IdentityPage() {
  return (
    <>
      <PageHeader
        title="Identity Security"
        description="Human, service and workload identities discovered from cloud connectors, with the permissions and trust relationships that feed attack path analysis. Identity findings are produced by the cloud posture assessments."
      />
      <div className="space-y-4">
        <DataTable<Asset>
          path="/assets"
          params={{ type: "identity" }}
          searchable
          searchPlaceholder="Search identities"
          defaultSort={{ key: "risk_score", order: "desc" }}
          rowHref={(a) => `/assets/${a.id}`}
          empty={{ title: "No identities inventoried", body: <>Connect a cloud account under <Link href="/integrations" className="text-accent hover:underline">Integrations</Link> and run the cloud posture assessment.</> }}
          columns={[
            { key: "name", header: "Identity", sortable: true, render: (a) => <div><div className="font-medium">{a.name}</div><div className="max-w-md truncate font-mono text-xs text-muted">{a.identifier}</div></div> },
            { key: "risk_score", header: "Risk", sortable: true, render: (a) => <span className="tabular">{a.risk_score.toFixed(0)}</span> },
            { key: "open_findings", header: "Open findings", render: (a) => <span className="tabular">{a.open_findings}</span> },
            { key: "exposure", header: "Exposure", render: (a) => <StatusBadge value={a.exposure} /> },
            { key: "owner", header: "Owner", render: (a) => (a.owner_user_id || a.owner_team_id ? <Badge tone="ok">Assigned</Badge> : <Badge tone="medium">Unowned</Badge>) },
            { key: "last_seen_at", header: "Last seen", sortable: true, render: (a) => relativeTime(a.last_seen_at) },
          ]}
        />
        <FindingsTable params={{ domain: ["identity"] }} />
      </div>
    </>
  );
}
