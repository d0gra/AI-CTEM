"use client";

import { useState } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Button, Dialog, JsonBlock, PageHeader, StatusBadge } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { useGet } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export default function AuditPage() {
  const [verifying, setVerifying] = useState(false);
  const { data: chain, error, isFetching } = useGet<Obj>(verifying ? "/audit/verify" : null);
  const [selected, setSelected] = useState<Obj | null>(null);
  return (
    <>
      <PageHeader title="Audit Logs" description="Append-only record of sign-ins, permission denials, configuration changes, assessment authorizations and data access. Events are hash-chained per organization; the application cannot modify or delete them."
                  actions={<Button onClick={() => setVerifying(true)} loading={isFetching}>Verify integrity</Button>} />
      {error && <div className="mb-3"><Alert tone="critical">{errorMessage(error)}</Alert></div>}
      {chain && <div className="mb-3"><Alert tone={chain.valid ? "ok" : "critical"}>{chain.valid ? `Hash chain verified across ${chain.events} events.` : `Integrity check FAILED at sequence ${chain.first_invalid_seq}. The log may have been altered outside the application.`}</Alert></div>}
      <DataTable<Obj>
        urlState
        path="/audit/events" pageSize={50}
        filters={[
          { key: "outcome", label: "Outcome", options: ["success", "failure", "denied"] },
          { key: "action", label: "Action", options: [{ value: "auth.", label: "Authentication" }, { value: "authz.", label: "Authorization denials" }, { value: "assessment.", label: "Assessments" }, { value: "ai_redteam.", label: "AI red team" }, { value: "integration.", label: "Integrations" }, { value: "scope.", label: "Scope" }, { value: "risk.", label: "Risk" }, { value: "finding.", label: "Findings" }, { value: "user.", label: "Users" }, { value: "role.", label: "Roles" }, { value: "evidence.", label: "Evidence access" }, { value: "report.", label: "Reports" }] },
        ]}
        empty={{ title: "No audit events match" }}
        columns={[
          { key: "occurred_at", header: "Time", render: (e) => <span className="whitespace-nowrap text-xs">{formatDate(e.occurred_at, true)}</span> },
          { key: "actor_email", header: "Actor", render: (e) => <span className="text-xs">{e.actor_email ?? "system"}</span> },
          { key: "action", header: "Action", render: (e) => <span className="font-mono text-xs">{e.action}</span> },
          { key: "entity", header: "Entity", render: (e) => <span className="font-mono text-xs text-muted">{e.entity_type ? `${e.entity_type}:${String(e.entity_id).slice(0, 8)}` : "—"}</span> },
          { key: "outcome", header: "Outcome", render: (e) => <StatusBadge value={e.outcome === "success" ? "succeeded" : "failed"} /> },
          { key: "ip_address", header: "IP", render: (e) => <span className="font-mono text-xs">{e.ip_address ?? "—"}</span> },
          { key: "detail", header: "", render: (e) => <Button size="sm" variant="ghost" onClick={() => setSelected(e)}>Details</Button> },
        ]}
      />
      <Dialog open={!!selected} onClose={() => setSelected(null)} title={selected ? `Event #${selected.seq}` : ""} wide>
        {selected && <JsonBlock value={selected} />}
      </Dialog>
    </>
  );
}
