"use client";

import Link from "next/link";
import { useState } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Button, Card, Field, Input, PageHeader, SeverityBadge, Skeleton, StatusBadge, Tabs } from "@/components/ui";
import { FindingsTable } from "@/features/findings-table";
import { errorMessage } from "@/lib/api";
import { formatDate, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

function PolicyEditor() {
  const { data } = useGet<Obj>("/risk/policy");
  return data ? <PolicyForm initial={data} /> : <Skeleton className="h-40" />;
}

function PolicyForm({ initial }: { initial: Obj }) {
  const { data: me } = useMe();
  const save = useAction<Obj, Obj>("PUT", "/risk/policy");
  const [draft, setDraft] = useState<Obj>(() => structuredClone(initial));
  const editable = can(me, "risk:configure");
  const num = (group: string, key: string, step = 1) => (
    <Field key={`${group}.${key}`} label={titleCase(key)}>
      <Input type="number" step={step} disabled={!editable} value={draft[group][key]} onChange={(e) => setDraft({ ...draft, [group]: { ...draft[group], [key]: Number(e.target.value) } })} />
    </Field>
  );
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {save.error && <div className="lg:col-span-2"><Alert tone="critical">{errorMessage(save.error)}</Alert></div>}
      {save.isSuccess && <div className="lg:col-span-2"><Alert tone="ok">Policy saved as version {save.data?.version}. Open findings are being rescored.</Alert></div>}
      <Card title={`Risk level thresholds (policy version ${draft.version})`}>
        <p className="mb-3 text-xs text-muted">Minimum score for each level. Score = min(100, max(floors, 100 × likelihood × impact + escalators)).</p>
        <div className="grid grid-cols-4 gap-3">{["critical", "high", "medium", "low"].map((k) => num("thresholds", k))}</div>
      </Card>
      <Card title="Remediation SLA (hours)"><div className="grid grid-cols-4 gap-3">{["critical", "high", "medium", "low"].map((k) => num("sla_hours", k))}</div></Card>
      <Card title="Exposure factor (likelihood)"><div className="grid grid-cols-4 gap-3">{["internet", "internal", "private", "unknown"].map((k) => num("exposure_factor", k, 0.05))}</div></Card>
      <Card title="Asset criticality factor (impact)"><div className="grid grid-cols-4 gap-3">{["critical", "high", "medium", "low"].map((k) => num("criticality_factor", k, 0.05))}</div></Card>
      <Card title="Floors and escalators (points)">
        <div className="grid grid-cols-3 gap-3">
          {["kev_internet_floor", "kev_floor", "privileged_identity_points", "ai_autonomy_points", "ai_unapproved_tools_points", "ai_sensitive_data_points", "ai_tenant_isolation_points", "risk_acceptance_max_days"].map((k) => (
            <Field key={k} label={titleCase(k)}><Input type="number" disabled={!editable} value={draft[k]} onChange={(e) => setDraft({ ...draft, [k]: Number(e.target.value) })} /></Field>
          ))}
        </div>
      </Card>
      <Card title="Attack path escalator (points)"><div className="grid grid-cols-3 gap-3">{["verified", "probable", "theoretical"].map((k) => num("attack_path_points", k))}</div></Card>
      {editable && <div className="lg:col-span-2"><Button variant="primary" loading={save.isPending} onClick={() => save.mutate(draft)}>Save and rescore</Button></div>}
    </div>
  );
}

export default function RiskPage() {
  const { data: me } = useMe();
  const [tab, setTab] = useState<"priorities" | "acceptances" | "policy">("priorities");
  const decide = useAction<{ id: string; approve: boolean }, Obj>("POST", (b) => `/risk/acceptances/${b.id}/decision`);
  const revoke = useAction<{ id: string }, Obj>("POST", (b) => `/risk/acceptances/${b.id}/revoke`);
  const approver = can(me, "risk:approve");
  return (
    <>
      <PageHeader title="Risk Management" description="Risk-based prioritisation, risk acceptance with approval and expiry, and the organization's risk policy. Every score has a factor-by-factor explanation on the finding." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "priorities", label: "Priorities" }, { id: "acceptances", label: "Risk acceptances" }, { id: "policy", label: "Risk policy" }]} />
      {(decide.error || revoke.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(decide.error ?? revoke.error)}</Alert></div>}
      {tab === "priorities" && <FindingsTable params={{ open_only: true }} />}
      {tab === "acceptances" && (
        <DataTable<Obj>
          path="/risk/acceptances"
          filters={[{ key: "status", label: "Status", options: ["pending", "approved", "rejected", "expired", "revoked"] }]}
          empty={{ title: "No risk acceptances", body: "Request acceptance from a finding. A different person with approval rights must decide it." }}
          columns={[
            { key: "finding_title", header: "Finding", className: "max-w-sm", render: (a) => <Link href={`/findings/${a.finding_id}`} className="block truncate font-medium hover:underline">{a.finding_title}</Link> },
            { key: "finding_risk_level", header: "Risk", render: (a) => <SeverityBadge value={a.finding_risk_level} /> },
            { key: "reason", header: "Reason", className: "max-w-xs", render: (a) => <span className="block truncate text-xs" title={a.reason}>{a.reason}</span> },
            { key: "status", header: "Status", render: (a) => <StatusBadge value={a.status} /> },
            { key: "expires_at", header: "Expires", render: (a) => <span className="text-xs">{formatDate(a.expires_at)}</span> },
            { key: "actions", header: "", render: (a) => (
              <div className="flex gap-1">
                {approver && a.status === "pending" && a.requested_by_user_id !== me?.id && (<><Button size="sm" onClick={() => decide.mutate({ id: a.id, approve: true })}>Approve</Button><Button size="sm" variant="ghost" onClick={() => decide.mutate({ id: a.id, approve: false })}>Reject</Button></>)}
                {a.status === "pending" && a.requested_by_user_id === me?.id && <span className="text-xs text-muted">Awaiting another approver</span>}
                {approver && a.status === "approved" && <Button size="sm" variant="ghost" onClick={() => revoke.mutate({ id: a.id })}>Revoke</Button>}
              </div>) },
          ]}
        />
      )}
      {tab === "policy" && <PolicyEditor />}
    </>
  );
}
