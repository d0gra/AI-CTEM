"use client";

import Link from "next/link";
import { useState } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Dialog, Field, PageHeader, Select, SeverityBadge, Stat, StatusBadge, Tabs } from "@/components/ui";
import { FindingsTable } from "@/features/findings-table";
import { errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";
import { TaskDialog } from "@/features/remediation";

export default function RemediationPage() {
  const { data: me } = useMe();
  const { data: overview } = useGet<Obj>("/dashboard/overview");
  const { data: integrations } = useGet<Obj[]>(can(me, "integrations:read") ? "/integrations" : null);
  const update = useAction<{ id: string; status: string }, Obj>("PATCH", (b) => `/remediation/tasks/${b.id}`);
  const ticket = useAction<{ id: string; integration_id: string; confirm: boolean }, Obj>("POST", (b) => `/remediation/tasks/${b.id}/ticket`);
  const [tab, setTab] = useState<"tasks" | "validation" | "overdue">("tasks");
  const [ticketing, setTicketing] = useState<Obj | null>(null);
  const [target, setTarget] = useState("");
  const [editing, setEditing] = useState<Obj | null>(null);
  const { data: directory } = useGet<Obj>("/admin/directory");
  const person = (t: Obj) => directory?.users.find((u: Obj) => u.id === t.assignee_user_id)?.full_name;
  const team = (t: Obj) => directory?.teams.find((x: Obj) => x.id === t.team_id)?.name;
  const writable = can(me, "remediation:write");
  const systems = (integrations ?? []).filter((i) => ["github_issues", "gitlab_issues", "jira"].includes(i.connector) && i.enabled);
  const r = overview?.remediation;
  return (
    <>
      <PageHeader title="Remediation" description="Assignment, due dates and verification. A task is completed only when its finding is verified as remediated by a retest or a recorded manual verification." />
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Open tasks" value={r?.open_tasks ?? "—"} />
        <Stat label="Awaiting retest" value={r?.pending_validation ?? "—"} />
        <Stat label="Findings past SLA" value={r?.overdue_slas ?? "—"} tone={r?.overdue_slas ? "critical" : "ok"} />
        <Stat label="Unassigned critical/high" value={r?.unassigned_high_risk ?? "—"} tone={r?.unassigned_high_risk ? "high" : undefined} />
      </div>
      {(update.error || ticket.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(update.error ?? ticket.error)}</Alert></div>}
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "tasks", label: "Tasks" }, { id: "validation", label: "Awaiting retest", count: r?.pending_validation }, { id: "overdue", label: "Past SLA", count: r?.overdue_slas }]} />
      {tab === "tasks" && (
        <DataTable<Obj>
          path="/remediation/tasks"
          urlState
          filters={[
            { key: "status", label: "Status", options: ["open", "in_progress", "pending_validation", "done", "cancelled"] },
            ...(directory ? [{ key: "assignee_user_id", label: "Assignee", options: directory.users.map((u: Obj) => ({ value: u.id, label: u.full_name })) }] : []),
          ]}
          toggles={[{ key: "overdue", label: "Overdue" }, { key: "mine", label: "Assigned to me" }]}
          empty={{ title: "No remediation tasks", body: "Create a task from a finding to assign and track its fix." }}
          columns={[
            { key: "title", header: "Task", className: "max-w-sm", render: (t) => <div className="min-w-0"><Link href={`/findings/${t.finding_id}`} className="block truncate font-medium hover:underline">{t.title}</Link><div className="text-xs text-muted">Finding is {t.finding_status?.replace(/_/g, " ")}</div></div> },
            { key: "priority", header: "Priority", render: (t) => <SeverityBadge value={t.priority} /> },
            { key: "status", header: "Status", render: (t) => <StatusBadge value={t.status} /> },
            { key: "assignee", header: "Assigned to", render: (t) => person(t) || team(t)
                ? <span className="text-xs">{person(t) ?? "—"}{team(t) && <span className="text-muted"> · {team(t)}</span>}</span>
                : <Badge tone="medium">Unassigned</Badge> },
            { key: "due_at", header: "Due", render: (t) => <span className="flex items-center gap-1.5 text-xs">{formatDate(t.due_at)}{t.overdue && <Badge tone="critical">Overdue</Badge>}</span> },
            { key: "ticket", header: "Ticket", render: (t) => t.ticket_url ? <a href={t.ticket_url} target="_blank" rel="noreferrer noopener" className="text-xs text-accent hover:underline">{t.ticket_key}</a> : writable && systems.length > 0 && !["done", "cancelled"].includes(t.status) ? <Button size="sm" variant="ghost" onClick={() => { setTicketing(t); setTarget(systems[0].id); }}>Create</Button> : <span className="text-xs text-muted">—</span> },
            { key: "actions", header: "", render: (t) => writable && (
              <div className="flex gap-1">
                {t.status === "open" && <Button size="sm" onClick={() => update.mutate({ id: t.id, status: "in_progress" })}>Start</Button>}
                {t.status === "in_progress" && <Button size="sm" onClick={() => update.mutate({ id: t.id, status: "pending_validation" })}>Fix applied</Button>}
                {t.status === "pending_validation" && <Link href={`/findings/${t.finding_id}`} className="text-xs text-accent hover:underline">Retest finding</Link>}
                {!["done", "cancelled"].includes(t.status) && <Button size="sm" variant="ghost" onClick={() => setEditing(t)}>Edit</Button>}
              </div>) },
          ]}
        />
      )}
      {tab === "validation" && <FindingsTable params={{ status: "pending_validation" }} />}
      {tab === "overdue" && <FindingsTable params={{ overdue: true }} />}
      {editing && <TaskDialog task={editing} onClose={() => setEditing(null)} />}
      <Dialog open={!!ticketing} onClose={() => setTicketing(null)} title="Create external ticket">
        <div className="space-y-3">
          <Alert tone="medium">This creates an issue in an external system using the stored integration credentials. The ticket includes the finding title, description and remediation guidance.</Alert>
          <Field label="Ticketing system"><Select value={target} onChange={(e) => setTarget(e.target.value)}>{systems.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</Select></Field>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setTicketing(null)}>Cancel</Button>
            <Button variant="primary" loading={ticket.isPending} onClick={() => ticketing && ticket.mutate({ id: ticketing.id, integration_id: target, confirm: true }, { onSettled: () => setTicketing(null) })}>Create ticket</Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
