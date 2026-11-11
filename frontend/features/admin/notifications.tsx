"use client";

import { useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Card, Dialog, EmptyState, Field, Input, Select, Skeleton, StatusBadge } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, titleCase } from "@/lib/format";
import { useAction, useGet } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export function NotificationRules() {
  const { data: rules } = useGet<Obj[]>("/notifications/rules");
  const { data: events } = useGet<Record<string, string>>("/notifications/event-types");
  const { data: integrations } = useGet<Obj[]>("/integrations");
  const create = useAction<Obj>("POST", "/notifications/rules");
  const remove = useAction<{ id: string }, Obj>("DELETE", (b) => `/notifications/rules/${b.id}`);
  const [open, setOpen] = useState(false);
  const [channel, setChannel] = useState("email");
  const targets = (integrations ?? []).filter((i) => i.connector === channel);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    create.mutate({ name: String(form.get("name")), channel, min_severity: String(form.get("min_severity")), event_types: form.getAll("event_types").map(String),
                    email_to: channel === "email" ? String(form.get("email_to")) : null, integration_id: channel === "email" ? null : String(form.get("integration_id")) },
                  { onSuccess: () => setOpen(false) });
  };
  return (
    <div className="space-y-4">
      <Card title="Notification rules" action={<Button size="sm" variant="primary" onClick={() => setOpen(true)}>New rule</Button>}>
        <p className="mb-3 text-xs text-muted">Every event is shown in the in-app inbox. Rules additionally deliver matching events to email, a webhook, Slack or Microsoft Teams. Repeats of the same event for the same item within 24 hours are counted, not re-sent.</p>
        {remove.error && <Alert tone="critical">{errorMessage(remove.error)}</Alert>}
        {!rules ? <Skeleton className="h-16" /> : rules.length === 0 ? <EmptyState title="No delivery rules" /> : (
          <ul className="divide-y divide-border">
            {rules.map((r) => (
              <li key={r.id} className="flex items-start justify-between gap-3 py-2 text-sm">
                <div>
                  <div className="font-medium">{r.name} <Badge>{titleCase(r.channel)}</Badge></div>
                  <div className="text-xs text-muted">
                    {r.event_types.length ? r.event_types.map((e: string) => events?.[e] ?? e).join(", ") : "All events"} · {titleCase(r.min_severity)} and above
                    {r.email_to && ` · ${r.email_to}`}{r.integration_id && ` · ${(integrations ?? []).find((i) => i.id === r.integration_id)?.name ?? "integration"}`}
                  </div>
                </div>
                <Button size="sm" variant="ghost" onClick={() => remove.mutate({ id: r.id })}>Delete</Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Delivery log">
        <DataTable<Obj>
          path="/notifications/deliveries"
          empty={{ title: "Nothing delivered yet" }}
          columns={[
            { key: "attempted_at", header: "Time", render: (d) => <span className="text-xs">{formatDate(d.attempted_at, true)}</span> },
            { key: "rule", header: "Rule", render: (d) => <span className="text-xs">{(rules ?? []).find((r) => r.id === d.rule_id)?.name ?? "Deleted rule"}</span> },
            { key: "status", header: "Result", render: (d) => <StatusBadge value={d.status} /> },
            { key: "error", header: "Error", className: "max-w-md", render: (d) => <span className="block truncate text-xs text-critical" title={d.error ?? ""}>{d.error}</span> },
          ]}
        />
      </Card>
      <Dialog open={open} onClose={() => setOpen(false)} title="New notification rule">
        <form onSubmit={submit} className="space-y-3">
          {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
          <Field label="Name"><Input name="name" required minLength={2} /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Channel">
              <Select value={channel} onChange={(e) => setChannel(e.target.value)}>
                {["email", "webhook", "slack", "teams"].map((c) => <option key={c} value={c}>{c === "teams" ? "Microsoft Teams" : titleCase(c)}</option>)}
              </Select>
            </Field>
            <Field label="Minimum severity">
              <Select name="min_severity" defaultValue="high">{["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}</Select>
            </Field>
          </div>
          {channel === "email" ? (
            <Field label="Send to" hint="Requires SMTP to be configured for the deployment."><Input type="email" name="email_to" required /></Field>
          ) : (
            <Field label="Destination" hint={targets.length ? undefined : `Add a ${titleCase(channel)} integration under Integrations first.`}>
              <Select name="integration_id" required>{targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select>
            </Field>
          )}
          <fieldset className="max-h-52 space-y-1 overflow-y-auto rounded-md border border-border p-2">
            <legend className="px-1 text-xs font-medium text-muted">Events (none selected = all)</legend>
            {Object.entries(events ?? {}).map(([key, label]) => (
              <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" name="event_types" value={key} /> {label}</label>
            ))}
          </fieldset>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Create</Button></div>
        </form>
      </Dialog>
    </div>
  );
}
