"use client";

import { useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, EmptyState, ErrorState, Field, Input, JsonBlock, PageHeader, Select, SeverityBadge, Skeleton, Stat, StatusBadge, Textarea } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

function Detail({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: me } = useMe();
  const { data } = useGet<Obj>(`/policies/${id}`);
  const evaluate = useAction<Obj, Obj>("POST", `/policies/${id}/evaluate`);
  const requestException = useAction<Obj>("POST", `/policies/${id}/exceptions`);
  const decide = useAction<{ id: string; approve: boolean }, Obj>("POST", (b) => `/policies/exceptions/${b.id}/decision`);
  const [exceptionFor, setExceptionFor] = useState<Obj | null>(null);
  return (
    <Dialog open onClose={onClose} title={data?.name ?? "Policy"} wide>
      {!data ? <Skeleton className="h-32" /> : (
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p>{data.description}</p>
            <Button size="sm" loading={evaluate.isPending} onClick={() => evaluate.mutate({})}>Evaluate now</Button>
          </div>
          {(evaluate.error || requestException.error || decide.error) && <Alert tone="critical">{errorMessage(evaluate.error ?? requestException.error ?? decide.error)}</Alert>}
          <div className="grid gap-3 md:grid-cols-2">
            <div><div className="mb-1 text-xs font-medium text-muted">Applies to ({data.entity_type}s matching)</div><JsonBlock value={data.scope} /></div>
            <div><div className="mb-1 text-xs font-medium text-muted">Must satisfy</div><JsonBlock value={data.condition} /></div>
          </div>
          {data.framework_refs.length > 0 && <p className="text-xs text-muted">Framework references: {data.framework_refs.join("; ")}</p>}
          <div>
            <div className="mb-1 text-xs font-medium text-muted">Violations in latest evaluation ({data.latest_evaluation?.failed ?? 0})</div>
            {!data.latest_evaluation ? <p className="text-xs text-muted">Not evaluated yet.</p> : data.latest_evaluation.violations.length === 0 ? <p className="text-xs text-muted">None.</p> : (
              <ul className="max-h-60 space-y-1 overflow-y-auto text-xs">
                {data.latest_evaluation.violations.map((v: Obj) => (
                  <li key={v.entity_id} className="flex items-start justify-between gap-2 rounded border border-border p-2">
                    <span><span className="font-medium">{v.label}</span> <span className="font-mono text-muted">{JSON.stringify(v.observed)}</span></span>
                    {can(me, "risk:request") && <Button size="sm" variant="ghost" onClick={() => setExceptionFor(v)}>Request exception</Button>}
                  </li>))}
              </ul>
            )}
          </div>
          <div>
            <div className="mb-1 text-xs font-medium text-muted">Evaluation history</div>
            <ul className="text-xs">{data.history.slice(0, 8).map((h: Obj) => <li key={h.id}>{formatDate(h.evaluated_at, true)}: <StatusBadge value={h.status} /> {h.passed}/{h.total} passed, {h.exempt} exempt</li>)}</ul>
          </div>
          <div>
            <div className="mb-1 text-xs font-medium text-muted">Exceptions</div>
            {data.exceptions.length === 0 ? <p className="text-xs text-muted">None.</p> : (
              <ul className="space-y-1 text-xs">
                {data.exceptions.map((x: Obj) => (
                  <li key={x.id} className="flex items-start justify-between gap-2 rounded border border-border p-2">
                    <span><StatusBadge value={x.status} /> {x.reason} <span className="text-muted">· until {formatDate(x.expires_at)}</span></span>
                    {x.status === "pending" && can(me, "risk:approve") && x.requested_by_user_id !== me?.id && (
                      <span className="flex gap-1"><Button size="sm" onClick={() => decide.mutate({ id: x.id, approve: true })}>Approve</Button><Button size="sm" variant="ghost" onClick={() => decide.mutate({ id: x.id, approve: false })}>Reject</Button></span>)}
                  </li>))}
              </ul>
            )}
          </div>
          {exceptionFor && (
            <form className="space-y-2 rounded-md border border-border p-3" onSubmit={(e) => {
              e.preventDefault();
              const form = new FormData(e.currentTarget);
              requestException.mutate({ entity_id: exceptionFor.entity_id, reason: String(form.get("reason")), expires_at: new Date(`${form.get("expires_at")}T23:59:59`).toISOString() },
                                      { onSuccess: () => setExceptionFor(null) });
            }}>
              <div className="text-xs font-medium">Exception for {exceptionFor.label}</div>
              <Textarea name="reason" required minLength={20} placeholder="Why this item cannot meet the policy, and what reduces the risk (at least 20 characters)" />
              <div className="flex items-end gap-2">
                <Field label="Expires"><Input type="date" name="expires_at" required /></Field>
                <Button type="submit" size="sm" variant="primary" loading={requestException.isPending}>Submit for approval</Button>
                <Button type="button" size="sm" variant="ghost" onClick={() => setExceptionFor(null)}>Cancel</Button>
              </div>
            </form>
          )}
        </div>
      )}
    </Dialog>
  );
}

export default function PoliciesPage() {
  const { data: me } = useMe();
  const { data, error, isLoading, refetch } = useGet<Obj>("/policies", undefined, { refetchInterval: 8000 });
  const evaluateAll = useAction<Obj>("POST", "/policies/evaluate");
  const toggle = useAction<{ id: string; enabled: boolean }, Obj>("PATCH", (b) => `/policies/${b.id}`);
  const create = useAction<Obj>("POST", "/policies");
  const [detail, setDetail] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  if (error) return <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />;
  const manage = can(me, "policies:manage");
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setFormError(null);
    const form = Object.fromEntries(new FormData(e.currentTarget)) as Obj;
    try {
      create.mutate({ ...form, scope: JSON.parse(form.scope || "{}"), condition: JSON.parse(form.condition) }, { onSuccess: () => setCreating(false) });
    } catch {
      setFormError("Scope and condition must be valid JSON.");
    }
  };
  return (
    <>
      <PageHeader title="Policies & Compliance" description="Security and AI governance rules evaluated against live asset and finding attributes. A policy cannot pass because data is missing: unknown values count as failures."
                  actions={<>{manage && <Button onClick={() => setCreating(true)}>New policy</Button>}<Button variant="primary" loading={evaluateAll.isPending} onClick={() => evaluateAll.mutate({})}>Evaluate all</Button></>} />
      {(evaluateAll.error || toggle.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(evaluateAll.error ?? toggle.error)}</Alert></div>}
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Compliance" value={data?.summary.compliance_percent == null ? "—" : `${data.summary.compliance_percent}%`} hint="of applicable, evaluated policies" />
        <Stat label="Compliant" value={data?.summary.compliant ?? "—"} tone="ok" />
        <Stat label="Non-compliant" value={data?.summary.non_compliant ?? "—"} tone={data?.summary.non_compliant ? "critical" : undefined} />
        <Stat label="Policies" value={data?.summary.total ?? "—"} />
      </div>
      <Card>
        {isLoading ? <Skeleton className="h-40" /> : !data?.items.length ? <EmptyState title="No policies" /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted"><tr>{["Policy", "Severity", "Applies to", "Status", "Result", "Evaluated", ""].map((h) => <th key={h} className="py-1 pr-3 font-medium">{h}</th>)}</tr></thead>
              <tbody>
                {data.items.map((p: Obj) => {
                  const e = p.latest_evaluation;
                  return (
                    <tr key={p.id} className="border-t border-border">
                      <td className="max-w-md py-2 pr-3"><button className="text-left font-medium hover:underline" onClick={() => setDetail(p.id)}>{p.name}</button><div className="truncate text-xs text-muted">{p.framework_refs.join(" · ")}</div></td>
                      <td className="pr-3"><SeverityBadge value={p.severity} /></td>
                      <td className="pr-3 text-xs">{p.entity_type}s</td>
                      <td className="pr-3">{!p.enabled ? <Badge>Disabled</Badge> : e ? <StatusBadge value={e.status} /> : <Badge>Not evaluated</Badge>}</td>
                      <td className="tabular pr-3 text-xs">{e ? `${e.passed}/${e.total} pass${e.exempt ? `, ${e.exempt} exempt` : ""}` : "—"}</td>
                      <td className="pr-3 text-xs text-muted">{e ? relativeTime(e.evaluated_at) : "—"}</td>
                      <td className="text-right">{manage && <Button size="sm" variant="ghost" onClick={() => toggle.mutate({ id: p.id, enabled: !p.enabled })}>{p.enabled ? "Disable" : "Enable"}</Button>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {detail && <Detail id={detail} onClose={() => setDetail(null)} />}
      <Dialog open={creating} onClose={() => setCreating(false)} title="New policy" wide>
        <form onSubmit={submit} className="space-y-3">
          {(formError || create.error) && <Alert tone="critical">{formError ?? errorMessage(create.error)}</Alert>}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Key" hint="Lowercase letters, digits and hyphens."><Input name="key" required pattern="[a-z0-9][a-z0-9-]{2,78}" /></Field>
            <Field label="Name"><Input name="name" required minLength={3} /></Field>
            <Field label="Severity"><Select name="severity" defaultValue="medium">{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</Select></Field>
            <Field label="Evaluated against"><Select name="entity_type"><option value="asset">Assets</option><option value="finding">Findings</option></Select></Field>
          </div>
          <Field label="Description"><Textarea name="description" /></Field>
          <Field label="Scope rule (JSON; {} = all)" hint={`Fields: ${(data?.fields.asset ?? []).slice(0, 12).join(", ")}…`}><Textarea name="scope" className="font-mono text-xs" defaultValue={'{"field": "type", "op": "eq", "value": "llm_endpoint"}'} /></Field>
          <Field label="Condition rule (JSON)" hint={`Operators: ${(data?.operators ?? []).join(", ")}. Combine with {"all": [...]}, {"any": [...]}, {"not": {...}}.`}><Textarea name="condition" required className="font-mono text-xs" defaultValue={'{"field": "ai.rate_limited", "op": "is_true"}'} /></Field>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setCreating(false)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Create</Button></div>
        </form>
      </Dialog>
    </>
  );
}
