"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Alert, Badge, Button, Card, Dialog, EmptyState, Field, Input, JsonBlock, PageHeader, Select, SeverityBadge, Skeleton, StatusBadge, Tabs, Textarea } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import { redTeamSchema, type RedTeamValues } from "@/lib/schemas";
import type { Obj } from "@/types/api";

function NewDialog({ onClose, catalog }: { onClose: () => void; catalog: Obj }) {
  const { data: integrations } = useGet<Obj[]>("/integrations");
  const create = useAction<Obj>("POST", "/ai-redteam/assessments");
  const [profiles, setProfiles] = useState<string[]>(["llm_application"]);
  const { register, handleSubmit, formState } = useForm<RedTeamValues>({
    resolver: zodResolver(redTeamSchema),
    defaultValues: { authorization_days: 14, request_budget: 60, rate_limit_per_minute: 20, attempts: 2, forbidden_markers: "" },
  });
  const targets = (integrations ?? []).filter((i) => i.connector === "llm");
  const submit = handleSubmit((v) =>
    create.mutate({ ...v, profiles, forbidden_markers: v.forbidden_markers.split("\n").map((s) => s.trim()).filter(Boolean) }, { onSuccess: onClose }));
  const number = { valueAsNumber: true } as const;
  return (
    <Dialog open onClose={onClose} title="New AI red team assessment" wide>
      <form onSubmit={submit} noValidate className="space-y-3">
        {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" error={formState.errors.name?.message}><Input {...register("name")} /></Field>
          <Field label="Target" error={formState.errors.integration_id?.message} hint={targets.length ? "The endpoint must also be in authorized scope with active testing allowed." : "Add an LLM endpoint under Integrations first."}>
            <Select {...register("integration_id")}><option value="">Select…</option>{targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select>
          </Field>
        </div>
        <fieldset className="rounded-md border border-border p-3">
          <legend className="px-1 text-xs font-medium text-muted">Profiles</legend>
          <div className="grid gap-1 sm:grid-cols-2">
            {Object.entries(catalog.profiles as Record<string, string>).map(([key, label]) => (
              <label key={key} className="flex items-start gap-2 text-xs">
                <input type="checkbox" className="mt-0.5" checked={profiles.includes(key)} onChange={(e) => setProfiles((p) => (e.target.checked ? [...p, key] : p.filter((x) => x !== key)))} />
                <span><span className="font-medium">{titleCase(key)}</span> — {label}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <Field label="Authorization statement" error={formState.errors.authorization_statement?.message} hint="Recorded in the audit log with your identity.">
          <Textarea {...register("authorization_statement")} placeholder="Approved by <owner> under <change/contract reference>; staging environment only." />
        </Field>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Field label="Valid for (days)" error={formState.errors.authorization_days?.message}><Input type="number" {...register("authorization_days", number)} /></Field>
          <Field label="Request budget" error={formState.errors.request_budget?.message}><Input type="number" {...register("request_budget", number)} /></Field>
          <Field label="Requests / minute" error={formState.errors.rate_limit_per_minute?.message}><Input type="number" {...register("rate_limit_per_minute", number)} /></Field>
          <Field label="Attempts per test" error={formState.errors.attempts?.message}><Input type="number" {...register("attempts", number)} /></Field>
        </div>
        <Field label="Forbidden markers (optional, one per line)" hint="Canary strings you planted in a restricted document or another tenant. Required for the retrieval and tenant-isolation tests against deployed applications.">
          <Textarea rows={2} {...register("forbidden_markers")} />
        </Field>
        <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>Cancel</Button><Button type="submit" variant="primary" disabled={!profiles.length} loading={create.isPending}>Authorize and create</Button></div>
      </form>
    </Dialog>
  );
}

function Results({ runId }: { runId: string }) {
  const { data } = useGet<Obj[]>(`/ai-redteam/runs/${runId}/tests`, undefined, { refetchInterval: 5000 });
  const [open, setOpen] = useState<Obj | null>(null);
  if (!data) return <Skeleton className="h-20" />;
  if (!data.length) return <p className="text-xs text-muted">No test records yet.</p>;
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-muted"><tr>{["Test", "Threat category", "OWASP", "Status", "Outcome", "Confidence", "Severity", "Reproduced", "Retest", ""].map((h) => <th key={h} className="py-1 pr-2 font-medium">{h}</th>)}</tr></thead>
          <tbody>
            {data.map((t) => (
              <tr key={t.id} className="border-t border-border align-top">
                <td className="py-1.5 pr-2 font-mono">{t.test_id}</td><td className="pr-2">{t.threat_category}</td><td className="pr-2">{t.owasp_llm}</td>
                <td className="pr-2"><StatusBadge value={t.execution_status} /></td><td className="pr-2">{t.outcome ? <StatusBadge value={t.outcome} /> : "—"}</td>
                <td className="pr-2">{titleCase(t.confidence)}</td><td className="pr-2"><SeverityBadge value={t.severity} /></td>
                <td className="tabular pr-2">{t.reproducibility.attempts ? `${t.reproducibility.reproduced}/${t.reproducibility.attempts}` : "—"}</td>
                <td className="pr-2">{t.retest_result ? <StatusBadge value={t.retest_result === "fixed" ? "remediated" : "failed"} /> : "—"}</td>
                <td><Button size="sm" variant="ghost" onClick={() => setOpen(t)}>Details</Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Dialog open={!!open} onClose={() => setOpen(null)} title={open ? `${open.test_id} · ${open.threat_category}` : ""} wide>
        {open && (
          <div className="space-y-2 text-sm">
            {([["Objective", open.objective], ["Preconditions", open.preconditions], ["Scope", open.scope], ["Procedure", open.procedure], ["Observed behaviour", open.observed_behavior || "—"], ["Remediation", open.remediation]] as [string, string][]).map(([k, v]) => (
              <div key={k}><div className="text-xs font-medium text-muted">{k}</div><p>{v}</p></div>
            ))}
            <div className="text-xs text-muted">MITRE ATLAS {open.atlas_technique ?? "—"} · NIST AI RMF {open.nist_ai_rmf} · executed {formatDate(open.executed_at, true)}</div>
            {open.finding_id && <Link href={`/findings/${open.finding_id}`} className="text-xs text-accent hover:underline">Open finding</Link>}
            {open.evidence && <><div className="text-xs font-medium text-muted">Evidence (recorded exchanges)</div><JsonBlock value={open.evidence} /></>}
          </div>
        )}
      </Dialog>
    </>
  );
}

export default function AIRedTeamPage() {
  const { data: me } = useMe();
  const { data: catalog } = useGet<Obj>("/ai-redteam/catalog");
  const { data: list } = useGet<Obj[]>("/ai-redteam/assessments", undefined, { refetchInterval: 4000 });
  const run = useAction<{ id: string; dry: boolean }, Obj>("POST", (b) => `/ai-redteam/assessments/${b.id}/run${b.dry ? "?dry_run=true" : ""}`);
  const cancel = useAction<{ job: string }, Obj>("POST", (b) => `/jobs/${b.job}/cancel`);
  const [tab, setTab] = useState<"assessments" | "catalog">("assessments");
  const [creating, setCreating] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const allowed = can(me, "ai_redteam:run");
  return (
    <>
      <PageHeader title="AI Red Team" description="Deterministic adversarial testing of LLM endpoints and AI applications. A test is recorded as vulnerable only when a planted marker, canary or forbidden tool call appears in the target's response."
                  actions={allowed && catalog && <Button variant="primary" onClick={() => setCreating(true)}>New assessment</Button>} />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "assessments", label: "Assessments", count: list?.length }, { id: "catalog", label: "Test catalogue", count: catalog?.tests.length }]} />
      {(run.error || cancel.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(run.error ?? cancel.error)}</Alert></div>}
      {tab === "assessments" && (
        <div className="space-y-4">
          {catalog && <Card title="Safety controls"><ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">{catalog.safety.map((s: string) => <li key={s}>{s}</li>)}</ul></Card>}
          {!list ? <Skeleton className="h-24" /> : list.length === 0 ? (
            <Card><EmptyState title="No AI red team assessments">Add the target as an LLM endpoint under Integrations, add its URL to authorized scope with active testing, then create an assessment.</EmptyState></Card>
          ) : list.map((a) => {
            const last = a.last_run, busy = last && ["queued", "running"].includes(last.status);
            return (
              <Card key={a.id} title={a.name} action={
                <div className="flex items-center gap-2">
                  {!a.authorization_current && <Badge tone="critical">Authorization expired</Badge>}
                  {last && <StatusBadge value={last.status} />}
                  {allowed && busy && last.job_id && <Button size="sm" variant="danger" onClick={() => cancel.mutate({ job: last.job_id })}>Cancel</Button>}
                  {allowed && <Button size="sm" variant="ghost" disabled={busy || !a.authorization_current} onClick={() => run.mutate({ id: a.id, dry: true })}>Dry run</Button>}
                  {allowed && <Button size="sm" disabled={busy || !a.authorization_current} onClick={() => run.mutate({ id: a.id, dry: false })}>Run</Button>}
                </div>}>
                <div className="space-y-2 text-xs text-muted">
                  <p>Target: <span className="text-text">{a.target_name}</span> · Profiles: {a.profiles.map(titleCase).join(", ")} · Budget {a.request_budget} requests at {a.rate_limit_per_minute}/min</p>
                  <p>Authorized until {formatDate(a.authorization_expires_at)}: “{a.authorization_statement}”</p>
                  {last?.error && <p className="text-critical">{last.error}</p>}
                  {last && <p>Last run {relativeTime(last.created_at)}{last.dry_run ? " (dry run)" : ""}{last.summary?.requests != null ? ` · ${last.summary.requests} requests sent · ${last.summary.findings_created ?? 0} new findings` : ""}</p>}
                  {last && <Button size="sm" variant="ghost" onClick={() => setExpanded(expanded === last.id ? null : last.id)}>{expanded === last.id ? "Hide results" : "Show results"}</Button>}
                </div>
                {last && expanded === last.id && <div className="mt-3 border-t border-border pt-3"><Results runId={last.id} /></div>}
              </Card>
            );
          })}
        </div>
      )}
      {tab === "catalog" && catalog && (
        <Card>
          <div className="space-y-3">
            {catalog.tests.map((t: Obj) => (
              <details key={t.id} className="rounded-md border border-border">
                <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2 text-sm"><span className="font-mono text-xs">{t.id}</span><span className="font-medium">{t.title}</span><Badge>{t.owasp_llm}</Badge>{t.atlas_technique && <Badge tone="low">{t.atlas_technique}</Badge>}<SeverityBadge value={t.severity} /></summary>
                <div className="space-y-1 border-t border-border p-3 text-xs"><p><b>Objective:</b> {t.objective}</p><p><b>Preconditions:</b> {t.preconditions}</p><p><b>Procedure:</b> {t.procedure}</p><p><b>Remediation:</b> {t.remediation}</p></div>
              </details>
            ))}
            <p className="text-xs text-muted">Related profiles are assessed by other engines under AI Security: {Object.entries(catalog.related_engines as Record<string, string>).map(([k, v]) => `${titleCase(k)} → ${titleCase(v)}`).join("; ")}.</p>
          </div>
        </Card>
      )}
      {creating && catalog && <NewDialog onClose={() => setCreating(false)} catalog={catalog} />}
    </>
  );
}
