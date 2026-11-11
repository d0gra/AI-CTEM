"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { useForm } from "react-hook-form";
import { Alert, Badge, Button, Card, Dialog, ErrorState, Field, Input, JsonBlock, KeyValue, PageHeader, Select, SeverityBadge, Skeleton, StatusBadge, Textarea } from "@/components/ui";
import { api, downloadUrl, errorMessage } from "@/lib/api";
import { formatBytes, formatDate, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import { acceptanceSchema, type AcceptanceValues } from "@/lib/schemas";
import type { Obj } from "@/types/api";
import { useQueryClient } from "@tanstack/react-query";

function Prose({ text }: { text: string }) {
  return <p className="whitespace-pre-wrap text-sm leading-relaxed">{text}</p>;
}

function RiskBreakdown({ risk }: { risk: Obj }) {
  const factors = [...risk.likelihood.factors.map((f: Obj) => ({ ...f, group: "Likelihood" })), ...risk.impact.factors.map((f: Obj) => ({ ...f, group: "Impact" }))];
  return (
    <div className="space-y-3 text-sm">
      <p className="text-xs text-muted">
        Score = {risk.formula}. Likelihood {risk.likelihood.value} × impact {risk.impact.value} gives a base of {risk.base_score}. Inputs are not averaged.
      </p>
      <table className="w-full text-left text-xs">
        <thead className="text-muted"><tr><th className="py-1 font-medium">Factor</th><th className="font-medium">Value</th><th className="font-medium">Why</th></tr></thead>
        <tbody>
          {factors.map((f: Obj) => (
            <tr key={f.name} className="border-t border-border align-top">
              <td className="py-1.5 pr-3">{f.group}: {titleCase(f.name)}</td>
              <td className="tabular pr-3">{f.value}</td>
              <td className="text-muted">{f.reason}</td>
            </tr>
          ))}
          {risk.escalators.map((e: Obj) => (
            <tr key={e.name} className="border-t border-border align-top">
              <td className="py-1.5 pr-3">Escalator: {titleCase(e.name)}</td><td className="tabular pr-3">+{e.points}</td><td className="text-muted">{e.reason}</td>
            </tr>
          ))}
          {risk.floors.map((f: Obj) => (
            <tr key={f.name} className="border-t border-border align-top">
              <td className="py-1.5 pr-3">Floor: {titleCase(f.name)}</td><td className="tabular pr-3">≥ {f.minimum}</td><td className="text-muted">{f.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AcceptanceDialog({ findingId, open, onClose, users }: { findingId: string; open: boolean; onClose: () => void; users: Obj[] }) {
  const request = useAction<Obj>("POST", "/risk/acceptances");
  const { register, handleSubmit, formState } = useForm<AcceptanceValues>({ resolver: zodResolver(acceptanceSchema), defaultValues: { compensating_controls: "" } });
  const submit = handleSubmit((v) => request.mutate({ ...v, finding_id: findingId, expires_at: new Date(v.expires_at).toISOString() }, { onSuccess: onClose }));
  return (
    <Dialog open={open} onClose={onClose} title="Request risk acceptance">
      <form onSubmit={submit} noValidate className="space-y-3">
        {request.error && <Alert tone="critical">{errorMessage(request.error)}</Alert>}
        <Alert>A second person with approval rights must approve this request. Accepted risk expires and the finding returns to triage.</Alert>
        <Field label="Business reason" error={formState.errors.reason?.message}><Textarea {...register("reason")} /></Field>
        <Field label="Compensating controls" error={formState.errors.compensating_controls?.message}><Textarea {...register("compensating_controls")} /></Field>
        <Field label="Risk owner" error={formState.errors.owner_user_id?.message}>
          <Select {...register("owner_user_id")}><option value="">Select…</option>{users.map((u) => <option key={u.id} value={u.id}>{u.full_name}</option>)}</Select>
        </Field>
        <Field label="Expires" error={formState.errors.expires_at?.message}><Input type="date" {...register("expires_at")} /></Field>
        <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>Cancel</Button><Button type="submit" variant="primary" loading={request.isPending}>Submit request</Button></div>
      </form>
    </Dialog>
  );
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const client = useQueryClient();
  const { data: me } = useMe();
  const { data: f, error, isLoading, refetch } = useGet<Obj>(`/findings/${id}`, undefined, { refetchInterval: 8000 });
  const { data: directory } = useGet<Obj>("/admin/directory");
  const patch = useAction<Obj>("PATCH", `/findings/${id}`);
  const retest = useAction<Obj>("POST", `/findings/${id}/retest`);
  const verify = useAction<Obj>("POST", `/findings/${id}/verify`);
  const comment = useAction<Obj>("POST", `/findings/${id}/comments`);
  const createTask = useAction<Obj>("POST", "/remediation/tasks");
  const explain = useAction<Obj, Obj>("POST", `/analytics/findings/${id}/explain`);
  const [note, setNote] = useState("");
  const [status, setStatus] = useState("");
  const [text, setText] = useState("");
  const [accepting, setAccepting] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyNote, setVerifyNote] = useState("");
  const [uploadError, setUploadError] = useState<string | null>(null);

  if (error) return <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />;
  if (isLoading || !f) return <Skeleton className="h-64 w-full" />;
  const canWrite = can(me, "findings:write");
  const actionError = patch.error ?? retest.error ?? verify.error ?? comment.error ?? createTask.error ?? explain.error;
  const open = ["new", "triaged", "assigned", "in_progress", "pending_validation"].includes(f.status);

  const upload = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setUploadError(null);
    try {
      await api(`/findings/${id}/evidence`, { method: "POST", form: new FormData(e.currentTarget) });
      e.currentTarget.reset();
      await client.invalidateQueries();
    } catch (err) {
      setUploadError(errorMessage(err));
    }
  };

  return (
    <>
      <PageHeader
        title={f.title}
        description={<>On <Link href={`/assets/${f.asset.id}`} className="text-accent hover:underline">{f.asset.name}</Link> · {titleCase(f.asset.type)} · found by {f.source} ({f.rule_id})</>}
        actions={<><SeverityBadge value={f.risk_level} /><StatusBadge value={f.status} />{f.kev && <Badge tone="critical">Known exploited</Badge>}{f.overdue && <Badge tone="critical">Past SLA</Badge>}</>}
      />
      {actionError && <div className="mb-3"><Alert tone="critical">{errorMessage(actionError)}</Alert></div>}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {f.description && <Card title="Description"><Prose text={f.description} /></Card>}
          {(f.technical_impact || f.business_impact) && (
            <div className="grid gap-4 md:grid-cols-2">
              {f.technical_impact && <Card title="Technical impact"><Prose text={f.technical_impact} /></Card>}
              {f.business_impact && <Card title="Business impact"><Prose text={f.business_impact} /></Card>}
            </div>
          )}
          {f.reproduction && <Card title="Reproduction"><pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs">{f.reproduction}</pre></Card>}
          <Card title="Remediation">
            {f.remediation ? <Prose text={f.remediation} /> : <p className="text-sm text-muted">No remediation guidance was supplied by the source.</p>}
            {f.remediation_tasks.length > 0 && (
              <ul className="mt-3 space-y-1 border-t border-border pt-3 text-sm">
                {f.remediation_tasks.map((t: Obj) => (
                  <li key={t.id} className="flex items-center justify-between gap-2">
                    <span className="truncate">{t.title}</span>
                    <span className="flex items-center gap-2"><StatusBadge value={t.status} />{t.ticket_url && <a className="text-xs text-accent hover:underline" href={t.ticket_url} target="_blank" rel="noreferrer noopener">{t.ticket_key}</a>}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title={`Evidence (${f.evidence.length})`}>
            {f.evidence.length === 0 && <p className="text-sm text-muted">No evidence recorded.</p>}
            <div className="space-y-3">
              {f.evidence.map((e: Obj) => (
                <details key={e.id} className="rounded-md border border-border">
                  <summary className="cursor-pointer px-3 py-2 text-sm"><Badge>{titleCase(e.kind)}</Badge> <span className="ml-1">{e.summary}</span> <span className="text-xs text-muted">· {formatDate(e.created_at, true)}</span></summary>
                  <div className="space-y-2 border-t border-border p-3">
                    {e.has_file ? (
                      <p className="text-xs">
                        <a className="text-accent hover:underline" href={downloadUrl(`/evidence/${e.id}/download`)}>Download file</a> · {formatBytes(e.size_bytes)} · SHA-256 <span className="font-mono">{e.sha256}</span>
                      </p>
                    ) : <JsonBlock value={e.content} />}
                  </div>
                </details>
              ))}
            </div>
            {canWrite && (
              <form onSubmit={upload} className="mt-3 flex flex-wrap items-end gap-2 border-t border-border pt-3">
                <Field label="Attach evidence file"><Input type="file" name="file" required className="py-1.5" accept=".png,.jpg,.jpeg,.pdf,.txt,.log,.json,.csv,.har,.xml" /></Field>
                <Field label="Summary"><Input name="summary" required minLength={3} /></Field>
                <Button type="submit" size="md">Upload</Button>
                {uploadError && <Alert tone="critical">{uploadError}</Alert>}
              </form>
            )}
          </Card>
          {f.risk.current && <Card title={`Why this priority: risk ${f.risk_score.toFixed(1)} (${f.risk_level})`}><RiskBreakdown risk={f.risk.current} /></Card>}
          {can(me, "ai_analytics:use") && (
            <Card title="AI-assisted explanation" action={<Button size="sm" loading={explain.isPending} onClick={() => explain.mutate({})}>Generate</Button>}>
              {!explain.data && <p className="text-sm text-muted">Generates an advisory summary from this finding&apos;s recorded facts. It never changes the finding and requires an AI provider enabled under Administration.</p>}
              {explain.data && (
                <div className="space-y-2 text-sm">
                  <Alert tone="medium">{explain.data.notice} Model: {explain.data.model}.</Alert>
                  <p>{explain.data.analysis.summary}</p>
                  <p>{explain.data.analysis.why_it_matters}</p>
                  <ol className="list-decimal space-y-0.5 pl-5">{explain.data.analysis.recommended_actions.map((a: string) => <li key={a}>{a}</li>)}</ol>
                  {explain.data.analysis.caveats.length > 0 && <p className="text-xs text-muted">Caveats: {explain.data.analysis.caveats.join("; ")}</p>}
                </div>
              )}
            </Card>
          )}
          <Card title="Timeline">
            <ol className="space-y-2">
              {f.timeline.map((e: Obj) => (
                <li key={e.id} className="text-sm">
                  <span className="font-medium">{titleCase(e.event_type)}</span>
                  <span className="text-muted"> · {e.actor ?? "system"} · {formatDate(e.occurred_at, true)}</span>
                  {e.event_type === "comment" ? <p className="mt-0.5 whitespace-pre-wrap">{e.data.body}</p> : Object.keys(e.data).length > 0 && (
                    <p className="mt-0.5 text-xs text-muted">{Object.entries(e.data).filter(([, v]) => v != null && v !== "").map(([k, v]) => `${titleCase(k)}: ${String(v)}`).join(" · ")}</p>
                  )}
                </li>
              ))}
            </ol>
            {canWrite && (
              <form className="mt-3 flex gap-2 border-t border-border pt-3" onSubmit={(e) => { e.preventDefault(); comment.mutate({ body: text }, { onSuccess: () => setText("") }); }}>
                <Input aria-label="Comment" placeholder="Add a comment" value={text} onChange={(e) => setText(e.target.value)} required />
                <Button type="submit" loading={comment.isPending}>Comment</Button>
              </form>
            )}
          </Card>
        </div>
        <div className="space-y-4">
          <Card title="Details">
            <KeyValue items={[
              ["Risk score", <span key="r" className="tabular">{f.risk_score.toFixed(1)}</span>],
              ["Severity", <SeverityBadge key="s" value={f.severity} />],
              ["Confidence", titleCase(f.confidence)],
              ["Domain", titleCase(f.domain)],
              ["First seen", formatDate(f.first_seen_at, true)],
              ["Last seen", formatDate(f.last_seen_at, true)],
              ["Due", formatDate(f.due_at)],
              ["Weakness", f.cwe ?? "—"],
              ["Asset exposure", <StatusBadge key="e" value={f.asset.exposure} />],
              ["Asset criticality", titleCase(f.asset.criticality)],
            ]} />
          </Card>
          {f.vulnerability && (
            <Card title={f.vulnerability.external_id}>
              <KeyValue items={[
                ["CVSS", f.vulnerability.cvss_score ?? "Not synchronised"],
                ["EPSS", f.vulnerability.epss_score == null ? "Not synchronised" : `${(f.vulnerability.epss_score * 100).toFixed(2)}%`],
                ["CISA KEV", f.vulnerability.kev ? `Yes (due ${formatDate(f.vulnerability.kev_due_date)})` : "No"],
                ["Fixed in", f.vulnerability.fixed_versions?.join(", ") || "—"],
              ]} />
            </Card>
          )}
          {f.ai && (
            <Card title="AI threat taxonomy">
              <KeyValue items={[["OWASP LLM Top 10", f.ai.owasp_llm ?? "—"], ["MITRE ATLAS", f.ai.atlas_technique ?? "—"], ["NIST AI RMF", f.ai.nist_ai_rmf ?? "—"], ["Test", f.ai.test_id ?? "—"]]} />
            </Card>
          )}
          {canWrite && (
            <Card title="Workflow">
              <div className="space-y-3">
                <Field label="Owner">
                  <Select value={f.owner_user_id ?? ""} onChange={(e) => patch.mutate({ owner_user_id: e.target.value || null })}>
                    <option value="">Unassigned</option>
                    {(directory?.users ?? []).map((u: Obj) => <option key={u.id} value={u.id}>{u.full_name}</option>)}
                  </Select>
                </Field>
                <Field label="Team">
                  <Select value={f.owner_team_id ?? ""} onChange={(e) => patch.mutate({ owner_team_id: e.target.value || null })}>
                    <option value="">No team</option>
                    {(directory?.teams ?? []).map((t: Obj) => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </Select>
                </Field>
                <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (status) patch.mutate({ status, note }, { onSuccess: () => { setStatus(""); setNote(""); } }); }}>
                  <Field label="Change status">
                    <Select value={status} onChange={(e) => setStatus(e.target.value)}>
                      <option value="">Select…</option>
                      {f.allowed_transitions.filter((s: string) => !["accepted_risk", "remediated"].includes(s)).map((s: string) => <option key={s} value={s}>{titleCase(s)}</option>)}
                    </Select>
                  </Field>
                  <Input aria-label="Note" placeholder={status === "false_positive" ? "Justification (required)" : "Note (optional)"} value={note} onChange={(e) => setNote(e.target.value)} />
                  <Button type="submit" size="sm" disabled={!status} loading={patch.isPending}>Apply</Button>
                </form>
                {open && (
                  <div className="flex flex-wrap gap-2 border-t border-border pt-3">
                    {f.can_automated_retest && can(me, "assessments:run") && <Button size="sm" variant="primary" loading={retest.isPending} onClick={() => retest.mutate({})}>Retest</Button>}
                    <Button size="sm" onClick={() => setVerifying(true)}>Record manual verification</Button>
                    {can(me, "remediation:write") && <Button size="sm" loading={createTask.isPending} onClick={() => createTask.mutate({ finding_id: id })}>Create remediation task</Button>}
                    {can(me, "risk:request") && <Button size="sm" onClick={() => setAccepting(true)}>Request risk acceptance</Button>}
                  </div>
                )}
                <p className="text-xs text-muted">A finding is marked remediated only when a retest no longer observes it, or a manual verification is recorded.</p>
              </div>
            </Card>
          )}
          {f.references.length > 0 && (
            <Card title="References">
              <ul className="space-y-1 text-xs">{f.references.map((r: string) => <li key={r} className="truncate"><a href={r} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">{r}</a></li>)}</ul>
            </Card>
          )}
        </div>
      </div>
      {accepting && <AcceptanceDialog findingId={id} open onClose={() => setAccepting(false)} users={directory?.users ?? []} />}
      <Dialog open={verifying} onClose={() => setVerifying(false)} title="Record manual verification">
        <div className="space-y-3">
          <Field label="What was checked and what was observed"><Textarea value={verifyNote} onChange={(e) => setVerifyNote(e.target.value)} /></Field>
          <div className="flex justify-end gap-2">
            <Button disabled={verifyNote.length < 5} onClick={() => verify.mutate({ result: "still_present", note: verifyNote }, { onSuccess: () => setVerifying(false) })}>Still present</Button>
            <Button variant="primary" disabled={verifyNote.length < 5} onClick={() => verify.mutate({ result: "fixed", note: verifyNote }, { onSuccess: () => setVerifying(false) })}>Verified fixed</Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
