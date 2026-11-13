"use client";

import Link from "next/link";
import { Play, Plus, Upload } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, EmptyState, ErrorState, Field, Input, Select, Skeleton, StatusBadge, Textarea } from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";
import { UploadHistory } from "@/features/ci";
import { useQueryClient } from "@tanstack/react-query";

/** Renders inputs for an engine's JSON-schema configuration (booleans, numbers, strings, string lists). */
function ConfigFields({ schema, value, onChange }: { schema: Obj; value: Obj; onChange: (v: Obj) => void }) {
  const properties: Obj = schema?.properties ?? {};
  const keys = Object.keys(properties);
  if (!keys.length) return null;
  return (
    <fieldset className="space-y-2 rounded-md border border-border p-3">
      <legend className="px-1 text-xs font-medium text-muted">Options</legend>
      {keys.map((key) => {
        const spec = properties[key];
        const type = spec.type ?? spec.anyOf?.find((a: Obj) => a.type !== "null")?.type;
        const current = value[key] ?? spec.default;
        const label = titleCase(key);
        if (type === "boolean") {
          return (
            <label key={key} className="flex items-start gap-2 text-sm">
              <input type="checkbox" className="mt-0.5" checked={!!current} onChange={(e) => onChange({ ...value, [key]: e.target.checked })} />
              <span>
                {label}
                {spec.description && <span className="block text-xs text-muted">{spec.description}</span>}
              </span>
            </label>
          );
        }
        if (type === "integer" || type === "number") {
          return (
            <Field key={key} label={label} hint={spec.description}>
              <Input type="number" min={spec.minimum} max={spec.maximum} value={current ?? ""} onChange={(e) => onChange({ ...value, [key]: e.target.value === "" ? undefined : Number(e.target.value) })} />
            </Field>
          );
        }
        if (type === "array") {
          return (
            <Field key={key} label={label} hint={spec.description ?? "Comma-separated"}>
              <Input value={Array.isArray(current) ? current.join(", ") : ""} onChange={(e) => onChange({ ...value, [key]: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} />
            </Field>
          );
        }
        return (
          <Field key={key} label={label} hint={spec.description}>
            <Input value={current ?? ""} onChange={(e) => onChange({ ...value, [key]: e.target.value || undefined })} />
          </Field>
        );
      })}
    </fieldset>
  );
}

function NewAssessmentDialog({ open, onClose, engines }: { open: boolean; onClose: () => void; engines: Obj[] }) {
  const [kind, setKind] = useState(engines[0]?.kind ?? "");
  const [name, setName] = useState("");
  const [targetKind, setTargetKind] = useState("");
  const [targets, setTargets] = useState("");
  const [integrationId, setIntegrationId] = useState("");
  const [interval, setIntervalMinutes] = useState("");
  const [config, setConfig] = useState<Obj>({});
  const engine = engines.find((e) => e.kind === kind) ?? engines[0];
  const { data: integrations } = useGet<Obj[]>(engine?.requires_connector ? "/integrations" : null);
  const create = useAction<Obj, Obj>("POST", "/assessments");
  if (!engine) return null;
  const kinds: string[] = engine.target_kinds;
  const activeKind = kinds.includes(targetKind) ? targetKind : kinds[0];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(
      {
        name, kind: engine.kind, config,
        targets: targets.split("\n").map((t) => t.trim()).filter(Boolean).map((value) => ({ kind: activeKind, value })),
        integration_id: integrationId || null,
        schedule_interval_minutes: interval ? Number(interval) : null,
      },
      { onSuccess: () => { onClose(); setName(""); setTargets(""); setConfig({}); } },
    );
  };

  return (
    <Dialog open={open} onClose={onClose} title="New assessment" wide>
      <form onSubmit={submit} className="space-y-3">
        {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
        <Field label="Assessment type">
          <Select value={engine.kind} onChange={(e) => { setKind(e.target.value); setConfig({}); }}>
            {engines.map((e) => (
              <option key={e.kind} value={e.kind}>{e.name}</option>
            ))}
          </Select>
        </Field>
        <p className="text-xs text-muted">{engine.description}</p>
        <div className="flex flex-wrap gap-1.5">
          <Badge tone={engine.active ? "high" : "info"}>{engine.active ? "Active: sends traffic to targets" : "Passive / offline"}</Badge>
          {engine.tool.required && <Badge tone={engine.tool.available ? "ok" : "critical"}>{engine.tool.available ? engine.tool.version ?? engine.tool.required : `${engine.tool.required} is not installed on the workers`}</Badge>}
        </div>
        <Field label="Name">
          <Input required minLength={2} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        {kinds.length > 0 && (
          <div className="grid gap-3 sm:grid-cols-[10rem_1fr]">
            <Field label="Target type">
              <Select value={activeKind} onChange={(e) => setTargetKind(e.target.value)}>
                {kinds.map((k) => <option key={k} value={k}>{titleCase(k)}</option>)}
              </Select>
            </Field>
            <Field label="Targets" hint="One per line. Every target must be covered by an authorized scope entry.">
              <Textarea required value={targets} onChange={(e) => setTargets(e.target.value)} placeholder={activeKind === "domain" ? "example.com" : activeKind === "url" ? "https://app.example.com" : ""} />
            </Field>
          </div>
        )}
        {engine.requires_connector && (
          <Field label="Integration">
            <Select required value={integrationId} onChange={(e) => setIntegrationId(e.target.value)}>
              <option value="">Select…</option>
              {(integrations ?? []).filter((i) => i.connector === engine.requires_connector).map((i) => (
                <option key={i.id} value={i.id}>{i.name}</option>
              ))}
            </Select>
          </Field>
        )}
        <ConfigFields schema={engine.config_schema} value={config} onChange={setConfig} />
        <Field label="Repeat every (minutes)" hint="Leave empty to run on demand only. Minimum 15.">
          <Input type="number" min={15} value={interval} onChange={(e) => setIntervalMinutes(e.target.value)} />
        </Field>
        <div className="flex justify-end gap-2">
          <Button type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>Create</Button>
        </div>
      </form>
    </Dialog>
  );
}

export function ImportDialog({ open, onClose, initialFormat = "trivy" }: { open: boolean; onClose: () => void; initialFormat?: string }) {
  const client = useQueryClient();
  const [format, setFormat] = useState(initialFormat);
  const [target, setTarget] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const formats = ["ctem", "trivy", "grype", "nuclei", "semgrep", "gitleaks", "checkov", "zap", "prowler", "nmap", "sarif", "sbom"];
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.set("format", format);
      form.set("file", file);
      if (target) form.set("target", target);
      await api("/scanner-imports", { method: "POST", form });
      await client.invalidateQueries();
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onClose={onClose} title="Import scanner results">
      <form onSubmit={submit} className="space-y-3">
        {error && <Alert tone="critical">{error}</Alert>}
        <Field label="Format">
          <Select value={format} onChange={(e) => setFormat(e.target.value)}>
            {formats.map((f) => <option key={f} value={f}>{f === "sbom" ? "SBOM (CycloneDX / SPDX JSON)" : f === "prowler" ? "Prowler (OCSF JSON)" : f === "ctem" ? "CTEM CLI inventory (ctem discover)" : titleCase(f)}</option>)}
          </Select>
        </Field>
        <Alert>To send results on every build instead, use a pipeline token: <Link href="/integrations?tab=ci" className="text-accent hover:underline">Integrations → CI/CD pipelines</Link>.</Alert>
        <Field label="Results file" hint="Parsed by a background worker; a file in the wrong format fails the import with an explanation.">
          <Input type="file" required onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="py-1.5" />
        </Field>
        <Field label="Target identifier (optional)" hint="Required when the report does not name what was scanned (for example Semgrep or Gitleaks output).">
          <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="git@github.com:acme/shop.git" />
        </Field>
        <div className="flex justify-end gap-2">
          <Button type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={busy}>Import</Button>
        </div>
      </form>
    </Dialog>
  );
}

const MODULE_FORMATS: Record<string, string[] | undefined> = {
  web_api: ["zap", "nuclei"], supply_chain: ["trivy", "grype", "semgrep", "gitleaks", "sbom", "sarif"], cloud: ["checkov", "prowler"],
  attack_surface: ["nmap", "nuclei"],
};

export function AssessmentsPanel({ module, allowImport }: { module: string; allowImport?: boolean }) {
  return (
    <div className="space-y-4">
      <AssessmentList module={module} allowImport={allowImport} />
      {allowImport && <UploadHistory formats={MODULE_FORMATS[module]} />}
    </div>
  );
}

function AssessmentList({ module, allowImport }: { module: string; allowImport?: boolean }) {
  const { data: me } = useMe();
  const { data: engines } = useGet<Obj[]>("/assessments/engines");
  const { data, error, isLoading, refetch } = useGet<Obj>("/assessments", { module, page_size: 50 }, { refetchInterval: 4000 });
  const run = useAction<{ id: string; dry_run: boolean }, Obj>("POST", (b) => `/assessments/${b.id}/run`);
  const update = useAction<{ id: string } & Obj, Obj>("PATCH", (b) => `/assessments/${b.id}`);
  const remove = useAction<{ id: string }, Obj>("DELETE", (b) => `/assessments/${b.id}`);
  const cancel = useAction<{ id: string }, Obj>("POST", (b) => `/jobs/${b.id}/cancel`);
  const [editing, setEditing] = useState<Obj | null>(null);
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const firstFormat = MODULE_FORMATS[module]?.[0];
  const moduleEngines = (engines ?? []).filter((e) => e.module === module && e.kind !== "scanner_import" && e.kind !== "ai_redteam");
  const canRun = can(me, "assessments:run");

  return (
    <Card
      title="Assessments"
      action={
        canRun && (
          <div className="flex gap-2">
            {allowImport && <Button size="sm" onClick={() => setImporting(true)}><Upload className="h-3.5 w-3.5" /> Import results</Button>}
            {moduleEngines.length > 0 && <Button size="sm" variant="primary" onClick={() => setCreating(true)}><Plus className="h-3.5 w-3.5" /> New assessment</Button>}
          </div>
        )
      }
    >
      {(run.error || update.error || remove.error || cancel.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(run.error ?? update.error ?? remove.error ?? cancel.error)}</Alert></div>}
      {isLoading && <Skeleton className="h-16 w-full" />}
      {error && <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />}
      {data && data.items.length === 0 && (
        <EmptyState title="No assessments yet">
          Add the targets you are authorized to assess under Administration → Authorized scope, then create an assessment.
        </EmptyState>
      )}
      {data && data.items.length > 0 && (
        <ul className="divide-y divide-border">
          {data.items.map((a: Obj) => {
            const last = a.last_run;
            const busy = last && ["queued", "running"].includes(last.status);
            return (
              <li key={a.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 truncate text-sm font-medium">{a.name}{!a.enabled && <Badge>Schedule paused</Badge>}</div>
                  <div className="truncate text-xs text-muted">
                    {titleCase(a.kind)}
                    {a.targets.length > 0 && ` · ${a.targets.slice(0, 2).map((t: Obj) => t.value).join(", ")}${a.targets.length > 2 ? ` +${a.targets.length - 2}` : ""}`}
                    {a.schedule_interval_minutes && ` · every ${a.schedule_interval_minutes} min`}
                    {a.enabled && a.next_run_at && ` · next ${relativeTime(a.next_run_at)}`}
                  </div>
                  {last?.error && <div className="mt-1 text-xs text-critical">{last.error}</div>}
                  {last?.summary?.skipped?.length > 0 && <div className="mt-1 text-xs text-medium">{last.summary.skipped.length} item(s) skipped: {last.summary.skipped[0].reason}</div>}
                </div>
                <div className="flex items-center gap-2">
                  {last ? (
                    <span className="flex items-center gap-1.5 text-xs text-muted">
                      <StatusBadge value={last.status} />
                      {last.dry_run && <Badge>Dry run</Badge>}
                      {last.status === "succeeded" && !last.dry_run && <span className="tabular">{last.summary?.findings_created ?? 0} new · {last.summary?.findings_seen ?? 0} seen</span>}
                      <span>{relativeTime(last.created_at)}</span>
                    </span>
                  ) : (
                    <span className="text-xs text-muted">Never run</span>
                  )}
                  {canRun && busy && last.job_id && <Button size="sm" variant="ghost" onClick={() => cancel.mutate({ id: last.job_id })}>Cancel run</Button>}
                  {canRun && a.kind !== "scanner_import" && (
                    <>
                      <Button size="sm" variant="ghost" disabled={busy || run.isPending} onClick={() => run.mutate({ id: a.id, dry_run: true })}>Dry run</Button>
                      <Button size="sm" disabled={busy || run.isPending} onClick={() => run.mutate({ id: a.id, dry_run: false })}><Play className="h-3 w-3" /> Run</Button>
                      <Button size="sm" variant="ghost" onClick={() => setEditing(a)}>Edit</Button>
                    </>
                  )}
                  {canRun && !busy && (
                    <Button size="sm" variant="ghost" onClick={() => window.confirm(`Delete “${a.name}”? Its findings are kept.`) && remove.mutate({ id: a.id })}>Delete</Button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {creating && <NewAssessmentDialog open onClose={() => setCreating(false)} engines={moduleEngines} />}
      <Dialog open={!!editing} onClose={() => setEditing(null)} title={editing ? `Edit ${editing.name}` : ""}>
        {editing && (
          <form className="space-y-3" onSubmit={(e) => {
            e.preventDefault();
            const form = new FormData(e.currentTarget);
            const interval = String(form.get("interval") ?? "");
            update.mutate({ id: editing.id, name: String(form.get("name")), enabled: form.has("enabled"), schedule_interval_minutes: interval ? Number(interval) : null },
                          { onSuccess: () => setEditing(null) });
          }}>
            <Field label="Name"><Input name="name" required minLength={2} defaultValue={editing.name} /></Field>
            <Field label="Repeat every (minutes)" hint="Empty = on demand only. Minimum 15."><Input type="number" name="interval" min={15} defaultValue={editing.schedule_interval_minutes ?? ""} /></Field>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={editing.enabled} /> Run on schedule</label>
            <p className="text-xs text-muted">Targets and options are fixed once created; create a new assessment to change them.</p>
            <div className="flex justify-end gap-2"><Button type="button" onClick={() => setEditing(null)}>Cancel</Button><Button type="submit" variant="primary" loading={update.isPending}>Save</Button></div>
          </form>
        )}
      </Dialog>
      {importing && <ImportDialog open initialFormat={firstFormat} onClose={() => setImporting(false)} />}
    </Card>
  );
}
