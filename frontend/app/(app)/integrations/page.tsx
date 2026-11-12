"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, EmptyState, Field, Input, PageHeader, Skeleton, StatusBadge, Tabs } from "@/components/ui";
import { ImportDialog } from "@/features/assessments";
import { CiPipelines, UploadHistory } from "@/features/ci";
import { errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

const CATEGORY_LABEL: Record<string, string> = {
  ai: "AI", cloud: "Cloud", notification: "Notifications", scanner: "Scanners", threat_intel: "Threat intelligence", ticketing: "Ticketing",
};

function SchemaForm({ schema, prefix, secret, values }: { schema: Obj | null; prefix: string; secret?: boolean; values?: Obj }) {
  const properties: Obj = schema?.properties ?? {};
  const required: string[] = schema?.required ?? [];
  return (
    <>
      {Object.entries(properties).map(([key, spec]) => {
        const s = spec as Obj;
        const type = s.type ?? s.anyOf?.find((a: Obj) => a.type !== "null")?.type;
        const current = values?.[key] ?? s.default;
        const label = `${titleCase(key)}${required.includes(key) && !values ? " *" : ""}`;
        if (type === "boolean") {
          return <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" name={`${prefix}.${key}:bool`} defaultChecked={!!current} /> {label}<span className="text-xs text-muted">{s.description}</span></label>;
        }
        if (s.enum) {
          return <Field key={key} label={label} hint={s.description}><select name={`${prefix}.${key}`} defaultValue={current ?? s.enum[0]} className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm">{s.enum.map((v: string) => <option key={v}>{v}</option>)}</select></Field>;
        }
        const suffix = type === "array" ? ":list" : type === "object" ? ":json" : type === "integer" ? ":int" : "";
        const shown = secret ? "" : current == null ? "" : Array.isArray(current) ? current.join(", ") : typeof current === "object" ? JSON.stringify(current) : String(current);
        return (
          <Field key={key} label={label} hint={secret && values ? "Leave empty to keep the stored value." : s.description ?? (type === "array" ? "Comma-separated" : type === "object" ? "JSON object" : undefined)}>
            <Input name={`${prefix}.${key}${suffix}`} type={secret ? "password" : "text"} autoComplete="off" required={required.includes(key) && !(secret && values)} defaultValue={shown} />
          </Field>
        );
      })}
    </>
  );
}

function collect(form: FormData, prefix: string): Obj {
  const out: Obj = {};
  for (const [name, raw] of form.entries()) {
    if (!name.startsWith(prefix + ".")) continue;
    const [key, kind] = name.slice(prefix.length + 1).split(":");
    const value = String(raw).trim();
    if (kind === "bool") out[key] = true;
    else if (value === "") continue;
    else if (kind === "list") out[key] = value.split(",").map((v) => v.trim()).filter(Boolean);
    else if (kind === "json") out[key] = JSON.parse(value);
    else if (kind === "int") out[key] = Number(value);
    else out[key] = value;
  }
  return out;
}

function ConnectorAction({ c, manage, onConfigure, onUpload, onSync, syncing }: {
  c: Obj; manage: boolean; onConfigure: () => void; onUpload: () => void; onSync: () => void; syncing: boolean;
}) {
  if (c.key === "claude") return <Link href="/admin?tab=analytics" className="text-sm text-accent hover:underline">Set up in Administration</Link>;
  if (c.mode === "connection") return manage ? <Button size="sm" onClick={onConfigure}>Connect</Button> : null;
  if (c.mode === "feed") return c.key === "osv" ? null : <Button size="sm" loading={syncing} onClick={onSync}>Sync now</Button>;
  return <Button size="sm" onClick={onUpload}>Upload results</Button>;
}

function ConnectorState({ c }: { c: Obj }) {
  if (c.tool) {
    return c.tool.available ? <Badge tone="ok">{c.tool.version ?? "Installed on workers"}</Badge> : <Badge tone="medium">Not installed on workers · upload only</Badge>;
  }
  if (c.mode === "feed") {
    if (c.key === "osv") return <Badge>Queried during dependency analysis</Badge>;
    if (!c.sync?.last_success_at) return c.sync?.last_error ? <Badge tone="critical">Last sync failed</Badge> : <Badge>Not yet synchronised</Badge>;
    return <Badge tone={c.sync.last_error ? "critical" : "ok"}>Synchronised {relativeTime(c.sync.last_success_at)} · {c.sync.records.toLocaleString()} records</Badge>;
  }
  return null;
}

type Tab = "configured" | "catalog" | "ci" | "uploads";
const TABS: Tab[] = ["configured", "catalog", "ci", "uploads"];

export default function IntegrationsPage() {
  return <Suspense><Integrations /></Suspense>;
}

function Integrations() {
  const router = useRouter();
  const search = useSearchParams();
  const { data: me } = useMe();
  const { data: catalog } = useGet<Obj[]>("/integrations/catalog", undefined, { refetchInterval: 15_000 });
  const { data: configured } = useGet<Obj[]>("/integrations");
  const create = useAction<Obj>("POST", "/integrations");
  const update = useAction<{ id: string } & Obj, Obj>("PATCH", (b) => `/integrations/${b.id}`);
  const test = useAction<{ id: string }, Obj>("POST", (b) => `/integrations/${b.id}/test`);
  const remove = useAction<{ id: string }, Obj>("DELETE", (b) => `/integrations/${b.id}`);
  const sync = useAction<{ source: string }, Obj>("POST", (b) => `/intel/sync?source=${b.source}`);
  const requested = search.get("tab") as Tab | null;
  const tab: Tab = requested && TABS.includes(requested) ? requested : "configured";
  const setTab = (next: Tab) => router.replace(next === "configured" ? "/integrations" : `/integrations?tab=${next}`, { scroll: false });
  const [adding, setAdding] = useState<Obj | null>(null);
  const [editing, setEditing] = useState<Obj | null>(null);
  const [uploading, setUploading] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const manage = can(me, "integrations:manage");
  const specFor = (key: string) => (catalog ?? []).find((c) => c.key === key);

  const submitNew = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!adding) return;
    setFormError(null);
    const form = new FormData(e.currentTarget);
    try {
      create.mutate({ connector: adding.key, name: String(form.get("name")), config: collect(form, "config"), credentials: collect(form, "credentials") }, { onSuccess: () => setAdding(null) });
    } catch {
      setFormError("One of the JSON fields is not valid JSON.");
    }
  };
  const submitEdit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!editing) return;
    setFormError(null);
    const form = new FormData(e.currentTarget);
    try {
      const credentials = collect(form, "credentials");
      update.mutate({ id: editing.id, name: String(form.get("name")), config: collect(form, "config"), ...(Object.keys(credentials).length ? { credentials } : {}) },
                    { onSuccess: () => setEditing(null) });
    } catch {
      setFormError("One of the JSON fields is not valid JSON.");
    }
  };
  const categories = [...new Set((catalog ?? []).map((c) => c.category))];
  const editSpec = editing ? specFor(editing.connector) : null;

  return (
    <>
      <PageHeader title="Integrations" description="Connections to clouds, scanners, model endpoints, ticketing and notification systems, and pipelines that send scanner results. Credentials are encrypted at rest and never returned by the API." />
      {(test.error || remove.error || update.error || sync.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(test.error ?? remove.error ?? update.error ?? sync.error)}</Alert></div>}
      {test.data && <div className="mb-3"><Alert tone={test.data.ok ? "ok" : "critical"}>{test.data.ok ? "Connection succeeded: " : `Connection failed (${test.data.error_class}): `}{test.data.detail}</Alert></div>}
      {sync.isSuccess && <div className="mb-3"><Alert tone="ok">Synchronisation queued. The status updates when the worker finishes.</Alert></div>}
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "configured", label: "Configured", count: configured?.length }, { id: "catalog", label: "Available integrations", count: catalog?.length },
                                         { id: "ci", label: "CI/CD pipelines" }, { id: "uploads", label: "Uploaded results" }]} />
      {tab === "ci" && <CiPipelines />}
      {tab === "uploads" && <UploadHistory pageSize={50} title="All uploaded results" />}
      {tab === "configured" && (
        <Card>
          {!configured ? <Skeleton className="h-20" /> : configured.length === 0 ? <EmptyState title="No integrations configured">Choose one from Available integrations.</EmptyState> : (
            <ul className="divide-y divide-border">
              {configured.map((i) => (
                <li key={i.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-sm font-medium">{i.name}{!i.enabled && <Badge>Disabled</Badge>}</div>
                    <div className="text-xs text-muted">
                      {specFor(i.connector)?.name ?? titleCase(i.connector)} · {i.has_credentials ? "credentials stored (encrypted)" : "no stored credentials"}
                      {i.last_checked_at ? ` · checked ${relativeTime(i.last_checked_at)}` : ""}{i.last_sync_at ? ` · last used by an assessment ${relativeTime(i.last_sync_at)}` : ""}
                    </div>
                    {i.last_error && <div className="mt-0.5 text-xs text-critical">{i.last_error_class}: {i.last_error}</div>}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge value={i.health} />
                    {manage && i.connector === "claude" && <Link href="/admin?tab=analytics" className="text-xs text-accent hover:underline">Manage</Link>}
                    {manage && i.connector !== "claude" && (
                      <>
                        <Button size="sm" loading={test.isPending && test.variables?.id === i.id} onClick={() => test.mutate({ id: i.id })}>Test connection</Button>
                        <Button size="sm" variant="ghost" onClick={() => { setFormError(null); setEditing(i); }}>Edit</Button>
                        <Button size="sm" variant="ghost" onClick={() => update.mutate({ id: i.id, enabled: !i.enabled })}>{i.enabled ? "Disable" : "Enable"}</Button>
                        <Button size="sm" variant="ghost" onClick={() => window.confirm(`Delete integration “${i.name}”? Assessments and rules that use it will stop working.`) && remove.mutate({ id: i.id })}>Delete</Button>
                      </>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
      {tab === "catalog" && (
        <div className="space-y-4">
          {!catalog && <Skeleton className="h-40" />}
          {categories.map((category) => (
            <Card key={category} title={CATEGORY_LABEL[category] ?? titleCase(category)}>
              <ul className="divide-y divide-border">
                {(catalog ?? []).filter((c) => c.category === category).map((c) => (
                  <li key={c.key} className="flex flex-wrap items-start justify-between gap-3 py-2.5">
                    <div className="min-w-0 max-w-3xl">
                      <div className="flex flex-wrap items-center gap-2 text-sm font-medium">{c.name}<ConnectorState c={c} /></div>
                      <p className="mt-0.5 text-xs text-muted">{c.description}</p>
                      {c.required_permissions && <p className="mt-0.5 text-xs text-muted">Access: {c.required_permissions}</p>}
                      {c.sync?.last_error && <p className="mt-0.5 text-xs text-critical">{c.sync.last_error}</p>}
                    </div>
                    <ConnectorAction c={c} manage={manage} onConfigure={() => { setFormError(null); setAdding(c); }}
                                     onUpload={() => setUploading(c.import_format ?? c.key)} onSync={() => sync.mutate({ source: c.key })}
                                     syncing={sync.isPending && sync.variables?.source === c.key} />
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}
      <Dialog open={!!adding} onClose={() => setAdding(null)} title={adding ? `Connect ${adding.name}` : ""} wide>
        {adding && (
          <form onSubmit={submitNew} className="space-y-3">
            {(formError || create.error) && <Alert tone="critical">{formError ?? errorMessage(create.error)}</Alert>}
            {adding.required_permissions && <Alert>Use a dedicated, least-privilege credential. {adding.required_permissions}</Alert>}
            <Field label="Name *"><Input name="name" required minLength={2} defaultValue={adding.name} /></Field>
            <SchemaForm schema={adding.config_schema} prefix="config" />
            <SchemaForm schema={adding.credentials_schema} prefix="credentials" secret />
            <div className="flex justify-end gap-2"><Button type="button" onClick={() => setAdding(null)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Save</Button></div>
          </form>
        )}
      </Dialog>
      <Dialog open={!!editing} onClose={() => setEditing(null)} title={editing ? `Edit ${editing.name}` : ""} wide>
        {editing && editSpec && (
          <form onSubmit={submitEdit} className="space-y-3">
            {(formError || update.error) && <Alert tone="critical">{formError ?? errorMessage(update.error)}</Alert>}
            <Field label="Name"><Input name="name" required minLength={2} defaultValue={editing.name} /></Field>
            <SchemaForm schema={editSpec.config_schema} prefix="config" values={editing.config} />
            <SchemaForm schema={editSpec.credentials_schema} prefix="credentials" secret values={{}} />
            <p className="text-xs text-muted">Changing settings marks the integration unverified until the next successful connection test.</p>
            <div className="flex justify-end gap-2"><Button type="button" onClick={() => setEditing(null)}>Cancel</Button><Button type="submit" variant="primary" loading={update.isPending}>Save</Button></div>
          </form>
        )}
      </Dialog>
      {uploading && <ImportDialog open initialFormat={uploading} onClose={() => setUploading(null)} />}
    </>
  );
}
