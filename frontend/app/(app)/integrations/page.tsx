"use client";

import { useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, EmptyState, Field, Input, PageHeader, Skeleton, StatusBadge, Tabs } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

const STATUS_LABEL: Record<string, [string, string]> = {
  available: ["Implemented", "ok"], import_only: ["Import only", "low"], reference: ["Public data source", "info"],
};

function SchemaForm({ schema, prefix, secret }: { schema: Obj | null; prefix: string; secret?: boolean }) {
  const properties: Obj = schema?.properties ?? {};
  const required: string[] = schema?.required ?? [];
  return (
    <>
      {Object.entries(properties).map(([key, spec]) => {
        const s = spec as Obj;
        const type = s.type ?? s.anyOf?.find((a: Obj) => a.type !== "null")?.type;
        const label = `${titleCase(key)}${required.includes(key) ? " *" : ""}`;
        if (type === "boolean") {
          return <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" name={`${prefix}.${key}:bool`} defaultChecked={!!s.default} /> {label}<span className="text-xs text-muted">{s.description}</span></label>;
        }
        if (s.enum) {
          return <Field key={key} label={label} hint={s.description}><select name={`${prefix}.${key}`} defaultValue={s.default ?? s.enum[0]} className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm">{s.enum.map((v: string) => <option key={v}>{v}</option>)}</select></Field>;
        }
        const suffix = type === "array" ? ":list" : type === "object" ? ":json" : type === "integer" ? ":int" : "";
        return (
          <Field key={key} label={label} hint={s.description ?? (type === "array" ? "Comma-separated" : type === "object" ? "JSON object" : undefined)}>
            <Input name={`${prefix}.${key}${suffix}`} type={secret ? "password" : "text"} autoComplete="off" required={required.includes(key)}
                   defaultValue={s.default == null ? "" : Array.isArray(s.default) ? s.default.join(", ") : typeof s.default === "object" ? JSON.stringify(s.default) : String(s.default)} />
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

export default function IntegrationsPage() {
  const { data: me } = useMe();
  const { data: catalog } = useGet<Obj[]>("/integrations/catalog");
  const { data: configured } = useGet<Obj[]>("/integrations");
  const create = useAction<Obj>("POST", "/integrations");
  const test = useAction<{ id: string }, Obj>("POST", (b) => `/integrations/${b.id}/test`);
  const remove = useAction<{ id: string }, Obj>("DELETE", (b) => `/integrations/${b.id}`);
  const [tab, setTab] = useState<"configured" | "catalog">("configured");
  const [adding, setAdding] = useState<Obj | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const manage = can(me, "integrations:manage");
  const submit = (e: FormEvent<HTMLFormElement>) => {
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
  const categories = [...new Set((catalog ?? []).map((c) => c.category))];
  return (
    <>
      <PageHeader title="Integrations" description="Connections to clouds, scanners, model endpoints, ticketing and notification systems. Credentials are encrypted at rest and never returned by the API. The catalogue states the real implementation status of every connector." />
      {(test.error || remove.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(test.error ?? remove.error)}</Alert></div>}
      {test.data && <div className="mb-3"><Alert tone={test.data.ok ? "ok" : "critical"}>{test.data.ok ? "Connection succeeded: " : `Connection failed (${test.data.error_class}): `}{test.data.detail}</Alert></div>}
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "configured", label: "Configured", count: configured?.length }, { id: "catalog", label: "Catalogue", count: catalog?.length }]} />
      {tab === "configured" && (
        <Card>
          {!configured ? <Skeleton className="h-20" /> : configured.length === 0 ? <EmptyState title="No integrations configured">Choose a connector from the catalogue.</EmptyState> : (
            <ul className="divide-y divide-border">
              {configured.map((i) => (
                <li key={i.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                  <div className="min-w-0">
                    <div className="text-sm font-medium">{i.name}</div>
                    <div className="text-xs text-muted">{titleCase(i.connector)} · {i.has_credentials ? "credentials stored (encrypted)" : "no credentials"}{i.last_checked_at ? ` · checked ${relativeTime(i.last_checked_at)}` : ""}</div>
                    {i.last_error && <div className="mt-0.5 text-xs text-critical">{i.last_error_class}: {i.last_error}</div>}
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusBadge value={i.health} />
                    {manage && <Button size="sm" loading={test.isPending && test.variables?.id === i.id} onClick={() => test.mutate({ id: i.id })}>Test connection</Button>}
                    {manage && <Button size="sm" variant="ghost" onClick={() => window.confirm(`Delete integration “${i.name}”? Assessments and rules that use it will stop working.`) && remove.mutate({ id: i.id })}>Delete</Button>}
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
            <Card key={category} title={titleCase(category)}>
              <ul className="divide-y divide-border">
                {(catalog ?? []).filter((c) => c.category === category).map((c) => {
                  const [label, tone] = STATUS_LABEL[c.status] ?? [c.status, "info"];
                  return (
                    <li key={c.key} className="flex flex-wrap items-start justify-between gap-3 py-2.5">
                      <div className="min-w-0 max-w-3xl">
                        <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
                          {c.name}<Badge tone={tone}>{label}</Badge>
                          {c.status === "available" && <Badge tone={c.live_validated ? "ok" : "medium"}>{c.live_validated ? "Validated by execution" : "Fixture-tested; live validation pending"}</Badge>}
                          {c.tool && <Badge tone={c.tool.available ? "ok" : "info"}>{c.tool.available ? c.tool.version ?? "installed" : "binary not installed on this server"}</Badge>}
                        </div>
                        <p className="mt-0.5 text-xs text-muted">{c.description}</p>
                        {c.required_permissions && <p className="mt-0.5 text-xs text-muted">Required access: {c.required_permissions}</p>}
                        {c.sync && <p className="mt-0.5 text-xs text-muted">Last sync: {c.sync.last_success_at ? relativeTime(c.sync.last_success_at) : "never"}{c.sync.last_error ? ` · last error: ${c.sync.last_error}` : ""}</p>}
                      </div>
                      {c.configurable && manage && <Button size="sm" onClick={() => setAdding(c)}>Configure</Button>}
                    </li>
                  );
                })}
              </ul>
            </Card>
          ))}
        </div>
      )}
      <Dialog open={!!adding} onClose={() => setAdding(null)} title={adding ? `Configure ${adding.name}` : ""} wide>
        {adding && (
          <form onSubmit={submit} className="space-y-3">
            {(formError || create.error) && <Alert tone="critical">{formError ?? errorMessage(create.error)}</Alert>}
            {adding.required_permissions && <Alert>Use a dedicated, least-privilege credential. {adding.required_permissions}</Alert>}
            <Field label="Name *"><Input name="name" required minLength={2} /></Field>
            <SchemaForm schema={adding.config_schema} prefix="config" />
            <SchemaForm schema={adding.credentials_schema} prefix="credentials" secret />
            <div className="flex justify-end gap-2"><Button type="button" onClick={() => setAdding(null)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Save</Button></div>
          </form>
        )}
      </Dialog>
    </>
  );
}
