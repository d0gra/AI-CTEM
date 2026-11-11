"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useState, type FormEvent } from "react";
import { useForm } from "react-hook-form";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Card, Dialog, EmptyState, Field, Input, PageHeader, Select, Skeleton, Tabs, Textarea } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import { scopeSchema, type ScopeValues } from "@/lib/schemas";
import type { Obj } from "@/types/api";

function Scope() {
  const { data: me } = useMe();
  const { data } = useGet<Obj[]>("/scope");
  const add = useAction<Obj>("POST", "/scope");
  const remove = useAction<{ id: string }, Obj>("DELETE", (b) => `/scope/${b.id}`);
  const { register, handleSubmit, reset, formState } = useForm<ScopeValues>({ resolver: zodResolver(scopeSchema), defaultValues: { kind: "domain", allow_active: false, allow_private_network: false } });
  const manage = can(me, "scope:manage");
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Card title="Authorized scope" className="lg:col-span-2">
        <p className="mb-3 text-xs text-muted">No engine contacts a target that is not covered here. Active techniques additionally require “active testing”. Private addresses require both the flag below and the deployment setting CTEM_ALLOW_PRIVATE_TARGETS.</p>
        {remove.error && <Alert tone="critical">{errorMessage(remove.error)}</Alert>}
        {!data ? <Skeleton className="h-20" /> : data.length === 0 ? <EmptyState title="No authorized targets">Assessments cannot be created until at least one target is authorized.</EmptyState> : (
          <ul className="divide-y divide-border">
            {data.map((s) => (
              <li key={s.id} className="flex items-start justify-between gap-3 py-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2 text-sm"><Badge>{s.kind}</Badge><span className="font-mono">{s.value}</span>{s.allow_active ? <Badge tone="high">Active testing</Badge> : <Badge>Passive only</Badge>}{s.allow_private_network && <Badge tone="medium">Private network</Badge>}</div>
                  <div className="mt-0.5 text-xs text-muted">{s.authorization_note} · added {formatDate(s.created_at)}</div>
                </div>
                {manage && <Button size="sm" variant="ghost" onClick={() => remove.mutate({ id: s.id })}>Remove</Button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      {manage && (
        <Card title="Authorize a target">
          <form noValidate onSubmit={handleSubmit((v) => add.mutate(v, { onSuccess: () => reset() }))} className="space-y-3">
            {add.error && <Alert tone="critical">{errorMessage(add.error)}</Alert>}
            <Field label="Kind"><Select {...register("kind")}><option value="domain">Domain (includes subdomains)</option><option value="cidr">IP range (CIDR)</option><option value="url">URL prefix</option><option value="path">Local repository path</option></Select></Field>
            <Field label="Value" error={formState.errors.value?.message}><Input {...register("value")} placeholder="example.com" /></Field>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" {...register("allow_active")} /> Allow active testing</label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" {...register("allow_private_network")} /> Target is on a private network</label>
            <Field label="Authorization basis" error={formState.errors.authorization_note?.message} hint="Recorded in the audit log."><Textarea {...register("authorization_note")} placeholder="Owned by <team>; approved under <ticket/contract>." /></Field>
            <Button type="submit" variant="primary" loading={add.isPending}>Authorize</Button>
          </form>
        </Card>
      )}
    </div>
  );
}

function Users() {
  const { data: me } = useMe();
  const { data: roles } = useGet<Obj[]>("/admin/roles");
  const create = useAction<Obj>("POST", "/admin/users");
  const update = useAction<{ id: string } & Obj, Obj>("PATCH", (b) => `/admin/users/${b.id}`);
  const [open, setOpen] = useState(false);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    create.mutate(Object.fromEntries(new FormData(e.currentTarget)) as Obj, { onSuccess: () => setOpen(false) });
  };
  return (
    <>
      {update.error && <div className="mb-3"><Alert tone="critical">{errorMessage(update.error)}</Alert></div>}
      <div className="mb-3 text-right"><Button variant="primary" onClick={() => setOpen(true)}>Add user</Button></div>
      <DataTable<Obj>
        path="/admin/users"
        columns={[
          { key: "full_name", header: "User", render: (u) => <div><div className="font-medium">{u.full_name}</div><div className="text-xs text-muted">{u.email}</div></div> },
          { key: "role", header: "Role", render: (u) => u.id === me?.id ? <span className="text-xs">{titleCase(u.role_key)} (you)</span> : (
            <Select aria-label={`Role for ${u.email}`} className="w-52" value={u.role_id} onChange={(e) => update.mutate({ id: u.id, role_id: e.target.value })}>{(roles ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</Select>) },
          { key: "mfa", header: "MFA", render: (u) => (u.mfa_enabled ? <Badge tone="ok">Enabled</Badge> : <Badge tone="medium">Not enrolled</Badge>) },
          { key: "verified", header: "Email", render: (u) => (u.email_verified_at ? <Badge tone="ok">Verified</Badge> : <Badge>Unverified</Badge>) },
          { key: "last_login_at", header: "Last sign-in", render: (u) => <span className="text-xs">{relativeTime(u.last_login_at)}</span> },
          { key: "active", header: "", render: (u) => u.id !== me?.id && <Button size="sm" variant="ghost" onClick={() => update.mutate({ id: u.id, is_active: !u.is_active })}>{u.is_active ? "Deactivate" : "Reactivate"}</Button> },
        ]}
      />
      <Dialog open={open} onClose={() => setOpen(false)} title="Add user">
        <form onSubmit={submit} className="space-y-3">
          {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
          <Field label="Full name"><Input name="full_name" required /></Field>
          <Field label="Email"><Input name="email" type="email" required /></Field>
          <Field label="Initial password" hint="At least 12 characters. Share it out of band; the user should change it at first sign-in."><Input name="password" type="password" required minLength={12} autoComplete="new-password" /></Field>
          <Field label="Role" hint="You can only assign roles whose permissions you hold yourself."><Select name="role_id" required>{(roles ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</Select></Field>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Create user</Button></div>
        </form>
      </Dialog>
    </>
  );
}

function Roles() {
  const { data: roles } = useGet<Obj[]>("/admin/roles");
  if (!roles) return <Skeleton className="h-40" />;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {roles.map((r) => (
        <Card key={r.id} title={<span className="flex items-center gap-2">{r.name}{r.is_builtin ? <Badge>Built-in</Badge> : <Badge tone="low">Custom</Badge>}</span>}>
          <div className="flex flex-wrap gap-1">{r.permissions.map((p: string) => <span key={p} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]">{p}</span>)}</div>
        </Card>
      ))}
    </div>
  );
}

function Security() {
  const { data: me } = useMe();
  const { data: sessions } = useGet<Obj[]>("/auth/sessions");
  const revoke = useAction<{ id: string }, Obj>("DELETE", (b) => `/auth/sessions/${b.id}`);
  const setup = useAction<Obj, Obj>("POST", "/auth/mfa/setup");
  const enable = useAction<Obj>("POST", "/auth/mfa/enable");
  const change = useAction<Obj>("POST", "/auth/password/change");
  const [code, setCode] = useState("");
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Multi-factor authentication">
        {(setup.error || enable.error) && <Alert tone="critical">{errorMessage(setup.error ?? enable.error)}</Alert>}
        {me?.mfa_enabled || enable.isSuccess ? <Alert tone="ok">TOTP is enabled for your account.</Alert> : !setup.data ? (
          <div className="space-y-2"><p className="text-sm text-muted">Add a time-based one-time password from an authenticator app.</p><Button onClick={() => setup.mutate({})} loading={setup.isPending}>Set up MFA</Button></div>
        ) : (
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); enable.mutate({ code }); }}>
            <p className="text-sm">Add this secret to your authenticator app, then enter the current code. Other sessions are signed out when MFA is enabled.</p>
            <code className="block break-all rounded bg-surface-2 p-2 font-mono text-xs">{setup.data.secret}</code>
            <Field label="6-digit code"><Input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} required /></Field>
            <Button type="submit" variant="primary" loading={enable.isPending}>Enable MFA</Button>
          </form>
        )}
      </Card>
      <Card title="Change password">
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); const form = e.currentTarget; change.mutate(Object.fromEntries(new FormData(form)) as Obj, { onSuccess: () => form.reset() }); }}>
          {change.error && <Alert tone="critical">{errorMessage(change.error)}</Alert>}
          {change.isSuccess && <Alert tone="ok">Password changed. Other sessions were signed out.</Alert>}
          <Field label="Current password"><Input type="password" name="current_password" required autoComplete="current-password" /></Field>
          <Field label="New password"><Input type="password" name="new_password" required minLength={12} autoComplete="new-password" /></Field>
          <Button type="submit" loading={change.isPending}>Change password</Button>
        </form>
      </Card>
      <Card title="Active sessions" className="lg:col-span-2">
        <ul className="divide-y divide-border">
          {(sessions ?? []).map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-3 py-2 text-sm">
              <div className="min-w-0"><div className="truncate">{s.user_agent ?? "Unknown client"}</div><div className="text-xs text-muted">{s.ip_address ?? "unknown address"} · last active {relativeTime(s.last_seen_at)} · expires {formatDate(s.expires_at, true)}</div></div>
              {s.current ? <Badge tone="ok">This session</Badge> : <Button size="sm" variant="ghost" onClick={() => revoke.mutate({ id: s.id })}>Revoke</Button>}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

function Analytics() {
  const { data: me } = useMe();
  const { data } = useGet<Obj>("/analytics/settings");
  const { data: integrations } = useGet<Obj[]>(can(me, "integrations:read") ? "/integrations" : null);
  const save = useAction<Obj>("PUT", "/analytics/settings");
  if (!data) return <Skeleton className="h-40" />;
  const editable = can(me, "admin:org");
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    save.mutate({ enabled: form.has("enabled"), integration_id: form.get("integration_id") || null, monthly_token_budget: Number(form.get("monthly_token_budget")),
                  max_output_tokens: data.max_output_tokens, effort: form.get("effort"), share_evidence_with_provider: form.has("share_evidence_with_provider") });
  };
  return (
    <Card title="AI-assisted analysis">
      <form onSubmit={submit} className="max-w-2xl space-y-3">
        {save.error && <Alert tone="critical">{errorMessage(save.error)}</Alert>}
        {save.isSuccess && <Alert tone="ok">Settings saved.</Alert>}
        <Alert>Output is advisory and labelled as AI-generated. It never changes a finding&apos;s status, severity, confidence or score. Finding titles, descriptions and asset context are sent to the selected provider; credentials are redacted first.</Alert>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={data.enabled} disabled={!editable} /> Enable AI-assisted explanations</label>
        <Field label="Provider" hint="An LLM endpoint integration. For Claude, the default model is claude-opus-5-5 with server-side refusal fallback enabled.">
          <Select name="integration_id" defaultValue={data.integration_id ?? ""} disabled={!editable}><option value="">Select…</option>{(integrations ?? []).filter((i) => i.connector === "llm").map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}</Select>
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Monthly token budget"><Input type="number" name="monthly_token_budget" min={10000} defaultValue={data.monthly_token_budget} disabled={!editable} /></Field>
          <Field label="Effort"><Select name="effort" defaultValue={data.effort} disabled={!editable}>{["low", "medium", "high"].map((v) => <option key={v}>{v}</option>)}</Select></Field>
        </div>
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-0.5" name="share_evidence_with_provider" defaultChecked={data.share_evidence_with_provider} disabled={!editable} /><span>Authorize sending stored evidence content to the provider<span className="block text-xs text-muted">Off by default. Evidence can contain response bodies and configuration excerpts from your systems.</span></span></label>
        <p className="text-xs text-muted">This month: {data.usage_this_month.requests} requests, {data.usage_this_month.tokens.toLocaleString()} tokens, ${data.usage_this_month.cost_usd} (where pricing is known). Prompt version {data.prompt_version}.</p>
        {editable && <Button type="submit" variant="primary" loading={save.isPending}>Save</Button>}
      </form>
    </Card>
  );
}

export default function AdminPage() {
  const { data: me } = useMe();
  const [tab, setTab] = useState<"scope" | "users" | "roles" | "security" | "analytics">("scope");
  const tabs = [{ id: "scope" as const, label: "Authorized scope" }, ...(can(me, "admin:users") ? [{ id: "users" as const, label: "Users" }] : []), { id: "roles" as const, label: "Roles" },
                { id: "security" as const, label: "My security" }, ...(can(me, "ai_analytics:use") ? [{ id: "analytics" as const, label: "AI analysis" }] : [])];
  return (
    <>
      <PageHeader title="Administration" description="Authorized assessment scope, users and roles, your own account security, and AI-assisted analysis settings." />
      <Tabs value={tab} onChange={setTab} tabs={tabs} />
      {tab === "scope" && <Scope />}
      {tab === "users" && <Users />}
      {tab === "roles" && <Roles />}
      {tab === "security" && <Security />}
      {tab === "analytics" && <Analytics />}
    </>
  );
}
