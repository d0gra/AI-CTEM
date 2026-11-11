"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CheckCircle2, KeyRound, Server } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useForm } from "react-hook-form";
import { Alert, Badge, Button, Card, Field, Input, Select, Skeleton } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import { claudeSchema, type ClaudeValues } from "@/lib/schemas";
import type { Obj } from "@/types/api";

function ConnectForm({ status, onDone }: { status: Obj; onDone: () => void }) {
  const connect = useAction<ClaudeValues, Obj>("POST", "/analytics/claude/connect");
  const [models, setModels] = useState<Obj[]>([]);
  const { register, handleSubmit, watch, formState } = useForm<ClaudeValues>({
    resolver: zodResolver(claudeSchema),
    defaultValues: { credential_source: status.credential_source ?? "api_key", api_key: "", model: status.model ?? status.default_model, effort: status.effort ?? "medium" },
  });
  const source = watch("credential_source");
  const submit = handleSubmit((values) =>
    connect.mutate({ ...values, api_key: values.api_key || undefined }, {
      onSuccess: (result) => { setModels(result.models ?? []); onDone(); },
      onError: (error) => { const found = (error as { details?: Obj }).details?.models; if (Array.isArray(found)) setModels(found); },
    }));
  const options = models.length ? models : [{ id: "claude-opus-5-5", display_name: "Claude Opus 5.5" }, { id: "claude-sonnet-5-5", display_name: "Claude Sonnet 5.5" },
                                           { id: "claude-haiku-5-5", display_name: "Claude Haiku 5.5" }];
  return (
    <form onSubmit={submit} noValidate className="space-y-3">
      {connect.error && <Alert tone="critical">{errorMessage(connect.error)}</Alert>}
      <fieldset className="grid gap-2 sm:grid-cols-2">
        <label className="flex cursor-pointer items-start gap-2 rounded-md border border-border p-3 text-sm has-[:checked]:border-accent">
          <input type="radio" value="api_key" {...register("credential_source")} className="mt-1" />
          <span><span className="flex items-center gap-1.5 font-medium"><KeyRound className="h-4 w-4" /> Claude Console API key</span>
            <span className="text-xs text-muted">Create a key at platform.claude.com → Settings → API keys. Stored encrypted for this organization.</span></span>
        </label>
        <label className={`flex items-start gap-2 rounded-md border border-border p-3 text-sm has-[:checked]:border-accent ${status.server_credentials_allowed ? "cursor-pointer" : "opacity-60"}`}>
          <input type="radio" value="server" {...register("credential_source")} className="mt-1" disabled={!status.server_credentials_allowed} />
          <span><span className="flex items-center gap-1.5 font-medium"><Server className="h-4 w-4" /> Server sign-in</span>
            <span className="text-xs text-muted">{status.server_credentials_allowed
              ? "Use the Claude credentials of the platform's servers (an `ant auth login` sign-in, ANTHROPIC_API_KEY or workload identity federation). Nothing is stored here."
              : "Not enabled on this deployment (CTEM_ALLOW_SERVER_CLAUDE_CREDENTIALS)."}</span></span>
        </label>
      </fieldset>
      {source === "api_key" && (
        <Field label="API key" hint={status.has_api_key ? "Leave empty to keep the stored key." : "Begins with sk-ant-."}>
          <Input type="password" autoComplete="off" placeholder={status.has_api_key ? "••••••••  (stored)" : "sk-ant-…"} {...register("api_key")} />
        </Field>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Model" error={formState.errors.model?.message} hint={models.length ? `${models.length} models available to this credential.` : "The list is refreshed from your account when you connect."}>
          <Select {...register("model")}>{options.map((m) => <option key={m.id} value={m.id}>{m.display_name ?? m.id}</option>)}</Select>
        </Field>
        <Field label="Effort" hint="Higher effort reasons longer and uses more tokens.">
          <Select {...register("effort")}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></Select>
        </Field>
      </div>
      <Button type="submit" variant="primary" loading={connect.isPending}>{status.connected ? "Save and reconnect" : "Connect Claude"}</Button>
    </form>
  );
}

export function ClaudeConnection() {
  const { data: me } = useMe();
  const { data: status, refetch } = useGet<Obj>("/analytics/claude");
  const { data: settings } = useGet<Obj>("/analytics/settings");
  const test = useAction<Obj, Obj>("POST", "/analytics/claude/test");
  const disconnect = useAction<Obj>("DELETE", "/analytics/claude");
  const save = useAction<Obj>("PUT", "/analytics/settings");
  const [editing, setEditing] = useState(false);
  if (!status || !settings) return <Skeleton className="h-40" />;
  const admin = can(me, "admin:org");
  const saveSettings = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    save.mutate({ ...settings, enabled: form.has("enabled"), monthly_token_budget: Number(form.get("monthly_token_budget")),
                  max_output_tokens: Number(form.get("max_output_tokens")), share_evidence_with_provider: form.has("share_evidence_with_provider") });
  };
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Card title="Claude" className="lg:col-span-2" action={status.connected && <Badge tone={status.health === "healthy" ? "ok" : "critical"}>{status.health === "healthy" ? "Connected" : "Connection error"}</Badge>}>
        <div className="space-y-3">
          <p className="text-sm text-muted">Claude powers the AI features: finding and attack-path explanations and the executive briefing on the Overview page.</p>
          <Alert>{status.billing_note}</Alert>
          {status.connected && !editing && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <CheckCircle2 className="h-4 w-4 text-ok" aria-hidden />
                <span>{status.credential_source === "server" ? "Using the server's sign-in" : "Using a stored Console API key"}</span>
                <Badge>{status.model}</Badge><Badge>{status.effort} effort</Badge>
                {status.last_checked_at && <span className="text-xs text-muted">checked {relativeTime(status.last_checked_at)}</span>}
              </div>
              {status.last_error && <Alert tone="critical">{status.last_error}</Alert>}
              {test.data && <Alert tone={test.data.ok ? "ok" : "critical"}>{test.data.detail}</Alert>}
              {!status.in_use && <Alert tone="medium">Claude is connected but AI analysis is turned off below.</Alert>}
              <div className="flex flex-wrap gap-2">
                <Button size="sm" loading={test.isPending} onClick={() => test.mutate({}, { onSettled: () => refetch() })}>Test connection</Button>
                {admin && <Button size="sm" onClick={() => setEditing(true)}>Change</Button>}
                {admin && <Button size="sm" variant="ghost" loading={disconnect.isPending} onClick={() => window.confirm("Disconnect Claude? AI features stop working and the stored key is deleted.") && disconnect.mutate({})}>Disconnect</Button>}
              </div>
            </div>
          )}
          {(!status.connected || editing) && (admin ? <ConnectForm status={status} onDone={() => { setEditing(false); refetch(); }} />
            : <p className="text-sm text-muted">An organization administrator can connect Claude.</p>)}
          {editing && <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>}
        </div>
      </Card>
      <Card title="Usage and limits">
        <form onSubmit={saveSettings} className="space-y-3">
          {save.error && <Alert tone="critical">{errorMessage(save.error)}</Alert>}
          {save.isSuccess && <Alert tone="ok">Saved.</Alert>}
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={settings.enabled} disabled={!admin || !status.connected} /> AI analysis enabled</label>
          <Field label="Monthly token budget"><Input type="number" name="monthly_token_budget" min={10000} defaultValue={settings.monthly_token_budget} disabled={!admin} /></Field>
          <Field label="Maximum output tokens per request" hint="Includes the model's reasoning."><Input type="number" name="max_output_tokens" min={1024} max={16000} defaultValue={settings.max_output_tokens} disabled={!admin} /></Field>
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-0.5" name="share_evidence_with_provider" defaultChecked={settings.share_evidence_with_provider} disabled={!admin} />
            <span>Include stored evidence in prompts<span className="block text-xs text-muted">Off by default. Evidence can contain response bodies and configuration from your systems. Credentials are always redacted.</span></span></label>
          <p className="text-xs text-muted">This month: {settings.usage_this_month.requests} requests · {settings.usage_this_month.tokens.toLocaleString()} tokens · ${settings.usage_this_month.cost_usd}</p>
          {admin && <Button type="submit" size="sm" loading={save.isPending}>Save</Button>}
        </form>
      </Card>
    </div>
  );
}
