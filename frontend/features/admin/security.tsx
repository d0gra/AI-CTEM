"use client";

import { useState } from "react";
import { Alert, Badge, Button, Card, Field, Input } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime } from "@/lib/format";
import { useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export function Security() {
  const { data: me } = useMe();
  const { data: sessions } = useGet<Obj[]>("/auth/sessions");
  const revoke = useAction<{ id: string }, Obj>("DELETE", (b) => `/auth/sessions/${b.id}`);
  const setup = useAction<Obj, Obj>("POST", "/auth/mfa/setup");
  const enable = useAction<Obj>("POST", "/auth/mfa/enable");
  const change = useAction<Obj>("POST", "/auth/password/change");
  const disable = useAction<Obj>("POST", "/auth/mfa/disable");
  const resend = useAction<Obj, Obj>("POST", "/auth/email/resend");
  const [code, setCode] = useState("");
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Email address" className="lg:col-span-2">
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
          <span>{me?.email} {me?.email_verified ? <Badge tone="ok">Verified</Badge> : <Badge tone="medium">Not verified</Badge>}</span>
          {!me?.email_verified && <Button size="sm" loading={resend.isPending} onClick={() => resend.mutate({})}>Send verification link</Button>}
        </div>
        {resend.data && <p className="mt-2 text-xs text-muted">{resend.data.detail}</p>}
      </Card>
      <Card title="Multi-factor authentication">
        {(setup.error || enable.error) && <Alert tone="critical">{errorMessage(setup.error ?? enable.error)}</Alert>}
        {me?.mfa_enabled || enable.isSuccess ? (
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); const form = e.currentTarget; disable.mutate(Object.fromEntries(new FormData(form)) as Obj, { onSuccess: () => form.reset() }); }}>
            <Alert tone="ok">TOTP is enabled for your account.</Alert>
            {disable.error && <Alert tone="critical">{errorMessage(disable.error)}</Alert>}
            {disable.isSuccess && <Alert tone="medium">MFA has been turned off.</Alert>}
            <p className="text-xs text-muted">To turn MFA off, confirm with your password and a current code.</p>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Password"><Input type="password" name="password" required autoComplete="current-password" /></Field>
              <Field label="Current code"><Input name="code" inputMode="numeric" maxLength={6} required /></Field>
            </div>
            <Button type="submit" variant="danger" loading={disable.isPending}>Turn off MFA</Button>
          </form>
        ) : !setup.data ? (
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
