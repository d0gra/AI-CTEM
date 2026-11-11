"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { Alert, Badge, Button, Card, EmptyState, Field, Input, Select, Skeleton, Textarea } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import { scopeSchema, type ScopeValues } from "@/lib/schemas";
import type { Obj } from "@/types/api";

export function Scope() {
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
                  <div className="mt-0.5 text-xs text-muted">{s.authorization_note} · added {formatDate(s.created_at)}{s.expires_at ? ` · expires ${formatDate(s.expires_at)}` : ""}</div>
                </div>
                {manage && <Button size="sm" variant="ghost" onClick={() => remove.mutate({ id: s.id })}>Remove</Button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      {manage && (
        <Card title="Authorize a target">
          <form noValidate onSubmit={handleSubmit((v) => add.mutate({ ...v, expires_at: v.expires_at ? new Date(`${v.expires_at}T23:59:59`).toISOString() : null }, { onSuccess: () => reset() }))} className="space-y-3">
            {add.error && <Alert tone="critical">{errorMessage(add.error)}</Alert>}
            <Field label="Kind"><Select {...register("kind")}><option value="domain">Domain (includes subdomains)</option><option value="cidr">IP range (CIDR)</option><option value="url">URL prefix</option><option value="path">Local repository path</option></Select></Field>
            <Field label="Value" error={formState.errors.value?.message}><Input {...register("value")} placeholder="example.com" /></Field>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" {...register("allow_active")} /> Allow active testing</label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" {...register("allow_private_network")} /> Target is on a private network</label>
            <Field label="Authorization basis" error={formState.errors.authorization_note?.message} hint="Recorded in the audit log."><Textarea {...register("authorization_note")} placeholder="Owned by <team>; approved under <ticket/contract>." /></Field>
            <Field label="Authorization expires (optional)" hint="After this date engines refuse the target until it is authorized again."><Input type="date" {...register("expires_at")} /></Field>
            <Button type="submit" variant="primary" loading={add.isPending}>Authorize</Button>
          </form>
        </Card>
      )}
    </div>
  );
}
