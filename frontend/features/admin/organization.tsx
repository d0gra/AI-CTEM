"use client";

import { type FormEvent } from "react";
import { Alert, Badge, Button, Card, Field, Input, Skeleton } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export function Organization() {
  const { data: me } = useMe();
  const { data: org } = useGet<Obj>("/admin/organization");
  const rename = useAction<Obj>("PATCH", "/admin/organization");
  if (!org) return <Skeleton className="h-24" />;
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    rename.mutate({ name: String(new FormData(e.currentTarget).get("name")) });
  };
  return (
    <Card title="Organization">
      <form onSubmit={submit} className="flex max-w-xl flex-wrap items-end gap-3">
        <Field label="Name"><Input name="name" required minLength={2} defaultValue={org.name} disabled={!can(me, "admin:org")} /></Field>
        {can(me, "admin:org") && <Button type="submit" loading={rename.isPending}>Save</Button>}
      </form>
      {rename.error && <div className="mt-2"><Alert tone="critical">{errorMessage(rename.error)}</Alert></div>}
      {rename.isSuccess && <div className="mt-2"><Alert tone="ok">Saved.</Alert></div>}
      <p className="mt-3 text-xs text-muted">Identifier <span className="font-mono">{org.slug}</span> · created {formatDate(org.created_at)}</p>
    </Card>
  );
}

export function PlatformOrganizations() {
  const { data: me } = useMe();
  const { data, error } = useGet<Obj[]>("/platform/organizations");
  const toggle = useAction<{ id: string; is_active: boolean }, Obj>("PATCH", (b) => `/platform/organizations/${b.id}`);
  if (error) return <Alert tone="critical">{errorMessage(error)}</Alert>;
  if (!data) return <Skeleton className="h-32" />;
  return (
    <Card title={`All organizations (${data.length})`}>
      <p className="mb-3 text-xs text-muted">Platform operators can see each organization&apos;s size and suspend or reinstate it. Suspending signs out every user in that organization. Operators cannot read other organizations&apos; assets, findings or evidence from here.</p>
      {toggle.error && <Alert tone="critical">{errorMessage(toggle.error)}</Alert>}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-muted"><tr>{["Organization", "Users", "Assets", "Findings", "Last sign-in", "Created", "Status", ""].map((h) => <th key={h} className="py-1 pr-3 font-medium">{h}</th>)}</tr></thead>
          <tbody>
            {data.map((o) => (
              <tr key={o.id} className="border-t border-border">
                <td className="py-2 pr-3"><div className="font-medium">{o.name}</div><div className="font-mono text-xs text-muted">{o.slug}</div></td>
                <td className="tabular pr-3">{o.users}</td><td className="tabular pr-3">{o.assets}</td><td className="tabular pr-3">{o.findings}</td>
                <td className="pr-3 text-xs">{relativeTime(o.last_sign_in_at)}</td><td className="pr-3 text-xs">{formatDate(o.created_at)}</td>
                <td className="pr-3">{o.is_active ? <Badge tone="ok">Active</Badge> : <Badge tone="critical">Suspended</Badge>}</td>
                <td className="text-right">{o.id !== me?.organization_id && (
                  <Button size="sm" variant={o.is_active ? "ghost" : "secondary"} loading={toggle.isPending && toggle.variables?.id === o.id}
                          onClick={() => (o.is_active ? window.confirm(`Suspend ${o.name}? All of its users will be signed out.`) : true) && toggle.mutate({ id: o.id, is_active: !o.is_active })}>
                    {o.is_active ? "Suspend" : "Reinstate"}
                  </Button>)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
