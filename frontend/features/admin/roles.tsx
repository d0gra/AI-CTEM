"use client";

import { useState, type FormEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, Field, Input, Skeleton } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export function Roles() {
  const { data: me } = useMe();
  const { data: roles } = useGet<Obj[]>("/admin/roles");
  const { data: catalog } = useGet<Record<string, string>>(can(me, "admin:users") ? "/admin/permissions" : null);
  const create = useAction<Obj>("POST", "/admin/roles");
  const update = useAction<{ id: string } & Obj, Obj>("PATCH", (b) => `/admin/roles/${b.id}`);
  const remove = useAction<{ id: string }, Obj>("DELETE", (b) => `/admin/roles/${b.id}`);
  const [editing, setEditing] = useState<Obj | null>(null);
  const manage = can(me, "admin:users");
  if (!roles) return <Skeleton className="h-40" />;
  const groups = Object.keys(catalog ?? {}).reduce<Record<string, string[]>>((acc, key) => {
    (acc[key.split(":")[0]] ??= []).push(key);
    return acc;
  }, {});
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const permissions = form.getAll("permissions").map(String);
    const done = { onSuccess: () => setEditing(null) };
    if (editing?.id) update.mutate({ id: editing.id, name: String(form.get("name")), permissions }, done);
    else create.mutate({ key: String(form.get("key")), name: String(form.get("name")), permissions }, done);
  };
  return (
    <div className="space-y-4">
      {remove.error && <Alert tone="critical">{errorMessage(remove.error)}</Alert>}
      {manage && <div className="text-right"><Button variant="primary" onClick={() => setEditing({ key: "", name: "", permissions: [] })}>New custom role</Button></div>}
      <div className="grid gap-4 lg:grid-cols-2">
        {roles.map((r) => (
          <Card key={r.id} title={<span className="flex items-center gap-2">{r.name}{r.is_builtin ? <Badge>Built-in</Badge> : <Badge tone="low">Custom</Badge>}</span>}
                action={manage && !r.is_builtin && (
                  <div className="flex gap-1">
                    <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>Edit</Button>
                    <Button size="sm" variant="ghost" onClick={() => window.confirm(`Delete role “${r.name}”?`) && remove.mutate({ id: r.id })}>Delete</Button>
                  </div>)}>
            <div className="flex flex-wrap gap-1">{r.permissions.map((p: string) => <span key={p} title={catalog?.[p]} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]">{p}</span>)}</div>
          </Card>
        ))}
      </div>
      <Dialog open={!!editing} onClose={() => setEditing(null)} title={editing?.id ? `Edit ${editing.name}` : "New custom role"} wide>
        {editing && (
          <form onSubmit={submit} className="space-y-3">
            {(create.error || update.error) && <Alert tone="critical">{errorMessage(create.error ?? update.error)}</Alert>}
            <div className="grid gap-3 sm:grid-cols-2">
              {!editing.id && <Field label="Key" hint="Lowercase letters, digits and underscores."><Input name="key" required pattern="[a-z][a-z0-9_]{2,62}" /></Field>}
              <Field label="Name"><Input name="name" required minLength={2} defaultValue={editing.name} /></Field>
            </div>
            <Alert>You can only grant permissions that your own role holds.</Alert>
            <div className="grid gap-3 sm:grid-cols-2">
              {Object.entries(groups).map(([group, keys]) => (
                <fieldset key={group} className="rounded-md border border-border p-2">
                  <legend className="px-1 text-xs font-medium text-muted">{group.replace(/_/g, " ")}</legend>
                  {keys.map((key) => (
                    <label key={key} className="flex items-start gap-2 text-xs">
                      <input type="checkbox" name="permissions" value={key} className="mt-0.5" defaultChecked={editing.permissions.includes(key)} disabled={!me?.permissions.includes(key)} />
                      <span><span className="font-mono">{key}</span> <span className="text-muted">{catalog?.[key]}</span></span>
                    </label>
                  ))}
                </fieldset>
              ))}
            </div>
            <div className="flex justify-end gap-2"><Button type="button" onClick={() => setEditing(null)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending || update.isPending}>Save</Button></div>
          </form>
        )}
      </Dialog>
    </div>
  );
}
