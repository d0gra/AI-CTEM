"use client";

import { useState, type FormEvent } from "react";
import { Alert, Button, Card, Dialog, EmptyState, Field, Input, Skeleton, Textarea } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { useAction, useGet } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export function Teams() {
  const { data: teams } = useGet<Obj[]>("/admin/teams");
  const { data: directory } = useGet<Obj>("/admin/directory");
  const create = useAction<Obj>("POST", "/admin/teams");
  const update = useAction<{ id: string } & Obj, Obj>("PUT", (b) => `/admin/teams/${b.id}`);
  const remove = useAction<{ id: string }, Obj>("DELETE", (b) => `/admin/teams/${b.id}`);
  const [editing, setEditing] = useState<Obj | null>(null);
  const users: Obj[] = directory?.users ?? [];
  const nameOf = (id: string) => users.find((u) => u.id === id)?.full_name ?? "Unknown user";
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const body = { name: String(form.get("name")), description: String(form.get("description") ?? ""), business_unit: String(form.get("business_unit") ?? "") || null,
                   member_ids: form.getAll("member_ids").map(String) };
    const done = { onSuccess: () => setEditing(null) };
    if (editing?.id) update.mutate({ id: editing.id, ...body }, done);
    else create.mutate(body, done);
  };
  const error = create.error ?? update.error ?? remove.error;
  return (
    <Card title="Teams" action={<Button size="sm" variant="primary" onClick={() => setEditing({ name: "", description: "", business_unit: "", member_ids: [] })}>New team</Button>}>
      <p className="mb-3 text-xs text-muted">Teams own assets and findings and receive remediation tasks.</p>
      {error && !editing && <Alert tone="critical">{errorMessage(error)}</Alert>}
      {!teams ? <Skeleton className="h-20" /> : teams.length === 0 ? <EmptyState title="No teams">Create teams to assign ownership of assets and findings.</EmptyState> : (
        <ul className="divide-y divide-border">
          {teams.map((t) => (
            <li key={t.id} className="flex items-start justify-between gap-3 py-2">
              <div className="min-w-0">
                <div className="text-sm font-medium">{t.name}{t.business_unit && <span className="ml-2 text-xs font-normal text-muted">{t.business_unit}</span>}</div>
                {t.description && <div className="text-xs text-muted">{t.description}</div>}
                <div className="mt-0.5 text-xs text-muted">{t.member_ids.length ? t.member_ids.map(nameOf).join(", ") : "No members"}</div>
              </div>
              <div className="flex gap-1">
                <Button size="sm" variant="ghost" onClick={() => setEditing(t)}>Edit</Button>
                <Button size="sm" variant="ghost" onClick={() => window.confirm(`Delete team “${t.name}”? Assets and findings it owns become unassigned.`) && remove.mutate({ id: t.id })}>Delete</Button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <Dialog open={!!editing} onClose={() => setEditing(null)} title={editing?.id ? `Edit ${editing.name}` : "New team"}>
        {editing && (
          <form onSubmit={submit} className="space-y-3">
            {(create.error || update.error) && <Alert tone="critical">{errorMessage(create.error ?? update.error)}</Alert>}
            <Field label="Name"><Input name="name" required defaultValue={editing.name} /></Field>
            <Field label="Business unit"><Input name="business_unit" defaultValue={editing.business_unit ?? ""} /></Field>
            <Field label="Description"><Textarea name="description" defaultValue={editing.description} /></Field>
            <fieldset className="max-h-48 space-y-1 overflow-y-auto rounded-md border border-border p-2">
              <legend className="px-1 text-xs font-medium text-muted">Members</legend>
              {users.map((u) => (
                <label key={u.id} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" name="member_ids" value={u.id} defaultChecked={editing.member_ids.includes(u.id)} /> {u.full_name} <span className="text-xs text-muted">{u.email}</span>
                </label>
              ))}
            </fieldset>
            <div className="flex justify-end gap-2"><Button type="button" onClick={() => setEditing(null)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending || update.isPending}>Save</Button></div>
          </form>
        )}
      </Dialog>
    </Card>
  );
}
