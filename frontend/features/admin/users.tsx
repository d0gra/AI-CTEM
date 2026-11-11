"use client";

import { useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Dialog, Field, Input, Select } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export function Users() {
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
