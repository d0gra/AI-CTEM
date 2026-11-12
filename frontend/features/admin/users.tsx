"use client";

import { useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Dialog, Field, Input, Select } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";
import { CopyButton } from "@/features/ci";

export function Users() {
  const { data: me } = useMe();
  const { data: roles } = useGet<Obj[]>("/admin/roles");
  const create = useAction<Obj, Obj>("POST", "/admin/users");
  const reinvite = useAction<{ id: string; email: string }, Obj>("POST", (b) => `/admin/users/${b.id}/invite`);
  const [invite, setInvite] = useState<{ email: string; link: string } | null>(null);
  const update = useAction<{ id: string } & Obj, Obj>("PATCH", (b) => `/admin/users/${b.id}`);
  const [open, setOpen] = useState(false);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    create.mutate(Object.fromEntries(new FormData(e.currentTarget)) as Obj, {
      onSuccess: (user) => { setOpen(false); if (user.invite_link) setInvite({ email: user.email, link: user.invite_link }); },
    });
  };
  return (
    <>
      {(update.error || reinvite.error) && <div className="mb-3"><Alert tone="critical">{errorMessage(update.error ?? reinvite.error)}</Alert></div>}
      <div className="mb-3 text-right"><Button variant="primary" onClick={() => { create.reset(); setOpen(true); }}>Invite user</Button></div>
      <DataTable<Obj>
        path="/admin/users"
        columns={[
          { key: "full_name", header: "User", render: (u) => <div><div className="font-medium">{u.full_name}</div><div className="text-xs text-muted">{u.email}</div></div> },
          { key: "role", header: "Role", render: (u) => u.id === me?.id ? <span className="text-xs">{titleCase(u.role_key)} (you)</span> : (
            <Select aria-label={`Role for ${u.email}`} className="w-52" value={u.role_id} onChange={(e) => update.mutate({ id: u.id, role_id: e.target.value })}>{(roles ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</Select>) },
          { key: "mfa", header: "MFA", render: (u) => (u.mfa_enabled ? <Badge tone="ok">Enabled</Badge> : <Badge tone="medium">Not enrolled</Badge>) },
          { key: "verified", header: "Email", render: (u) => (u.email_verified_at ? <Badge tone="ok">Verified</Badge> : <Badge>Unverified</Badge>) },
          { key: "last_login_at", header: "Last sign-in", render: (u) => <span className="text-xs">{relativeTime(u.last_login_at)}</span> },
          { key: "active", header: "", render: (u) => u.id !== me?.id && (
            <div className="flex justify-end gap-1">
              {u.is_active && !u.last_login_at && (
                <Button size="sm" variant="ghost" loading={reinvite.isPending && reinvite.variables?.id === u.id}
                        onClick={() => reinvite.mutate({ id: u.id, email: u.email }, { onSuccess: (r) => setInvite({ email: u.email, link: r.invite_link }) })}>
                  New invite link
                </Button>
              )}
              <Button size="sm" variant="ghost" onClick={() => update.mutate({ id: u.id, is_active: !u.is_active })}>{u.is_active ? "Deactivate" : "Reactivate"}</Button>
            </div>) },
        ]}
      />
      <Dialog open={open} onClose={() => setOpen(false)} title="Add user">
        <form onSubmit={submit} className="space-y-3">
          {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
          <Field label="Full name"><Input name="full_name" required /></Field>
          <Field label="Email"><Input name="email" type="email" required /></Field>
          <Field label="Role" hint="You can only assign roles whose permissions you hold yourself."><Select name="role_id" required>{(roles ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</Select></Field>
          <p className="text-xs text-muted">
            The user chooses their own password from an invitation link that is valid for 7 days.
            {me?.email_delivery_configured ? " The link is emailed to them and also shown to you once." : " Email delivery is not configured, so share the link shown next through a channel you trust."}
          </p>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Invite user</Button></div>
        </form>
      </Dialog>
      <Dialog open={!!invite} onClose={() => setInvite(null)} title="Invitation link">
        {invite && (
          <div className="space-y-3">
            <Alert tone="medium">Anyone with this link can set the password for {invite.email} until it is used or expires in 7 days. Issuing a new link invalidates this one.</Alert>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded-md bg-surface-2 px-3 py-2 font-mono text-xs">{invite.link}</code>
              <CopyButton text={invite.link} />
            </div>
            <div className="flex justify-end"><Button variant="primary" onClick={() => setInvite(null)}>Done</Button></div>
          </div>
        )}
      </Dialog>
    </>
  );
}
