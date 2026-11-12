"use client";

import { type FormEvent } from "react";
import { Alert, Button, Dialog, Field, Input, Select, Skeleton, Textarea } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { titleCase } from "@/lib/format";
import { useAction, useGet } from "@/lib/hooks";
import type { Obj } from "@/types/api";

const dateInput = (value: string | null | undefined) => (value ? new Date(value).toISOString().slice(0, 10) : "");
const endOfDay = (value: string) => (value ? new Date(`${value}T23:59:59`).toISOString() : null);

/** Create a remediation task for a finding, or edit an existing task's assignment. */
export function TaskDialog({ finding, task, onClose, onSaved }: { finding?: Obj; task?: Obj; onClose: () => void; onSaved?: (task: Obj) => void }) {
  const { data: directory } = useGet<Obj>("/admin/directory");
  const create = useAction<Obj, Obj>("POST", "/remediation/tasks");
  const update = useAction<Obj, Obj>("PATCH", `/remediation/tasks/${task?.id}`);
  const action = task ? update : create;
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>;
    const body: Obj = { instructions: form.instructions, assignee_user_id: form.assignee_user_id || null, team_id: form.team_id || null };
    // Empty title, priority or due date on a new task take the server's defaults from the finding.
    if (form.title.trim()) body.title = form.title.trim();
    if (form.priority) body.priority = form.priority;
    if (form.due_at || task) body.due_at = endOfDay(form.due_at);
    if (!task) body.finding_id = finding?.id;
    action.mutate(body, { onSuccess: (saved) => { onSaved?.(saved); onClose(); } });
  };
  const source = task ?? {};
  return (
    <Dialog open onClose={onClose} title={task ? "Edit remediation task" : "Create remediation task"} wide>
      {!directory ? <Skeleton className="h-48" /> : (
      <form onSubmit={submit} className="space-y-3">
        {action.error && <Alert tone="critical">{errorMessage(action.error)}</Alert>}
        <Field label="Title"><Input name="title" minLength={3} maxLength={512} required={!!task} defaultValue={source.title ?? ""} placeholder={finding ? `Remediate: ${finding.title}` : undefined} /></Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Assignee">
            <Select name="assignee_user_id" defaultValue={source.assignee_user_id ?? finding?.owner_user_id ?? ""}>
              <option value="">Unassigned</option>
              {(directory?.users ?? []).map((u: Obj) => <option key={u.id} value={u.id}>{u.full_name} ({u.email})</option>)}
            </Select>
          </Field>
          <Field label="Team">
            <Select name="team_id" defaultValue={source.team_id ?? finding?.owner_team_id ?? ""}>
              <option value="">No team</option>
              {(directory?.teams ?? []).map((t: Obj) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </Select>
          </Field>
          <Field label="Priority" hint={task ? undefined : "Defaults to the finding's risk level."}>
            <Select name="priority" defaultValue={source.priority ?? ""}>
              {!task && <option value="">From risk ({titleCase(finding?.risk_level ?? "unknown")})</option>}
              {["critical", "high", "medium", "low"].map((p) => <option key={p} value={p}>{titleCase(p)}</option>)}
            </Select>
          </Field>
          <Field label="Due" hint={task ? undefined : "Defaults to the finding's SLA due date."}>
            <Input type="date" name="due_at" defaultValue={dateInput(source.due_at ?? finding?.due_at)} />
          </Field>
        </div>
        <Field label="Instructions" hint="What to change and how to confirm it. The finding's remediation guidance is included automatically when left empty.">
          <Textarea name="instructions" rows={5} maxLength={20000} defaultValue={source.instructions ?? ""} />
        </Field>
        <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>Cancel</Button><Button type="submit" variant="primary" loading={action.isPending}>{task ? "Save" : "Create task"}</Button></div>
      </form>
      )}
    </Dialog>
  );
}
