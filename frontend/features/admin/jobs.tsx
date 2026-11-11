"use client";

import { useState } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Button, Dialog, JsonBlock, StatusBadge } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export function Jobs() {
  const { data: me } = useMe();
  const cancel = useAction<{ id: string }, Obj>("POST", (b) => `/jobs/${b.id}/cancel`);
  const [selected, setSelected] = useState<Obj | null>(null);
  return (
    <>
      <p className="mb-3 text-xs text-muted">Background work for this organization: assessments, imports, reports, notification delivery, risk recalculation and scheduled maintenance. Failed jobs that exhausted their retries are shown as dead.</p>
      {cancel.error && <div className="mb-3"><Alert tone="critical">{errorMessage(cancel.error)}</Alert></div>}
      <DataTable<Obj>
        path="/jobs" refetchInterval={5000}
        filters={[{ key: "state", label: "State", options: ["queued", "running", "succeeded", "failed", "dead", "cancelled"] }]}
        empty={{ title: "No jobs" }}
        columns={[
          { key: "type", header: "Job", render: (j) => <span className="font-mono text-xs">{j.type}</span> },
          { key: "state", header: "State", render: (j) => <StatusBadge value={j.state} /> },
          { key: "progress", header: "Progress", render: (j) => <span className="text-xs">{j.state === "running" ? `${j.progress}% ${j.progress_message}` : j.progress_message || "—"}</span> },
          { key: "attempts", header: "Attempts", render: (j) => <span className="tabular text-xs">{j.attempts}/{j.max_attempts}</span> },
          { key: "created_at", header: "Queued", render: (j) => <span className="text-xs text-muted">{relativeTime(j.created_at)}</span> },
          { key: "error", header: "Error", className: "max-w-xs", render: (j) => <span className="block truncate text-xs text-critical" title={j.error ?? ""}>{j.error?.split("\n")[0]}</span> },
          { key: "actions", header: "", render: (j) => (
            <div className="flex gap-1">
              <Button size="sm" variant="ghost" onClick={() => setSelected(j)}>Details</Button>
              {can(me, "assessments:run") && ["queued", "running"].includes(j.state) && !j.cancel_requested && <Button size="sm" variant="ghost" onClick={() => cancel.mutate({ id: j.id })}>Cancel</Button>}
            </div>) },
        ]}
      />
      <Dialog open={!!selected} onClose={() => setSelected(null)} title={selected ? titleCase(selected.type) : ""} wide>
        {selected && (
          <div className="space-y-2 text-xs">
            <p>Started {formatDate(selected.started_at, true)} · finished {formatDate(selected.finished_at, true)}</p>
            {selected.error && <pre className="max-h-60 overflow-auto whitespace-pre-wrap rounded bg-surface-2 p-2 font-mono text-critical">{selected.error}</pre>}
            <JsonBlock value={selected.result} />
          </div>
        )}
      </Dialog>
    </>
  );
}
