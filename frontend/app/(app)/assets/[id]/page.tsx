"use client";

import { useParams, useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Graph } from "@/components/graph";
import { Alert, Badge, Button, Card, Dialog, EmptyState, ErrorState, Field, JsonBlock, KeyValue, PageHeader, Select, Skeleton, StatusBadge, Tabs } from "@/components/ui";
import { FindingsTable } from "@/features/findings-table";
import { errorMessage } from "@/lib/api";
import { formatDate, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { data: me } = useMe();
  const { data: a, error, isLoading, refetch } = useGet<Obj>(`/assets/${id}`);
  const { data: graph } = useGet<Obj>("/asset-graph", { root: id, depth: 2 });
  const { data: rels } = useGet<Obj[]>(`/assets/${id}/relationships`);
  const { data: history } = useGet<Obj>(`/assets/${id}/history`, { page_size: 50 });
  const { data: directory } = useGet<Obj>("/admin/directory");
  const { data: facets } = useGet<Obj>("/assets/facets");
  const patch = useAction<Obj>("PATCH", `/assets/${id}`);
  const link = useAction<Obj>("POST", "/asset-relationships");
  const unlink = useAction<{ id: string }, Obj>("DELETE", (b) => `/asset-relationships/${b.id}`);
  const [tab, setTab] = useState<"findings" | "relationships" | "history" | "attributes">("findings");
  const [linking, setLinking] = useState(false);
  const [target, setTarget] = useState("");
  const { data: candidates } = useGet<Obj>(linking && target.length > 1 ? "/assets" : null, { q: target, page_size: 8 });

  if (error) return <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />;
  if (isLoading || !a) return <Skeleton className="h-64 w-full" />;
  const editable = can(me, "assets:write");
  const set = (field: string) => (e: React.ChangeEvent<HTMLSelectElement>) => patch.mutate({ [field]: e.target.value || null });
  const addLink = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = Object.fromEntries(new FormData(e.currentTarget)) as Obj;
    const [source, dest] = form.direction === "out" ? [id, form.other] : [form.other, id];
    link.mutate({ source_asset_id: source, target_asset_id: dest, type: form.type, note: form.note }, { onSuccess: () => setLinking(false) });
  };
  const special = a.agent ?? a.mcp ?? a.model ?? a.ai;

  return (
    <>
      <PageHeader
        title={a.name}
        description={<span className="font-mono text-xs">{a.identifier}</span>}
        actions={<><Badge>{titleCase(a.type)}</Badge><StatusBadge value={a.exposure} /><Badge tone={a.risk_score >= 75 ? "critical" : a.risk_score >= 50 ? "high" : "info"}>Risk {a.risk_score.toFixed(0)}</Badge></>}
      />
      {patch.error && <div className="mb-3"><Alert tone="critical">{errorMessage(patch.error)}</Alert></div>}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Classification and ownership">
          <div className="grid grid-cols-2 gap-3">
            {([["exposure", ["unknown", "internet", "internal", "private"]], ["criticality", ["critical", "high", "medium", "low"]], ["environment", ["unknown", "production", "staging", "development", "test"]], ["data_sensitivity", ["unknown", "public", "internal", "confidential", "restricted"]]] as [string, string[]][]).map(([field, options]) => (
              <Field key={field} label={titleCase(field)}>
                <Select disabled={!editable} value={a[field]} onChange={set(field)}>{options.map((o) => <option key={o} value={o}>{titleCase(o)}</option>)}</Select>
              </Field>
            ))}
            <Field label="Owner">
              <Select disabled={!editable} value={a.owner_user_id ?? ""} onChange={set("owner_user_id")}><option value="">Unassigned</option>{(directory?.users ?? []).map((u: Obj) => <option key={u.id} value={u.id}>{u.full_name}</option>)}</Select>
            </Field>
            <Field label="Team">
              <Select disabled={!editable} value={a.owner_team_id ?? ""} onChange={set("owner_team_id")}><option value="">No team</option>{(directory?.teams ?? []).map((t: Obj) => <option key={t.id} value={t.id}>{t.name}</option>)}</Select>
            </Field>
          </div>
          <form className="mt-3 grid grid-cols-2 gap-3" onSubmit={(e) => {
            e.preventDefault();
            const form = new FormData(e.currentTarget);
            patch.mutate({ business_unit: String(form.get("business_unit") || "") || null,
                           tags: String(form.get("tags") || "").split(",").map((t) => t.trim()).filter(Boolean) });
          }}>
            <Field label="Business unit"><input name="business_unit" disabled={!editable} defaultValue={a.business_unit ?? ""} className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm" /></Field>
            <Field label="Tags" hint="Comma-separated"><input name="tags" disabled={!editable} defaultValue={a.tags.join(", ")} className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm" /></Field>
            {editable && <div className="col-span-2"><Button size="sm" type="submit" loading={patch.isPending}>Save labels</Button></div>}
          </form>
          <p className="mt-3 text-xs text-muted">Changing exposure, criticality or sensitivity rescores this asset&apos;s findings. Discovery never lowers exposure or overwrites analyst classification.</p>
        </Card>
        <Card title="Provenance">
          <KeyValue items={[
            ["Discovered by", a.discovery_sources.join(", ") || "—"], ["First seen", formatDate(a.first_seen_at, true)], ["Last seen", formatDate(a.last_seen_at, true)],
            ["Status", titleCase(a.status)], ["Open findings", Object.entries(a.findings_by_severity).map(([k, v]) => `${v} ${k}`).join(", ") || "None"],
            ["Business unit", a.business_unit ?? "—"], ["Tags", a.tags.join(", ") || "—"],
          ]} />
        </Card>
        <Card title="Relationship graph">
          {graph && graph.nodes.length > 1 ? (
            <Graph height={230} rootId={id} onNodeClick={(nodeId) => nodeId !== id && router.push(`/assets/${nodeId}`)}
                   nodes={graph.nodes.map((n: Obj) => ({ id: n.id, label: n.name, sub: titleCase(n.type), tone: n.id === id ? "accent" : n.exposure === "internet" ? "high" : "muted" }))}
                   edges={graph.edges.map((e: Obj) => ({ id: e.id, source: e.source, target: e.target, label: e.type, dashed: e.confidence < 0.9 }))} />
          ) : <EmptyState title="No relationships recorded" />}
        </Card>
      </div>
      <div className="mt-4">
        <Tabs value={tab} onChange={setTab} tabs={[
          { id: "findings", label: "Findings", count: a.open_findings }, { id: "relationships", label: "Relationships", count: rels?.length },
          { id: "history", label: "History", count: history?.total }, { id: "attributes", label: special ? "Attributes and AI posture" : "Attributes" },
        ]} />
        {tab === "findings" && <FindingsTable params={{ asset_id: id }} />}
        {tab === "relationships" && (
          <Card action={editable && <Button size="sm" onClick={() => setLinking(true)}>Add relationship</Button>}>
            {!rels?.length ? <EmptyState title="No relationships">Relationships are created by discovery engines or recorded manually. They are the edges used for attack path analysis.</EmptyState> : (
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-muted"><tr><th className="py-1 font-medium">Source</th><th className="font-medium">Relationship</th><th className="font-medium">Target</th><th className="font-medium">Provenance</th><th className="font-medium">Confidence</th><th /></tr></thead>
                <tbody>{rels.map((r) => (
                  <tr key={r.id} className="border-t border-border">
                    <td className="py-1.5">{r.source.name}</td><td><Badge>{r.type}</Badge></td><td>{r.target.name}</td>
                    <td className="text-xs text-muted">{r.provenance}</td><td className="tabular text-xs">{Math.round(r.confidence * 100)}%</td>
                    <td className="text-right">{editable && <Button size="sm" variant="ghost" onClick={() => window.confirm("Remove this relationship? Attack paths through it disappear at the next computation.") && unlink.mutate({ id: r.id })}>Remove</Button>}</td>
                  </tr>))}</tbody>
              </table>
            )}
          </Card>
        )}
        {tab === "history" && (
          <Card>
            {!history?.items.length ? <EmptyState title="No history" /> : (
              <ol className="space-y-2 text-sm">{history.items.map((e: Obj) => (
                <li key={e.id}><span className="font-medium">{titleCase(e.event_type)}</span><span className="text-muted"> · {e.source} · {formatDate(e.occurred_at, true)}</span>
                  {Object.keys(e.details).length > 0 && <pre className="mt-1 overflow-x-auto rounded bg-surface-2 p-2 font-mono text-xs">{JSON.stringify(e.details)}</pre>}</li>))}</ol>
            )}
          </Card>
        )}
        {tab === "attributes" && (
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Discovered attributes"><JsonBlock value={a.attributes} /></Card>
            {special && <Card title="AI posture"><JsonBlock value={{ ai: a.ai, agent: a.agent, mcp: a.mcp, model: a.model }} /></Card>}
          </div>
        )}
      </div>
      <Dialog open={linking} onClose={() => setLinking(false)} title="Add relationship">
        <form onSubmit={addLink} className="space-y-3">
          {link.error && <Alert tone="critical">{errorMessage(link.error)}</Alert>}
          <Alert>Manually asserted relationships are recorded with 80% confidence, which caps any attack path through them at &quot;probable&quot;.</Alert>
          <Field label="Direction"><Select name="direction"><option value="out">This asset → other asset</option><option value="in">Other asset → this asset</option></Select></Field>
          <Field label="Relationship"><Select name="type">{(facets?.relationship_types ?? []).map((t: string) => <option key={t}>{t}</option>)}</Select></Field>
          <Field label="Other asset" hint="Type to search, then choose.">
            <input className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Search assets" />
          </Field>
          <Select name="other" required size={Math.min(5, Math.max(2, candidates?.items.length ?? 2))} className="h-auto">
            {(candidates?.items ?? []).filter((c: Obj) => c.id !== id).map((c: Obj) => <option key={c.id} value={c.id}>{c.name} ({titleCase(c.type)})</option>)}
          </Select>
          <Field label="Basis for this relationship"><input name="note" required minLength={3} className="h-9 w-full rounded-md border border-border bg-surface px-3 text-sm" /></Field>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setLinking(false)}>Cancel</Button><Button type="submit" variant="primary" loading={link.isPending}>Add</Button></div>
        </form>
      </Dialog>
    </>
  );
}
