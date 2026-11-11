"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { Graph } from "@/components/graph";
import { Alert, Badge, Button, Card, ErrorState, KeyValue, PageHeader, SeverityBadge, Skeleton, StatusBadge } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

const edgeTone = { verified: "critical", probable: "high", theoretical: "muted" } as const;

export default function AttackPathDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { data: me } = useMe();
  const { data: p, error, isLoading, refetch } = useGet<Obj>(`/attack-paths/${id}`);
  const explain = useAction<Obj, Obj>("POST", `/analytics/attack-paths/${id}/explain`);
  if (error) return <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />;
  if (isLoading || !p) return <Skeleton className="h-64 w-full" />;
  const nodeId = (position: number) => `n${position}`;
  return (
    <>
      <PageHeader title={p.title} description={p.business_impact}
                  actions={<><SeverityBadge value={p.severity} /><StatusBadge value={p.classification} />{p.involves_ai && <Badge tone="low">Involves AI</Badge>}</>} />
      <div className="space-y-4">
        <Graph
          height={260}
          nodes={p.nodes.map((n: Obj) => ({ id: nodeId(n.position), column: n.position, label: n.label, sub: `${titleCase(n.role)} · ${titleCase(n.type)}`,
                                            tone: n.role === "entry" ? "high" : n.role === "target" ? "critical" : "accent" }))}
          edges={p.edges.map((e: Obj) => ({ id: `e${e.position}`, source: nodeId(e.position), target: nodeId(e.position + 1),
                                            label: `${e.relationship_type}${e.technique ? ` · ${e.technique}` : ""}`, tone: edgeTone[e.evidence_level as keyof typeof edgeTone], dashed: e.evidence_level === "theoretical" }))}
          onNodeClick={(nid) => router.push(`/assets/${p.nodes[Number(nid.slice(1))].asset_id}`)}
        />
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Steps and required conditions" className="lg:col-span-2">
            <ol className="space-y-3">
              {p.edges.map((e: Obj) => {
                const from = p.nodes[e.position], to = p.nodes[e.position + 1];
                return (
                  <li key={e.position} className="rounded-md border border-border p-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="tabular text-xs text-muted">Step {e.position + 1}</span>
                      <Link href={`/assets/${from.asset_id}`} className="font-medium hover:underline">{from.label}</Link>
                      <Badge>{e.relationship_type}</Badge>
                      <Link href={`/assets/${to.asset_id}`} className="font-medium hover:underline">{to.label}</Link>
                      <StatusBadge value={e.evidence_level} />
                      {e.technique && <Badge tone="low">{e.technique}</Badge>}
                      {to.crosses_trust_boundary && <Badge tone="medium">Crosses trust boundary</Badge>}
                    </div>
                    <p className="mt-1.5 text-xs text-muted">{e.condition}</p>
                    {e.enabling_finding && (
                      <p className="mt-1.5 text-xs">Evidence: <Link className="text-accent hover:underline" href={`/findings/${e.enabling_finding.id}`}>{e.enabling_finding.title}</Link> ({e.enabling_finding.severity}, {e.enabling_finding.confidence})</p>
                    )}
                  </li>
                );
              })}
            </ol>
          </Card>
          <div className="space-y-4">
            <Card title="Assessment">
              <KeyValue items={[
                ["Score", <span key="s" className="tabular">{p.score.toFixed(1)}</span>], ["Classification", titleCase(p.classification)],
                ["Confidence", `${Math.round(p.confidence * 100)}%`], ["Entry point", p.nodes[0].label], ["Target", p.nodes[p.nodes.length - 1].label],
                ["Target sensitivity", titleCase(p.nodes[p.nodes.length - 1].data_sensitivity)], ["First seen", formatDate(p.first_seen_at)],
              ]} />
              <p className="mt-3 text-xs text-muted">The classification is that of the weakest step. Verified requires a confirmed high-severity finding and an authoritative relationship on every step.</p>
            </Card>
            <Card title="Where to break this path">
              <ul className="space-y-2 text-sm">
                {p.remediation_opportunities.map((o: Obj, i: number) => (
                  <li key={i}>
                    <Badge tone={o.type === "fix_finding" ? "high" : "low"}>{o.type === "fix_finding" ? "Fix finding" : "Reduce privilege"}</Badge>{" "}
                    {o.finding_id ? <Link href={`/findings/${o.finding_id}`} className="hover:underline">{o.title}</Link> : o.title}
                  </li>
                ))}
              </ul>
            </Card>
            {can(me, "ai_analytics:use") && (
              <Card title="AI-assisted explanation" action={<Button size="sm" loading={explain.isPending} onClick={() => explain.mutate({})}>Generate</Button>}>
                {explain.error && <Alert tone="critical">{errorMessage(explain.error)}</Alert>}
                {explain.data ? <div className="space-y-2 text-sm"><Alert tone="medium">{explain.data.notice}</Alert><p>{explain.data.analysis.summary}</p><p>{explain.data.analysis.why_it_matters}</p></div>
                  : <p className="text-xs text-muted">Advisory summary generated from the recorded steps. Requires an AI provider enabled under Administration.</p>}
              </Card>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
