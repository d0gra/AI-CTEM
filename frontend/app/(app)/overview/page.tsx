"use client";

import Link from "next/link";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Sparkles } from "lucide-react";
import { Alert, Button, Card, EmptyState, ErrorState, PageHeader, SeverityBadge, Skeleton, Stat, StatusBadge } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

const tooltipStyle = { background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12, color: "var(--text)" };

function Briefing() {
  const { data: claude } = useGet<Obj>("/analytics/claude");
  const brief = useAction<Obj, Obj>("POST", "/analytics/briefing");
  if (!claude) return null;
  if (!claude.connected || !claude.in_use) {
    return (
      <Card className="mb-4">
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
          <span className="flex items-center gap-2 text-muted"><Sparkles className="h-4 w-4" aria-hidden /> Connect Claude to get a plain-language executive briefing of this page.</span>
          <Link href="/admin?tab=analytics" className="text-sm text-accent hover:underline">Connect Claude</Link>
        </div>
      </Card>
    );
  }
  const a = brief.data?.analysis;
  return (
    <Card className="mb-4" title={<span className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-accent" aria-hidden /> Executive briefing</span>}
          action={<Button size="sm" loading={brief.isPending} onClick={() => brief.mutate({})}>{a ? "Regenerate" : "Generate"}</Button>}>
      {brief.error && <Alert tone="critical">{errorMessage(brief.error)}</Alert>}
      {!a && !brief.error && <p className="text-sm text-muted">Claude summarises the figures on this page and suggests this week&apos;s priorities. Generated on request; uses your Claude Console credits.</p>}
      {a && (
        <div className="space-y-2 text-sm">
          <p>{a.summary}</p>
          <p className="text-muted">{a.why_it_matters}</p>
          <ol className="list-decimal space-y-0.5 pl-5">{a.recommended_actions.map((x: string) => <li key={x}>{x}</li>)}</ol>
          <p className="text-xs text-muted">AI-generated from the figures above by {brief.data?.model}. Verify against the findings before acting.{a.caveats.length ? ` Caveats: ${a.caveats.join("; ")}` : ""}</p>
        </div>
      )}
    </Card>
  );
}

export default function OverviewPage() {
  const { data: me } = useMe();
  const { data, error, isLoading, refetch } = useGet<Obj>("/dashboard/overview", { trend_days: 30 }, { refetchInterval: 60_000 });
  if (error) return <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />;
  if (isLoading || !data) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {Array.from({ length: 12 }).map((_, i) => <Skeleton key={i} className="h-20" />)}
      </div>
    );
  }
  const cloudOpen = Object.values(data.cloud.open_findings_by_severity as Record<string, number>).reduce((a, b) => a + b, 0);
  const aiOpen = Object.values(data.ai.open_findings_by_risk_level as Record<string, number>).reduce((a, b) => a + b, 0);
  const domains = Object.entries(data.findings.by_domain as Record<string, number>).map(([domain, count]) => ({ domain: titleCase(domain), count })).sort((a, b) => b.count - a.count);
  const empty = data.assets.total === 0;
  return (
    <>
      <PageHeader title="Overview" description={`Exposure across all assets. Computed from live data at ${formatDate(data.generated_at, true)}.`} />
      {!empty && can(me, "ai_analytics:use") && <Briefing />}
      {empty && (
        <Card className="mb-4">
          <EmptyState title="No assets yet">
            Start by recording the targets you are authorized to assess under <Link className="text-accent hover:underline" href="/admin">Administration → Authorized scope</Link>,
            then run a discovery from <Link className="text-accent hover:underline" href="/attack-surface">Attack Surface</Link> or connect a source under{" "}
            <Link className="text-accent hover:underline" href="/integrations">Integrations</Link>.
          </EmptyState>
        </Card>
      )}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Total assets" value={data.assets.total} hint={`${data.assets.unowned} without owner`} />
        <Stat label="Internet-exposed assets" value={data.assets.internet_exposed} tone={data.assets.internet_exposed ? "high" : undefined} />
        <Stat label="Critical findings" value={data.findings.critical} tone={data.findings.critical ? "critical" : undefined} hint={`${data.findings.high} high · ${data.findings.open} open`} />
        <Stat label="High-risk attack paths" value={data.attack_paths.high_risk} tone={data.attack_paths.high_risk ? "critical" : undefined} hint={`${data.attack_paths.active} active`} />
        <Stat label="Exploitable vulnerabilities" value={data.findings.exploitable} hint="Known exploited or public exploit" tone={data.findings.exploitable ? "critical" : undefined} />
        <Stat label="Cloud posture" value={cloudOpen} hint={`open findings · ${data.cloud.accounts} account(s)`} />
        <Stat label="AI security posture" value={aiOpen} hint={`open findings · ${data.ai.assets} AI asset(s)`} />
        <Stat label="Unmanaged AI assets" value={data.ai.unmanaged} hint="Unapproved, unknown or unowned" tone={data.ai.unmanaged ? "high" : undefined} />
        <Stat label="AI agent permission risks" value={data.ai.agent_permission_risks} tone={data.ai.agent_permission_risks ? "high" : undefined} />
        <Stat label="Open remediation tasks" value={data.remediation.open_tasks} hint={`${data.remediation.pending_validation} awaiting retest`} />
        <Stat label="Overdue SLAs" value={data.remediation.overdue_slas} tone={data.remediation.overdue_slas ? "critical" : "ok"} />
        <Stat label="Policy compliance" value={data.compliance.percent == null ? "—" : `${data.compliance.percent}%`} hint={`${data.compliance.non_compliant} non-compliant`} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card title="Risk trend (30 days)" className="lg:col-span-2">
          <div className="h-56" role="img" aria-label="Open findings over the last 30 days">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.trend} margin={{ left: -20, right: 8, top: 4 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} tick={{ fontSize: 11, fill: "var(--muted)" }} stroke="var(--border)" />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "var(--muted)" }} stroke="var(--border)" />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="open_total" name="Open findings" stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.12} />
                <Area type="monotone" dataKey="open_high_risk" name="Critical + high" stroke="var(--critical)" fill="var(--critical)" fillOpacity={0.15} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Open findings by domain">
          {domains.length === 0 ? <EmptyState title="No open findings" /> : (
            <div className="h-56" role="img" aria-label="Open findings by domain">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={domains.slice(0, 8)} layout="vertical" margin={{ left: 30, right: 8 }}>
                  <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: "var(--muted)" }} stroke="var(--border)" />
                  <YAxis type="category" dataKey="domain" width={90} tick={{ fontSize: 11, fill: "var(--muted)" }} stroke="var(--border)" />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-2)" }} />
                  <Bar dataKey="count" name="Open" fill="var(--accent)" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
        <Card title="Highest-risk findings" className="lg:col-span-2">
          {data.top_findings.length === 0 ? <EmptyState title="No open findings" /> : (
            <ul className="divide-y divide-border">
              {data.top_findings.map((f: Obj) => (
                <li key={f.id} className="flex items-center justify-between gap-3 py-2">
                  <div className="min-w-0">
                    <Link href={`/findings/${f.id}`} className="block truncate text-sm font-medium hover:underline">{f.title}</Link>
                    <div className="truncate text-xs text-muted">{f.asset_name} · {titleCase(f.domain)}</div>
                  </div>
                  <div className="flex items-center gap-2"><span className="tabular text-sm font-medium">{f.risk_score.toFixed(0)}</span><SeverityBadge value={f.risk_level} /></div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Recent assessment runs">
          {data.recent_runs.length === 0 ? <EmptyState title="No runs yet" /> : (
            <ul className="divide-y divide-border">
              {data.recent_runs.map((r: Obj) => (
                <li key={r.id} className="flex items-center justify-between gap-2 py-2">
                  <div className="min-w-0">
                    <div className="truncate text-sm">{r.name}</div>
                    <div className="text-xs text-muted">{relativeTime(r.created_at)}{r.dry_run ? " · dry run" : ""}</div>
                  </div>
                  <StatusBadge value={r.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
