"use client";

import Link from "next/link";
import { useState } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Card, Dialog, ErrorState, Field, Input, PageHeader, Select, Skeleton, Stat, StatusBadge, Tabs, Textarea } from "@/components/ui";
import { AssessmentsPanel } from "@/features/assessments";
import { FindingsTable } from "@/features/findings-table";
import { errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

const AI_DOMAINS = ["ai_llm", "ai_rag", "ai_agent", "ai_mcp", "ai_model", "ai_infra", "shadow_ai"];

function PostureDialog({ asset, onClose }: { asset: Obj; onClose: () => void }) {
  const { data } = useGet<Obj>(`/ai/assets/${asset.id}`);
  const patch = useAction<Obj>("PATCH", `/ai/assets/${asset.id}`);
  const [tools, setTools] = useState<string | null>(null);
  if (!data) return <Dialog open onClose={onClose} title={asset.name}><Skeleton className="h-32" /></Dialog>;
  const tri = (field: string, label: string, source: Obj | null) => (
    <Field key={field} label={label}>
      <Select value={source?.[field] == null ? "" : String(source[field])} onChange={(e) => patch.mutate({ [field]: e.target.value === "" ? null : e.target.value === "true" })}>
        <option value="">Unknown</option><option value="true">Yes</option><option value="false">No</option>
      </Select>
    </Field>
  );
  const isAgent = data.type === "ai_agent", isRag = ["rag_application", "vector_database"].includes(data.type), isModel = data.type === "ai_model";
  const saveTools = () => {
    try {
      patch.mutate({ tools: JSON.parse(tools ?? "[]") }, { onSuccess: () => setTools(null) });
    } catch {
      patch.reset();
      alert("Tools must be valid JSON: [{\"name\": \"…\", \"capabilities\": [\"payment\"], \"requires_approval\": false}]");
    }
  };
  return (
    <Dialog open onClose={onClose} title={`AI posture: ${data.name}`} wide>
      <div className="space-y-3">
        {patch.error && <Alert tone="critical">{errorMessage(patch.error)}</Alert>}
        <Alert>These attributes are recorded by the owning team and drive the AI posture review and policies. Weakening a control raises a notification.</Alert>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <Field label="Approval">
            <Select value={data.ai?.approval_status ?? "unknown"} onChange={(e) => patch.mutate({ approval_status: e.target.value })}>
              {["unknown", "under_review", "approved", "unapproved"].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}
            </Select>
          </Field>
          {tri("auth_required", "Requires authentication", data.ai)}
          {tri("rate_limited", "Rate limited", data.ai)}
          {tri("processes_sensitive_data", "Processes sensitive data", data.ai)}
          <Field label="Tenant isolation">
            <Select value={data.ai?.tenant_isolation ?? ""} onChange={(e) => patch.mutate({ tenant_isolation: e.target.value || null })}>
              <option value="">Unknown</option><option value="enforced">Enforced</option><option value="not_enforced">Not enforced</option><option value="not_applicable">Not applicable</option>
            </Select>
          </Field>
          {isAgent && (
            <>
              <Field label="Autonomy">
                <Select value={data.agent?.autonomy_level ?? "unknown"} onChange={(e) => patch.mutate({ autonomy_level: e.target.value })}>
                  {["unknown", "human_in_the_loop", "supervised", "autonomous"].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}
                </Select>
              </Field>
              {tri("human_approval_required", "Human approval required", data.agent)}
              {tri("persistent_memory", "Persistent memory", data.agent)}
              {tri("processes_untrusted_input", "Reads untrusted content", data.agent)}
              {tri("can_delegate", "Can delegate to agents", data.agent)}
            </>
          )}
          {isRag && (
            <>
              {tri("document_level_authorization", "Document-level authorization", data.attributes)}
              {tri("ingests_untrusted_content", "Ingests untrusted content", data.attributes)}
              {tri("ingestion_provenance_tracked", "Ingestion provenance tracked", data.attributes)}
              {tri("contains_sensitive_data", "Contains sensitive data", data.attributes)}
            </>
          )}
        </div>
        {isAgent && (
          <Field label={`Tools (${data.agent?.tools?.length ?? 0}; ${data.agent?.unapproved_high_impact_tools ?? 0} high-impact without approval)`}
                 hint="JSON list. Capabilities: shell, code_execution, filesystem_write, database_write, email_send, payment, deploy, iam_admin, delete, external_http, browser, read, search.">
            <Textarea className="font-mono text-xs" rows={6} value={tools ?? JSON.stringify(data.agent?.tools ?? [], null, 2)} onChange={(e) => setTools(e.target.value)} />
          </Field>
        )}
        {isAgent && tools !== null && <Button size="sm" variant="primary" loading={patch.isPending} onClick={saveTools}>Save tools</Button>}
        {isModel && (
          <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); const detail = String(new FormData(e.currentTarget).get("detail")); patch.mutate({ provenance_verified: true, provenance_detail: detail }); }}>
            <Field label={`Provenance: ${data.model?.provenance_verified ? "verified" : "not verified"}`} hint={data.model?.provenance_detail || "Describe the source and how integrity was checked."}>
              <Input name="detail" required minLength={5} placeholder="Digest matches publisher release…" />
            </Field>
            <Button type="submit" size="md">Mark verified</Button>
          </form>
        )}
        {data.mcp && <p className="text-xs text-muted">MCP: {data.mcp.transport} · auth {data.mcp.auth_type} · {data.mcp.tools?.length ?? 0} tools listed{data.mcp.last_probed_at ? ` · probed ${relativeTime(data.mcp.last_probed_at)}` : ""}</p>}
        <p className="text-xs"><Link href={`/assets/${data.id}`} className="text-accent hover:underline">Open asset record</Link></p>
      </div>
    </Dialog>
  );
}

function Governance() {
  const { data: me } = useMe();
  const { data } = useGet<Obj>("/ai/governance");
  const save = useAction<Obj>("PUT", "/ai/governance/approved-providers");
  if (!data) return <Skeleton className="h-24" />;
  const approved: string[] = data.approved_ai_providers;
  const editable = can(me, "ai:write", "risk:configure");
  const toggle = (key: string) => save.mutate({ providers: approved.includes(key) ? approved.filter((p) => p !== key) : [...approved, key] });
  return (
    <Card title="Approved AI providers">
      {save.error && <Alert tone="critical">{errorMessage(save.error)}</Alert>}
      <p className="mb-3 text-xs text-muted">
        {approved.length === 0 ? "No approved list is configured, so provider use is reported as “unknown” rather than unapproved. " : ""}
        {data.visibility_note}
      </p>
      <div className="flex flex-wrap gap-2">
        {data.known_providers.map((p: Obj) => (
          <label key={p.key} className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs">
            <input type="checkbox" disabled={!editable || save.isPending} checked={approved.includes(p.key)} onChange={() => toggle(p.key)} />
            {p.name}
            {data.detected_providers[p.key] ? <Badge tone={approved.includes(p.key) ? "ok" : approved.length ? "high" : "info"}>in use</Badge> : null}
          </label>
        ))}
      </div>
    </Card>
  );
}

export default function AISecurityPage() {
  const { data, error, refetch } = useGet<Obj>("/dashboard/ai", undefined, { refetchInterval: 30_000 });
  const [tab, setTab] = useState<"inventory" | "findings" | "assessments" | "integrations" | "governance">("inventory");
  const [editing, setEditing] = useState<Obj | null>(null);
  if (error) return <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />;
  const f = data?.findings;
  return (
    <>
      <PageHeader title="AI Security" description="Inventory and posture of AI applications, model endpoints, agents, MCP servers, vector stores and models, mapped to OWASP LLM Top 10 (2025), MITRE ATLAS and NIST AI RMF." />
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <Stat label="AI assets discovered" value={data?.assets.total ?? "—"} hint={data ? `${data.assets.without_owner} without owner` : undefined} />
        <Stat label="Public AI endpoints" value={data?.assets.public_endpoints ?? "—"} tone={data?.assets.public_endpoints ? "high" : undefined} />
        <Stat label="Unapproved providers" value={data?.unapproved_providers.length ?? "—"} tone={data?.unapproved_providers.length ? "high" : undefined} />
        <Stat label="Critical LLM findings" value={f?.critical_llm ?? "—"} tone={f?.critical_llm ? "critical" : undefined} />
        <Stat label="Vulnerable AI frameworks" value={f?.vulnerable_ai_frameworks ?? "—"} />
        <Stat label="Agents with excessive permissions" value={f?.agents_excessive_permissions ?? "—"} tone={f?.agents_excessive_permissions ? "high" : undefined} />
        <Stat label="MCP findings" value={f?.mcp ?? "—"} />
        <Stat label="RAG access-control findings" value={f?.rag ?? "—"} />
        <Stat label="Model supply-chain findings" value={f?.model_supply_chain ?? "—"} />
        <Stat label="Shadow AI findings" value={f?.shadow_ai ?? "—"} />
        <Stat label="AI attack paths" value={data?.attack_paths ?? "—"} tone={data?.attack_paths ? "critical" : undefined} />
        <Stat label="AI remediation" value={data ? (data.remediation_status.remediated ?? 0) + (data.remediation_status.closed ?? 0) : "—"} hint={data ? `resolved · ${f.open} open` : undefined} />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "inventory", label: "AI inventory", count: data?.assets.total }, { id: "findings", label: "AI findings", count: f?.open },
        { id: "assessments", label: "Discovery and assessment" }, { id: "integrations", label: "Detected usage", count: data?.assets.integrations_detected }, { id: "governance", label: "Governance" },
      ]} />
      {tab === "inventory" && (
        <DataTable<Obj>
          path="/ai/assets" searchable searchPlaceholder="Search AI assets or providers"
          filters={[
            { key: "type", label: "Type", options: ["ai_application", "llm_endpoint", "ai_agent", "mcp_server", "ai_model", "vector_database", "rag_application", "ai_framework", "ai_provider", "model_registry"] },
            { key: "approval_status", label: "Approval", options: ["approved", "unapproved", "under_review", "unknown"] },
            { key: "exposure", label: "Exposure", options: ["internet", "internal", "private", "unknown"] },
          ]}
          toggles={[{ key: "unowned", label: "Unowned" }]}
          empty={{ title: "No AI assets inventoried", body: "Run a repository analysis, MCP probe or endpoint probe from the Discovery and assessment tab, or register an asset." }}
          columns={[
            { key: "name", header: "AI asset", className: "max-w-sm", render: (a) => <div className="min-w-0"><div className="truncate font-medium">{a.name}</div><div className="truncate font-mono text-xs text-muted">{a.identifier}</div></div> },
            { key: "type", header: "Type", render: (a) => <span className="text-xs">{titleCase(a.type)}</span> },
            { key: "provider", header: "Provider", render: (a) => <span className="text-xs">{a.provider ?? "—"}</span> },
            { key: "approval_status", header: "Approval", render: (a) => <StatusBadge value={a.approval_status} /> },
            { key: "exposure", header: "Exposure", render: (a) => <StatusBadge value={a.exposure} /> },
            { key: "auth", header: "Auth", render: (a) => (a.auth_required == null ? <span className="text-xs text-muted">Unknown</span> : a.auth_required ? <Badge tone="ok">Required</Badge> : <Badge tone="critical">None</Badge>) },
            { key: "owner", header: "Owner", render: (a) => (a.has_owner ? <Badge tone="ok">Assigned</Badge> : <Badge tone="medium">Unowned</Badge>) },
            { key: "open_findings", header: "Findings", render: (a) => <span className="tabular">{a.open_findings}</span> },
            { key: "edit", header: "", render: (a) => <Button size="sm" variant="ghost" onClick={() => setEditing(a)}>Posture</Button> },
          ]}
        />
      )}
      {tab === "findings" && <FindingsTable params={{ domain: AI_DOMAINS }} />}
      {tab === "assessments" && <AssessmentsPanel module="ai_security" />}
      {tab === "integrations" && (
        <DataTable<Obj>
          path="/ai/integrations"
          empty={{ title: "No AI usage detected", body: "Run a repository analysis to detect AI SDKs, endpoints, credentials and configuration." }}
          columns={[
            { key: "provider", header: "Technology", render: (i) => <span className="font-medium">{titleCase(i.provider)}</span> },
            { key: "category", header: "Category", render: (i) => <span className="text-xs">{titleCase(i.category)}</span> },
            { key: "detection_method", header: "Detected by", render: (i) => <Badge>{i.detection_method}</Badge> },
            { key: "location", header: "Location", className: "max-w-md", render: (i) => <span className="block truncate font-mono text-xs">{i.location}</span> },
            { key: "package", header: "Package", render: (i) => <span className="text-xs">{i.package ? `${i.package}${i.version ? ` ${i.version}` : ""}` : "—"}</span> },
            { key: "source_name", header: "Source", render: (i) => <Link href={`/assets/${i.source_asset_id}`} className="text-xs text-accent hover:underline">{i.source_name}</Link> },
          ]}
        />
      )}
      {tab === "governance" && <Governance />}
      {editing && <PostureDialog asset={editing} onClose={() => setEditing(null)} />}
    </>
  );
}
