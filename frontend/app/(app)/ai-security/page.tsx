"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Plus, Trash2 } from "lucide-react";
import { Suspense, useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Card, Dialog, ErrorState, Field, Input, PageHeader, Select, Skeleton, Stat, StatusBadge, Tabs } from "@/components/ui";
import { AssessmentsPanel } from "@/features/assessments";
import { FindingsTable } from "@/features/findings-table";
import { errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

const AI_DOMAINS = ["ai_llm", "ai_rag", "ai_agent", "ai_mcp", "ai_model", "ai_infra", "shadow_ai"];
const AI_TYPES = ["ai_application", "llm_endpoint", "rag_application", "ai_agent", "mcp_server", "vector_database", "ai_model", "model_registry", "ai_framework", "ai_provider"];
const TYPE_HINT: Record<string, string> = {
  ai_application: "A product feature or service that calls a model.", llm_endpoint: "An inference API, gateway or self-hosted model server.",
  rag_application: "An application that retrieves documents into prompts.", ai_agent: "Software that lets a model choose and call tools.",
  mcp_server: "A Model Context Protocol server exposing tools or resources.", vector_database: "A vector store backing retrieval.",
  ai_model: "Model weights you host or fine-tune.", model_registry: "Where model artefacts are stored and promoted.",
  ai_framework: "A library such as LangChain or LlamaIndex.", ai_provider: "A hosted model provider account.",
};
const CAPABILITIES: { key: string; label: string; high: boolean }[] = [
  { key: "read", label: "Read data", high: false }, { key: "search", label: "Search", high: false },
  { key: "external_http", label: "Outbound HTTP", high: true }, { key: "browser", label: "Browser", high: true },
  { key: "filesystem_write", label: "Write files", high: true }, { key: "database_write", label: "Write database", high: true },
  { key: "delete", label: "Delete", high: true }, { key: "email_send", label: "Send email", high: true },
  { key: "payment", label: "Payments", high: true }, { key: "deploy", label: "Deploy", high: true },
  { key: "iam_admin", label: "IAM admin", high: true }, { key: "shell", label: "Shell", high: true },
  { key: "code_execution", label: "Run code", high: true },
];

type Tool = { name: string; description: string; capabilities: string[]; requires_approval: boolean };

function ToolsEditor({ initial, saving, onSave }: { initial: Tool[]; saving: boolean; onSave: (tools: Tool[]) => void }) {
  const [tools, setTools] = useState<Tool[]>(initial);
  const [dirty, setDirty] = useState(false);
  const change = (i: number, next: Partial<Tool>) => { setTools(tools.map((t, j) => (j === i ? { ...t, ...next } : t))); setDirty(true); };
  const highImpact = (t: Tool) => t.capabilities.some((c) => CAPABILITIES.find((x) => x.key === c)?.high);
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted">Tools the agent can call ({tools.length})</span>
        <Button size="sm" type="button" onClick={() => { setTools([...tools, { name: "", description: "", capabilities: [], requires_approval: false }]); setDirty(true); }}><Plus className="h-3.5 w-3.5" /> Add tool</Button>
      </div>
      {tools.length === 0 && <p className="text-xs text-muted">No tools recorded. Agents with no recorded tools cannot be checked for excessive agency.</p>}
      {tools.map((t, i) => (
        <div key={i} className="space-y-2 rounded-md border border-border p-3">
          <div className="flex gap-2">
            <Input aria-label="Tool name" placeholder="Tool name, e.g. refund_order" value={t.name} onChange={(e) => change(i, { name: e.target.value })} className="font-mono text-xs" />
            <Button size="md" type="button" variant="ghost" aria-label={`Remove ${t.name || "tool"}`} onClick={() => { setTools(tools.filter((_, j) => j !== i)); setDirty(true); }}><Trash2 className="h-4 w-4" /></Button>
          </div>
          <Input aria-label="Tool description" placeholder="What it does (optional)" value={t.description} onChange={(e) => change(i, { description: e.target.value })} />
          <div className="flex flex-wrap gap-1.5">
            {CAPABILITIES.map((c) => (
              <label key={c.key} className="flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[11px]">
                <input type="checkbox" checked={t.capabilities.includes(c.key)}
                       onChange={(e) => change(i, { capabilities: e.target.checked ? [...t.capabilities, c.key] : t.capabilities.filter((x) => x !== c.key) })} />
                {c.label}{c.high && <span className="text-high">*</span>}
              </label>
            ))}
          </div>
          <label className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={t.requires_approval} onChange={(e) => change(i, { requires_approval: e.target.checked })} />
            A person approves each call
            {highImpact(t) && !t.requires_approval && <Badge tone="high">High impact without approval</Badge>}
          </label>
        </div>
      ))}
      <div className="flex items-center justify-between">
        <span className="text-[11px] text-muted"><span className="text-high">*</span> high-impact capability</span>
        {dirty && <Button size="sm" variant="primary" loading={saving} disabled={tools.some((t) => !t.name.trim())}
                          onClick={() => onSave(tools.map((t) => ({ ...t, name: t.name.trim() })))}>Save tools</Button>}
      </div>
    </div>
  );
}

function RegisterDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (asset: Obj) => void }) {
  const create = useAction<Obj, Obj>("POST", "/ai/assets");
  const [type, setType] = useState("rag_application");
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = Object.fromEntries(new FormData(e.currentTarget).entries()) as Record<string, string>;
    create.mutate({ ...form, provider: form.provider || null }, { onSuccess: onCreated });
  };
  return (
    <Dialog open onClose={onClose} title="Add AI asset" wide>
      <form onSubmit={submit} className="space-y-3">
        {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Type" hint={TYPE_HINT[type]}>
            <Select name="type" value={type} onChange={(e) => setType(e.target.value)}>{AI_TYPES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</Select>
          </Field>
          <Field label="Name"><Input name="name" required maxLength={512} placeholder="Support assistant" /></Field>
          <Field label="Identifier" hint="URL, service name or another stable identifier. Re-adding the same identifier updates the existing asset.">
            <Input name="identifier" required maxLength={1024} placeholder="https://assistant.example.com/api" />
          </Field>
          <Field label="Provider (optional)" hint="For example openai, anthropic, azure_openai, bedrock, ollama."><Input name="provider" maxLength={48} /></Field>
          <Field label="Environment"><Select name="environment" defaultValue="production">{["production", "staging", "development", "test", "unknown"].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}</Select></Field>
          <Field label="Exposure"><Select name="exposure" defaultValue="internal">{["internet", "internal", "private", "unknown"].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}</Select></Field>
          <Field label="Criticality"><Select name="criticality" defaultValue="medium">{["critical", "high", "medium", "low"].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}</Select></Field>
          <Field label="Data sensitivity"><Select name="data_sensitivity" defaultValue="unknown">{["restricted", "confidential", "internal", "public", "unknown"].map((v) => <option key={v} value={v}>{titleCase(v)}</option>)}</Select></Field>
        </div>
        <p className="text-xs text-muted">After saving you record its security configuration. The posture review runs automatically and reports any control that is missing or not yet recorded.</p>
        <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Add and record posture</Button></div>
      </form>
    </Dialog>
  );
}

function PostureDialog({ asset, onClose }: { asset: Obj; onClose: () => void }) {
  const { data } = useGet<Obj>(`/ai/assets/${asset.id}`);
  const patch = useAction<Obj>("PATCH", `/ai/assets/${asset.id}`);
  if (!data) return <Dialog open onClose={onClose} title={asset.name}><Skeleton className="h-32" /></Dialog>;
  const tri = (field: string, label: string, source: Obj | null) => (
    <Field key={field} label={label}>
      <Select value={source?.[field] == null ? "" : String(source[field])} onChange={(e) => patch.mutate({ [field]: e.target.value === "" ? null : e.target.value === "true" })}>
        <option value="">Unknown</option><option value="true">Yes</option><option value="false">No</option>
      </Select>
    </Field>
  );
  const isAgent = data.type === "ai_agent", isRag = ["rag_application", "vector_database"].includes(data.type), isModel = data.type === "ai_model";
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
          <ToolsEditor key={JSON.stringify(data.agent?.tools ?? [])} saving={patch.isPending}
                       initial={(data.agent?.tools ?? []).map((t: Obj) => ({ name: t.name ?? "", description: t.description ?? "", capabilities: t.capabilities ?? [], requires_approval: !!t.requires_approval }))}
                       onSave={(next) => patch.mutate({ tools: next })} />
        )}
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

type Tab = "inventory" | "findings" | "assessments" | "integrations" | "governance";
const TABS: Tab[] = ["inventory", "findings", "assessments", "integrations", "governance"];

export default function AISecurityPage() {
  return <Suspense><AISecurity /></Suspense>;
}

function AISecurity() {
  const router = useRouter();
  const search = useSearchParams();
  const { data: me } = useMe();
  const { data, error, refetch } = useGet<Obj>("/dashboard/ai", undefined, { refetchInterval: 30_000 });
  const requested = search.get("tab") as Tab | null;
  const tab: Tab = requested && TABS.includes(requested) ? requested : "inventory";
  const assetParam = search.get("asset");
  const navigate = (next: { tab?: Tab; asset?: string | null }) => {
    const params = new URLSearchParams();
    const t = next.tab ?? tab;
    if (t !== "inventory") params.set("tab", t);
    const a = next.asset === undefined ? assetParam : next.asset;
    if (a) params.set("asset", a);
    router.replace(params.size ? `/ai-security?${params}` : "/ai-security", { scroll: false });
  };
  const setTab = (t: Tab) => navigate({ tab: t });
  const [adding, setAdding] = useState(false);
  if (error) return <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />;
  const f = data?.findings;
  return (
    <>
      <PageHeader title="AI Security" description="Inventory and posture of AI applications, model endpoints, agents, MCP servers, vector stores and models, mapped to OWASP LLM Top 10 (2025), MITRE ATLAS and NIST AI RMF."
                  actions={can(me, "ai:write") && <Button variant="primary" onClick={() => setAdding(true)}><Plus className="h-4 w-4" /> Add AI asset</Button>} />
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
          path="/ai/assets" urlState searchable searchPlaceholder="Search AI assets or providers"
          filters={[
            { key: "type", label: "Type", options: ["ai_application", "llm_endpoint", "ai_agent", "mcp_server", "ai_model", "vector_database", "rag_application", "ai_framework", "ai_provider", "model_registry"] },
            { key: "approval_status", label: "Approval", options: ["approved", "unapproved", "under_review", "unknown"] },
            { key: "exposure", label: "Exposure", options: ["internet", "internal", "private", "unknown"] },
          ]}
          toggles={[{ key: "unowned", label: "Unowned" }]}
          empty={{ title: "No AI assets inventoried", body: "Add one with Add AI asset, or run a repository analysis, MCP probe or endpoint probe from the Discovery and assessment tab." }}
          columns={[
            { key: "name", header: "AI asset", className: "max-w-sm", render: (a) => <div className="min-w-0"><div className="truncate font-medium">{a.name}</div><div className="truncate font-mono text-xs text-muted">{a.identifier}</div></div> },
            { key: "type", header: "Type", render: (a) => <span className="text-xs">{titleCase(a.type)}</span> },
            { key: "provider", header: "Provider", render: (a) => <span className="text-xs">{a.provider ?? "—"}</span> },
            { key: "approval_status", header: "Approval", render: (a) => <StatusBadge value={a.approval_status} /> },
            { key: "exposure", header: "Exposure", render: (a) => <StatusBadge value={a.exposure} /> },
            { key: "auth", header: "Auth", render: (a) => (a.auth_required == null ? <span className="text-xs text-muted">Unknown</span> : a.auth_required ? <Badge tone="ok">Required</Badge> : <Badge tone="critical">None</Badge>) },
            { key: "owner", header: "Owner", render: (a) => (a.has_owner ? <Badge tone="ok">Assigned</Badge> : <Badge tone="medium">Unowned</Badge>) },
            { key: "open_findings", header: "Findings", render: (a) => <span className="tabular">{a.open_findings}</span> },
            { key: "edit", header: "", render: (a) => <Button size="sm" variant="ghost" onClick={() => navigate({ asset: a.id })}>Posture</Button> },
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
      {assetParam && <PostureDialog key={assetParam} asset={{ id: assetParam, name: "" }} onClose={() => navigate({ asset: null })} />}
      {adding && <RegisterDialog onClose={() => setAdding(false)} onCreated={(a) => { setAdding(false); navigate({ tab: "inventory", asset: a.id }); }} />}
    </>
  );
}
