"use client";

import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { DataTable } from "@/components/data-table";
import { Alert, Badge, Button, Dialog, Field, Input, PageHeader, Select, StatusBadge } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Asset, Obj } from "@/types/api";

const AI_TYPES = ["ai_application", "llm_endpoint", "ai_agent", "mcp_server", "mcp_client", "ai_model", "vector_database", "rag_application", "ai_framework", "ai_provider", "model_registry"];

export default function AssetsPage() {
  const { data: me } = useMe();
  const { data: facets } = useGet<Obj>("/assets/facets");
  const [open, setOpen] = useState(false);
  const create = useAction<Obj, Asset>("POST", "/assets");
  const router = useRouter();
  const [type, setType] = useState("");
  const isAI = AI_TYPES.includes(type);
  const types: string[] = Object.keys(facets?.type ?? {}).sort();
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = Object.fromEntries(new FormData(e.currentTarget)) as Obj;
    create.mutate(form, {
      onSuccess: (asset) => {
        setOpen(false);
        if (AI_TYPES.includes(asset.type)) router.push(`/ai-security?asset=${asset.id}`);
      },
    });
  };
  return (
    <>
      <PageHeader
        title="Assets"
        description="Unified inventory of everything discovered or registered. Assets are identified by a type-qualified canonical identifier, never by display name alone."
        actions={can(me, "assets:write") && <Button variant="primary" onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> Add asset</Button>}
      />
      <DataTable<Asset>
        path="/assets"
        urlState
        searchable
        searchPlaceholder="Search name or identifier"
        defaultSort={{ key: "risk_score", order: "desc" }}
        filters={[
          { key: "type", label: "Type", options: types },
          { key: "exposure", label: "Exposure", options: ["internet", "internal", "private", "unknown"] },
          { key: "environment", label: "Environment", options: ["production", "staging", "development", "test", "unknown"] },
          { key: "criticality", label: "Criticality", options: ["critical", "high", "medium", "low"] },
        ]}
        toggles={[{ key: "unowned", label: "Unowned" }, { key: "ai_only", label: "AI assets" }]}
        rowHref={(a) => `/assets/${a.id}`}
        empty={{ title: "No assets match", body: "Assets are created by discovery, cloud and repository assessments, scanner imports, or manually." }}
        columns={[
          { key: "name", header: "Asset", sortable: true, className: "max-w-sm", render: (a) => <div className="min-w-0"><div className="truncate font-medium">{a.name}</div><div className="truncate font-mono text-xs text-muted">{a.identifier}</div></div> },
          { key: "type", header: "Type", sortable: true, render: (a) => <span className="text-xs">{titleCase(a.type)}</span> },
          { key: "risk_score", header: "Risk", sortable: true, render: (a) => <span className="tabular font-medium">{a.risk_score.toFixed(0)}</span> },
          { key: "open_findings", header: "Findings", render: (a) => <span className="tabular">{a.open_findings}</span> },
          { key: "exposure", header: "Exposure", sortable: true, render: (a) => <StatusBadge value={a.exposure} /> },
          { key: "criticality", header: "Criticality", render: (a) => <span className="text-xs">{titleCase(a.criticality)}</span> },
          { key: "owner", header: "Owner", render: (a) => (a.owner_user_id || a.owner_team_id ? <Badge tone="ok">Assigned</Badge> : <Badge tone="medium">Unowned</Badge>) },
          { key: "last_seen_at", header: "Last seen", sortable: true, render: (a) => <span className="whitespace-nowrap text-xs text-muted">{relativeTime(a.last_seen_at)}</span> },
        ]}
      />
      <Dialog open={open} onClose={() => setOpen(false)} title="Add asset">
        <form onSubmit={submit} className="space-y-3">
          {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
          <Field label="Type"><Select name="type" required value={type || facets?.asset_types?.[0] || ""} onChange={(e) => setType(e.target.value)}>{(facets?.asset_types ?? []).map((t: string) => <option key={t} value={t}>{titleCase(t)}</option>)}</Select></Field>
          {isAI && <Alert>AI assets appear under AI Security. After adding it you record its security configuration there; the posture review runs automatically.</Alert>}
          <Field label="Identifier" hint="Canonical identifier, e.g. FQDN, URL, ARN or connection string without credentials."><Input name="identifier" required /></Field>
          <Field label="Name"><Input name="name" required /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Exposure"><Select name="exposure" defaultValue="unknown">{["unknown", "internet", "internal", "private"].map((v) => <option key={v}>{v}</option>)}</Select></Field>
            <Field label="Criticality"><Select name="criticality" defaultValue="medium">{["critical", "high", "medium", "low"].map((v) => <option key={v}>{v}</option>)}</Select></Field>
            <Field label="Environment"><Select name="environment" defaultValue="unknown">{["unknown", "production", "staging", "development", "test"].map((v) => <option key={v}>{v}</option>)}</Select></Field>
            <Field label="Data sensitivity"><Select name="data_sensitivity" defaultValue="unknown">{["unknown", "public", "internal", "confidential", "restricted"].map((v) => <option key={v}>{v}</option>)}</Select></Field>
          </div>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>{isAI ? "Add and record posture" : "Add"}</Button></div>
        </form>
      </Dialog>
    </>
  );
}
