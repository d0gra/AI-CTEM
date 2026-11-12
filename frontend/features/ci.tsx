"use client";

import Link from "next/link";
import { Check, Copy, KeyRound } from "lucide-react";
import { useState, useSyncExternalStore, type FormEvent } from "react";
import { Alert, Badge, Button, Card, Dialog, EmptyState, ErrorState, Field, Input, Select, Skeleton, StatusBadge, Tabs } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { formatDate, relativeTime, titleCase } from "@/lib/format";
import { can, useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";

/** How to produce each supported report in a pipeline. `file` is what the ingest step uploads. */
const PRODUCERS: Record<string, { label: string; run: string; file: string }> = {
  trivy: { label: "Trivy", run: "trivy fs --scanners vuln,secret,misconfig --format json --output trivy.json .", file: "trivy.json" },
  grype: { label: "Grype", run: "grype dir:. -o json --file grype.json", file: "grype.json" },
  semgrep: { label: "Semgrep", run: "semgrep scan --config auto --json --output semgrep.json", file: "semgrep.json" },
  gitleaks: { label: "Gitleaks", run: "gitleaks detect --source . --report-format json --report-path gitleaks.json --exit-code 0", file: "gitleaks.json" },
  checkov: { label: "Checkov", run: "checkov -d . -o json --soft-fail > checkov.json", file: "checkov.json" },
  sbom: { label: "SBOM (CycloneDX / SPDX JSON)", run: "syft dir:. -o cyclonedx-json=sbom.json", file: "sbom.json" },
  sarif: { label: "SARIF (any SARIF 2.1 producer)", run: "# any tool that writes SARIF 2.1.0, for example CodeQL or Bandit", file: "results.sarif" },
  nuclei: { label: "Nuclei", run: "nuclei -u https://staging.example.com -jsonl -o nuclei.jsonl", file: "nuclei.jsonl" },
  zap: { label: "OWASP ZAP", run: "zap-baseline.py -t https://staging.example.com -J zap.json || true", file: "zap.json" },
  nmap: { label: "Nmap (XML)", run: "nmap -sV -oX nmap.xml scanme.example.com", file: "nmap.xml" },
  prowler: { label: "Prowler (OCSF JSON)", run: "prowler aws --output-formats json-ocsf --output-directory out --output-filename prowler", file: "out/prowler.ocsf.json" },
};

const PROVIDERS = [
  { id: "github_actions", label: "GitHub Actions" },
  { id: "gitlab_ci", label: "GitLab CI" },
  { id: "jenkins", label: "Jenkins" },
  { id: "shell", label: "Any shell" },
] as const;
type Provider = (typeof PROVIDERS)[number]["id"];

function ingestCommand(provider: Provider, format: string, failOn: string, file: string, indent: string) {
  const vars: Record<Provider, [string, string][]> = {
    github_actions: [["repository", "$GITHUB_REPOSITORY"], ["branch", "$GITHUB_REF_NAME"], ["commit", "$GITHUB_SHA"],
                     ["pipeline_url", "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"]],
    gitlab_ci: [["repository", "$CI_PROJECT_PATH"], ["branch", "$CI_COMMIT_REF_NAME"], ["commit", "$CI_COMMIT_SHA"], ["pipeline_url", "$CI_PIPELINE_URL"]],
    jenkins: [["repository", "$GIT_URL"], ["branch", "$BRANCH_NAME"], ["commit", "$GIT_COMMIT"], ["pipeline_url", "$BUILD_URL"]],
    shell: [["repository", "$(git config --get remote.origin.url)"], ["branch", "$(git rev-parse --abbrev-ref HEAD)"], ["commit", "$(git rev-parse HEAD)"]],
  };
  const query: [string, string][] = [["format", format], ["provider", provider === "shell" ? "" : provider], ...vars[provider],
                                     ["fail_on", failOn], ["exit_code", failOn === "none" ? "" : "true"]];
  const lines = [`curl --fail-with-body -sS -X POST "$CTEM_URL/api/v1/ci/ingest"`, `-H "Authorization: Bearer $CTEM_CI_TOKEN"`,
                 ...query.filter(([, v]) => v).map(([k, v]) => `--url-query "${k}=${v}"`), `--data-binary @${file}`];
  return lines.map((l, i) => (i === 0 ? l : indent + "  " + l)).join(" \\\n");
}

function snippet(provider: Provider, format: string, failOn: string, origin: string) {
  const p = PRODUCERS[format] ?? { label: format, run: "# produce the report", file: "report.json" };
  if (provider === "github_actions") {
    return `# .github/workflows/ctem.yml — add CTEM_CI_TOKEN under Settings → Secrets and variables → Actions
name: CTEM
on: [push, pull_request]
jobs:
  ${format}:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ${p.label}
        run: ${p.run}
      - name: Send results to CTEM${failOn !== "none" ? ` (fails on ${failOn} or above)` : ""}
        if: always()
        env:
          CTEM_URL: ${origin}
          CTEM_CI_TOKEN: \${{ secrets.CTEM_CI_TOKEN }}
        run: |
          ${ingestCommand(provider, format, failOn, p.file, "          ")}`;
  }
  if (provider === "gitlab_ci") {
    return `# .gitlab-ci.yml — add CTEM_CI_TOKEN as a masked CI/CD variable
ctem-${format}:
  stage: test
  variables:
    CTEM_URL: ${origin}
  script:
    - ${p.run}
    - >
      ${ingestCommand(provider, format, failOn, p.file, "      ").replace(/ \\\n {6}/g, "\n      ")}`;
  }
  if (provider === "jenkins") {
    return `// Jenkinsfile — store the token as a "Secret text" credential with ID ctem-ci-token
stage('CTEM ${p.label}') {
  environment {
    CTEM_URL = '${origin}'
    CTEM_CI_TOKEN = credentials('ctem-ci-token')
  }
  steps {
    sh '${p.run.replace(/'/g, "'\\''")}'
    sh '''
      ${ingestCommand(provider, format, failOn, p.file, "      ")}
    '''
  }
}`;
  }
  return `export CTEM_URL=${origin}
export CTEM_CI_TOKEN=...   # from a secret store, never committed
${p.run}
${ingestCommand(provider, format, failOn, p.file, "")}`;
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button size="sm" type="button" onClick={async () => {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }}>
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />} {copied ? "Copied" : label}
    </Button>
  );
}

function GateBadge({ upload }: { upload: Obj }) {
  const gate = upload.gate;
  if (!gate || gate.threshold === "none") return null;
  return gate.passed
    ? <Badge tone="ok">Gate passed · {titleCase(gate.threshold)}+</Badge>
    : <Badge tone="critical">Gate failed · {gate.blocking_count} {titleCase(gate.threshold)}+ open</Badge>;
}

/** Report uploads from people and pipelines. */
export function UploadHistory({ formats, source = "all", pageSize = 10, title = "Uploaded results" }: {
  formats?: string[]; source?: "all" | "ci" | "manual"; pageSize?: number; title?: string;
}) {
  const { data, error, isLoading, refetch } = useGet<Obj>("/imports", { source, format: formats, page_size: pageSize }, { refetchInterval: 5000 });
  return (
    <Card title={title} action={<Link href="/integrations?tab=ci" className="text-xs text-accent hover:underline">Send from CI/CD</Link>}>
      {isLoading && <Skeleton className="h-12" />}
      {error && <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />}
      {data && data.items.length === 0 && (
        <EmptyState title="Nothing uploaded yet">Upload a report here, or have a pipeline send it with a CI token.</EmptyState>
      )}
      {data && data.items.length > 0 && (
        <ul className="divide-y divide-border">
          {data.items.map((u: Obj) => (
            <li key={u.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
                  {PRODUCERS[u.format]?.label ?? titleCase(u.format ?? "report")}
                  {u.ci ? <Badge tone="low">{PROVIDERS.find((p) => p.id === u.ci.provider)?.label ?? "Pipeline"}</Badge> : <Badge>Manual upload</Badge>}
                  <GateBadge upload={u} />
                </div>
                <div className="truncate text-xs text-muted">
                  {u.ci?.repository ?? u.target ?? u.filename ?? "—"}
                  {u.ci?.branch && ` · ${u.ci.branch}`}
                  {u.ci?.commit && <> · <span className="font-mono">{String(u.ci.commit).slice(0, 10)}</span></>}
                  {u.ci?.token_name && ` · token “${u.ci.token_name}”`}
                  {u.ci?.pipeline_url && <> · <a href={u.ci.pipeline_url} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">pipeline</a></>}
                </div>
                {u.error && <div className="mt-0.5 text-xs text-critical">{u.error}</div>}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted">
                <StatusBadge value={u.status} />
                {u.status === "succeeded" && <span className="tabular">{u.findings_new ?? 0} new · {u.findings_seen ?? 0} seen</span>}
                <span title={formatDate(u.created_at)}>{relativeTime(u.created_at)}</span>
                {u.status === "succeeded" && <Link href={`/findings?source=import:${u.format}`} className="text-accent hover:underline">Findings</Link>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function Tokens() {
  const { data: tokens, error, isLoading } = useGet<Obj[]>("/ci/tokens", undefined, { refetchInterval: 15_000 });
  const create = useAction<{ name: string; expires_in_days: number | null }, Obj>("POST", "/ci/tokens");
  const revoke = useAction<{ id: string }, Obj>("DELETE", (b) => `/ci/tokens/${b.id}`);
  const [open, setOpen] = useState(false);
  const [issued, setIssued] = useState<Obj | null>(null);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const days = String(form.get("expires"));
    create.mutate({ name: String(form.get("name")), expires_in_days: days === "never" ? null : Number(days) },
                  { onSuccess: (t) => { setOpen(false); setIssued(t); } });
  };
  return (
    <Card title="Pipeline tokens" action={<Button size="sm" variant="primary" onClick={() => { create.reset(); setOpen(true); }}><KeyRound className="h-3.5 w-3.5" /> New token</Button>}>
      <p className="mb-3 text-xs text-muted">
        A pipeline token can only upload scanner results and read back the outcome of its own uploads. It cannot sign in or read anything else.
        Create one token per repository or pipeline so a leaked token can be revoked on its own.
      </p>
      {revoke.error && <div className="mb-2"><Alert tone="critical">{errorMessage(revoke.error)}</Alert></div>}
      {isLoading && <Skeleton className="h-12" />}
      {error && <Alert tone="critical">{errorMessage(error)}</Alert>}
      {tokens && tokens.length === 0 && <EmptyState title="No pipeline tokens">Create one, store it as a secret in your CI system, then use a snippet below.</EmptyState>}
      {tokens && tokens.length > 0 && (
        <ul className="divide-y divide-border">
          {tokens.map((t) => (
            <li key={t.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <div className="flex items-center gap-2 text-sm font-medium">{t.name}{!t.active && <Badge tone="critical">{t.revoked_at ? "Revoked" : "Expired"}</Badge>}</div>
                <div className="text-xs text-muted">
                  <span className="font-mono">{t.prefix}…</span> · created {relativeTime(t.created_at)}
                  {t.expires_at ? ` · expires ${formatDate(t.expires_at)}` : " · does not expire"}
                  {t.last_used_at ? ` · last used ${relativeTime(t.last_used_at)}${t.last_used_ip ? ` from ${t.last_used_ip}` : ""}` : " · never used"}
                </div>
              </div>
              {t.active && (
                <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables?.id === t.id}
                        onClick={() => window.confirm(`Revoke “${t.name}”? Pipelines using it will start failing to upload.`) && revoke.mutate({ id: t.id })}>
                  Revoke
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <Dialog open={open} onClose={() => setOpen(false)} title="New pipeline token">
        <form onSubmit={submit} className="space-y-3">
          {create.error && <Alert tone="critical">{errorMessage(create.error)}</Alert>}
          <Field label="Name" hint="Where it is used, for example the repository name."><Input name="name" required minLength={2} maxLength={120} placeholder="acme/shop · GitHub Actions" /></Field>
          <Field label="Expires">
            <Select name="expires" defaultValue="365">
              <option value="30">In 30 days</option><option value="90">In 90 days</option><option value="365">In 1 year</option>
              <option value="730">In 2 years</option><option value="never">Never</option>
            </Select>
          </Field>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" variant="primary" loading={create.isPending}>Create</Button></div>
        </form>
      </Dialog>
      <Dialog open={!!issued} onClose={() => setIssued(null)} title="Copy the token now">
        {issued && (
          <div className="space-y-3">
            <Alert tone="medium">This is the only time the token is shown. Store it as a secret named <span className="font-mono">CTEM_CI_TOKEN</span> in your CI system.</Alert>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded-md bg-surface-2 px-3 py-2 font-mono text-xs">{issued.token}</code>
              <CopyButton text={issued.token} />
            </div>
            <div className="flex justify-end"><Button variant="primary" onClick={() => setIssued(null)}>Done</Button></div>
          </div>
        )}
      </Dialog>
    </Card>
  );
}

function Snippets() {
  const [provider, setProvider] = useState<Provider>("github_actions");
  const [format, setFormat] = useState("trivy");
  const [failOn, setFailOn] = useState("high");
  const origin = useSyncExternalStore(() => () => {}, () => window.location.origin, () => "https://ctem.example.com");
  const text = snippet(provider, format, failOn, origin);
  return (
    <Card title="Pipeline setup">
      <div className="mb-3 grid gap-3 sm:grid-cols-2">
        <Field label="Report">
          <Select value={format} onChange={(e) => setFormat(e.target.value)}>
            {Object.entries(PRODUCERS).map(([k, p]) => <option key={k} value={k}>{p.label}</option>)}
          </Select>
        </Field>
        <Field label="Fail the build when an open finding is at least" hint="Counts every open finding the upload observed, including ones seen before. Accepted risks and false positives do not count.">
          <Select value={failOn} onChange={(e) => setFailOn(e.target.value)}>
            <option value="none">Never (report only)</option><option value="critical">Critical</option><option value="high">High</option>
            <option value="medium">Medium</option><option value="low">Low</option>
          </Select>
        </Field>
      </div>
      <Tabs value={provider} onChange={setProvider} tabs={PROVIDERS.map((p) => ({ id: p.id, label: p.label }))} />
      <div className="relative">
        <pre className="max-h-[28rem] overflow-auto rounded-md bg-surface-2 p-3 pr-24 font-mono text-xs leading-relaxed">{text}</pre>
        <div className="absolute right-2 top-2"><CopyButton text={text} /></div>
      </div>
      <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-muted">
        <li>The request waits until the report is processed (up to two minutes) and returns the new and seen finding counts and the gate result as JSON.</li>
        <li>With a threshold, a failed gate returns HTTP 412 and an unreadable report returns 422, so <span className="font-mono">curl --fail-with-body</span> fails the step. Use <span className="font-mono">wait=false</span> to upload without waiting.</li>
        <li><span className="font-mono">--url-query</span> needs curl 7.87 or later. Findings appear on the asset named by the report, or by <span className="font-mono">target</span> when the report names none.</li>
      </ul>
    </Card>
  );
}

export function CiPipelines() {
  const { data: me } = useMe();
  const manage = can(me, "integrations:manage");
  return (
    <div className="space-y-4">
      {manage ? <Tokens /> : <Alert>Creating pipeline tokens requires the integrations management permission.</Alert>}
      <Snippets />
      <UploadHistory source="ci" title="Pipeline uploads" pageSize={20} />
    </div>
  );
}
