"use client";

import Link from "next/link";
import { useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Terminal, Upload } from "lucide-react";
import { useState, useSyncExternalStore, type FormEvent } from "react";
import { Alert, Badge, Button, Card, Input, Tabs } from "@/components/ui";
import { CopyButton } from "@/features/ci";
import { api, errorMessage } from "@/lib/api";
import { can, useMe } from "@/lib/hooks";

/** Ways to install the CLI. `pipx` first: it is the one that leaves no mark on the project's own environment. */
const INSTALLERS = [
  { id: "pipx", label: "pipx", cmd: "pipx install aictem", hint: "Installs into its own environment and puts aictem on your PATH. Nothing is added to the project." },
  { id: "pip", label: "pip", cmd: "pip install aictem", hint: "Installs into the environment that is active right now, so activate a virtualenv first." },
  { id: "uv", label: "uv", cmd: "uv tool install aictem", hint: "The uv equivalent of pipx." },
  { id: "run", label: "Run without installing", cmd: "pipx run aictem discover .", hint: "Fetches and runs one version, then discards it. This is the form to use in a pipeline." },
] as const;
type Installer = (typeof INSTALLERS)[number]["id"];

const COMMANDS: { cmd: string; what: string }[] = [
  { cmd: "aictem discover .", what: "Scan this directory and print a summary of the assets and findings it found." },
  { cmd: "aictem discover . --all", what: "List every asset and finding instead of the top of each group." },
  { cmd: "aictem discover . --approved-providers openai,anthropic", what: "Report any other model provider as shadow AI in the CLI's own output. On upload, the platform applies the approved list under Governance instead." },
  { cmd: "aictem discover . --vulns", what: "Look up known vulnerabilities for pinned packages against osv.dev." },
  { cmd: "aictem discover . -f sarif -o aictem.sarif", what: "Write SARIF for GitHub code scanning or another SARIF dashboard." },
  { cmd: "aictem discover . -f json -o inventory.json", what: "Write the full inventory. This is the file the Import button on this page accepts." },
];

function Command({ text, className = "" }: { text: string; className?: string }) {
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-pre rounded-md bg-surface-2 px-3 py-2 font-mono text-xs">{text}</code>
      <CopyButton text={text} />
    </div>
  );
}

/**
 * How to run the discovery CLI, shown next to the assessments that need its output.
 * The platform cannot reach a private repository on a developer's machine, so this is the path that
 * covers everything the server-side repository analysis cannot see.
 */
export function DiscoveryCliCard() {
  const origin = useSyncExternalStore(() => () => {}, () => window.location.origin, () => "https://ctem.example.com");
  return (
    <Card
      title={<span className="flex items-center gap-2"><Terminal className="h-4 w-4 text-accent" aria-hidden /> Discover from inside a repository: the aictem CLI</span>}
      action={
        <a href="https://pypi.org/project/aictem/" target="_blank" rel="noreferrer noopener" className="flex items-center gap-1 text-xs text-accent hover:underline">
          PyPI <ExternalLink className="h-3 w-3" aria-hidden />
        </a>
      }
    >
      <p className="text-xs text-muted">
        <span className="font-mono text-text">aictem</span> inventories a repository from the inside and finds what an external scan cannot see:
        model providers and SDKs, agents and the tools they can call, RAG pipelines and vector stores, MCP servers and clients, model files,
        dependencies, containers, IaC and committed credentials. Run it on a laptop or in CI, then upload the inventory here.
      </p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        <Badge tone="ok">No dependencies</Badge>
        <Badge tone="ok">Python 3.11+</Badge>
        <Badge tone="low">Model files are disassembled, never loaded</Badge>
        <Badge tone="low">Secret values are never sent</Badge>
      </div>

      <h3 className="mt-4 text-xs font-semibold">1. Install it</h3>
      <div className="mt-1.5">
        <InstallCommand />
      </div>

      <h3 className="mt-4 text-xs font-semibold">2. Scan the repository</h3>
      <ul className="mt-1.5 space-y-2">
        {COMMANDS.map((c) => (
          <li key={c.cmd}>
            <Command text={c.cmd} />
            <p className="mt-1 text-xs text-muted">{c.what}</p>
          </li>
        ))}
      </ul>

      <h3 className="mt-4 text-xs font-semibold">3. Send the results to this platform</h3>
      <p className="mt-1.5 text-xs text-muted">
        Either upload <span className="font-mono">inventory.json</span> with <strong>Import results</strong> above, or have the CLI send it directly with an
        upload-only pipeline token from <Link href="/integrations?tab=ci" className="text-accent hover:underline">Integrations → CI/CD pipelines</Link>.
      </p>
      <Command className="mt-2" text={`export CTEM_URL=${origin}\nexport CTEM_CI_TOKEN=ctem_ci_...\naictem discover . --upload --gate high`} />
      <p className="mt-1.5 text-xs text-muted">
        <span className="font-mono">--gate high</span> exits non-zero when the platform has an open high or critical finding, which fails the build.
        Leave it out to report without gating.
      </p>
    </Card>
  );
}

/** What is being imported decides the command. Every one of them writes or sends the same inventory. */
const SCENARIOS = [
  { id: "repo", label: "One repository",
    cmd: "cd path/to/repository\naictem discover . -f json -o inventory.json",
    hint: "Run it from the root of a checkout. The repository is identified by its git remote, so scanning it again later updates the same assets instead of adding new ones." },
  { id: "service", label: "Part of a monorepo",
    cmd: "aictem discover services/payments -f json -o inventory.json",
    hint: "Give the directory to scan. Only that service's dependencies, agents, containers and IaC are recorded, under the same repository." },
  { id: "many", label: "Several repositories",
    cmd: 'for repo in ~/code/*/; do\n  (cd "$repo" && aictem discover . --upload)\ndone',
    hint: "Each repository is sent as its own upload and becomes its own repository asset. Set CTEM_URL and CTEM_CI_TOKEN first (step 3)." },
  { id: "ci", label: "On every build",
    cmd: "pipx run aictem discover . --upload --gate high",
    hint: "Nothing to install on the build agent. The inventory stays current with the code, and --gate high fails the build while a high or critical finding is open." },
] as const;
type Scenario = (typeof SCENARIOS)[number]["id"];

const OPTIONS: { flag: string; what: string }[] = [
  { flag: "--exclude 'vendor/*'", what: "Skip paths matching a glob. Repeat it, or list globs in a .aictemignore file." },
  { flag: "--no-secrets", what: "Leave out the committed-credential scan." },
  { flag: "--max-files 200000", what: "Raise the file limit for a very large repository (default 50,000)." },
  { flag: "--all", what: "Without -f json: print every asset and finding in the terminal, to check before sending." },
];

const CREATED: [type: string, from: string][] = [
  ["Repository", "the checkout itself, with branch and commit"],
  ["Packages", "21 manifest and lockfile formats; versions are checked for known vulnerabilities here"],
  ["Container images, Kubernetes resources", "Dockerfiles, Compose files and manifests"],
  ["Cloud resources", "Terraform and CloudFormation: storage, databases, identities, load balancers, model endpoints"],
  ["AI providers, frameworks, vector databases", "imports, dependencies, endpoints and configuration"],
  ["Agents and their tools", "the common agent frameworks, with each tool's capabilities"],
  ["RAG applications, inference endpoints", "retrieval code and self-hosted model servers"],
  ["MCP servers and clients", "editor and agent configuration, and servers implemented in the code"],
  ["Models", "weight files, disassembled without loading them"],
];

function InstallCommand() {
  const [installer, setInstaller] = useState<Installer>("pipx");
  const active = INSTALLERS.find((i) => i.id === installer) ?? INSTALLERS[0];
  return (
    <>
      <Tabs value={installer} onChange={setInstaller} tabs={INSTALLERS.map((i) => ({ id: i.id, label: i.label }))} />
      <Command text={active.cmd} />
      <p className="mt-1.5 text-xs text-muted">{active.hint} Needs Python 3.11 or later; check with <span className="font-mono">aictem --version</span>.</p>
    </>
  );
}

/** Uploads an inventory file produced by `aictem discover -f json`, without leaving the dialog it is shown in. */
function InventoryUpload({ onQueued }: { onQueued?: () => void }) {
  const client = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.set("format", "aictem");
      form.set("file", file);
      await api("/scanner-imports", { method: "POST", form });
      setSent(file.name);
      setFile(null);
      await client.invalidateQueries();
      onQueued?.();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="space-y-2">
      {error && <Alert tone="critical">{error}</Alert>}
      {sent && <Alert tone="ok">{sent} was accepted and is being processed. Its assets appear in the inventory within a minute; the upload is listed under <Link href="/ai-security?tab=assessments" className="text-accent hover:underline">Discovery and assessment</Link>.</Alert>}
      <div className="flex items-center gap-2">
        <Input key={sent ?? "empty"} type="file" accept=".json,application/json" aria-label="Inventory file" required onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="py-1.5" />
        <Button type="submit" variant="primary" loading={busy} disabled={!file}><Upload className="h-3.5 w-3.5" /> Import</Button>
      </div>
    </form>
  );
}

/**
 * The route to an inventory that does not involve typing assets in one at a time: install the CLI, scan a
 * repository, send the result. Shown in the dialogs that add assets, next to the form for adding one by hand.
 */
export function ImportFromRepository() {
  const { data: me } = useMe();
  const [scenario, setScenario] = useState<Scenario>("repo");
  const origin = useSyncExternalStore(() => () => {}, () => window.location.origin, () => "https://ctem.example.com");
  const active = SCENARIOS.find((x) => x.id === scenario) ?? SCENARIOS[0];
  const direct = scenario === "many" || scenario === "ci";
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">
        <span className="font-mono text-text">aictem</span> reads a repository where it is checked out and reports everything in it as assets, with the
        relationships between them and the problems it finds. One scan usually adds dozens of assets that would otherwise be typed in by hand.
      </p>

      <section>
        <h3 className="text-xs font-semibold">1. Install the CLI</h3>
        <div className="mt-1.5"><InstallCommand /></div>
      </section>

      <section>
        <h3 className="text-xs font-semibold">2. Scan</h3>
        <div className="mt-1.5">
          <Tabs value={scenario} onChange={setScenario} tabs={SCENARIOS.map((x) => ({ id: x.id, label: x.label }))} />
          <Command text={active.cmd} />
          <p className="mt-1.5 text-xs text-muted">{active.hint}</p>
        </div>
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer text-muted hover:text-text">Options for large or unusual repositories</summary>
          <ul className="mt-2 space-y-1.5">
            {OPTIONS.map((o) => <li key={o.flag}><span className="font-mono text-text">{o.flag}</span> <span className="text-muted">{o.what}</span></li>)}
          </ul>
        </details>
      </section>

      <section>
        <h3 className="text-xs font-semibold">3. Send the inventory here</h3>
        {!direct && (
          <div className="mt-1.5">
            <p className="mb-1.5 text-xs text-muted">Choose the <span className="font-mono">inventory.json</span> the scan wrote:</p>
            {can(me, "assessments:run") ? <InventoryUpload /> : <Alert>Uploading needs the permission to run assessments. Ask an administrator, or have a pipeline send it with a token.</Alert>}
            <p className="mb-1.5 mt-3 text-xs text-muted">Or skip the file and have the CLI send it:</p>
          </div>
        )}
        <Command className="mt-1.5" text={`export CTEM_URL=${origin}\nexport CTEM_CI_TOKEN=ctem_ci_...   # paste the token; keep it out of shell history and source control${direct ? "" : "\naictem discover . --upload"}`} />
        <p className="mt-1.5 text-xs text-muted">
          Create the token under <Link href="/integrations?tab=ci" className="text-accent hover:underline">Integrations → CI/CD pipelines</Link>. It can only upload results;
          it cannot sign in or read anything. {scenario === "ci" && <>That page also generates the complete job for GitHub Actions, GitLab CI and Jenkins.</>}
        </p>
      </section>

      <details className="text-xs">
        <summary className="cursor-pointer text-muted hover:text-text">What a scan adds to the inventory</summary>
        <ul className="mt-2 space-y-1">
          {CREATED.map(([type, from]) => <li key={type}><span className="font-medium text-text">{type}</span> <span className="text-muted">from {from}</span></li>)}
        </ul>
        <p className="mt-2 text-muted">Model files are never loaded and secret values never leave the machine: a finding carries the prefix, the length and a fingerprint.</p>
      </details>
    </div>
  );
}
