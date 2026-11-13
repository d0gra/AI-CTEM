"use client";

import Link from "next/link";
import { ExternalLink, Terminal } from "lucide-react";
import { useState, useSyncExternalStore } from "react";
import { Badge, Card, Tabs } from "@/components/ui";
import { CopyButton } from "@/features/ci";

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
  { cmd: "aictem discover . --approved-providers openai,anthropic", what: "Report any other model provider as shadow AI." },
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
  const [installer, setInstaller] = useState<Installer>("pipx");
  const origin = useSyncExternalStore(() => () => {}, () => window.location.origin, () => "https://ctem.example.com");
  const active = INSTALLERS.find((i) => i.id === installer) ?? INSTALLERS[0];
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
        <Tabs value={installer} onChange={setInstaller} tabs={INSTALLERS.map((i) => ({ id: i.id, label: i.label }))} />
        <Command text={active.cmd} />
        <p className="mt-1.5 text-xs text-muted">{active.hint}</p>
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
