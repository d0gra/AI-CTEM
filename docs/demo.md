# Public demo image

`Dockerfile.demo` builds a single container for showing the platform on a host that runs one service, such as Render. It contains PostgreSQL, the API, a worker and the web server. It is **not a production deployment**: data lives inside the container and is lost on every restart or redeploy, and the sign-in details are published. For real use, see [deployment.md](deployment.md).

## What a visitor gets

The sign-in page lists one account per built-in role, each with a **Sign in** button. All accounts share one password, `Demo-CTEM-2026!` unless `CTEM_DEMO_PASSWORD` changes it.

| Role | Email |
| --- | --- |
| Super Administrator | `super.admin@demo.example.com` |
| Organization Administrator | `org.admin@demo.example.com` |
| Security Administrator | `security.admin@demo.example.com` |
| Security Analyst | `analyst@demo.example.com` |
| Vulnerability Manager | `vuln.manager@demo.example.com` |
| Cloud Security Engineer | `cloud.engineer@demo.example.com` |
| Red Team Operator | `red.team@demo.example.com` |
| Auditor | `auditor@demo.example.com` |
| Read-only User | `viewer@demo.example.com` |

With `CTEM_DEMO_SAMPLE_DATA=true` (the default), the seed writes a small, deliberately insecure AI support bot into the container and runs the platform's real repository analysis on it, then the AI posture review. All values in it are synthetic: an old pinned dependency set, a provider key in the provider's format, a broad MCP filesystem server and a model file that references a code-execution callable. This gives about 90 findings and 17 assets across AI security, supply chain and secrets, produced by the engines. Vulnerability context comes from the public feeds the worker synchronises at start (CISA KEV, FIRST EPSS, MITRE ATT&CK, MITRE ATLAS), and dependency advisories come from the live OSV API. The container therefore needs outbound internet access.

## What demo mode restricts

`CTEM_DEMO_MODE=true` exists because anyone can sign in as an administrator:

- **No active testing.** Engines that send traffic to targets (HTTP exposure, Nmap, Nuclei, OpenAPI analysis, MCP and LLM endpoint probes, AI red teaming) refuse to run. Visitors can still define them and run **dry runs**, which show the plan without sending anything. Without this restriction, a visitor could authorize any domain as an administrator and scan it from your host.
- **Shared accounts stay usable.** Demo accounts cannot change their password or MFA, administrators cannot deactivate them, change their role or issue them password links, failed sign-ins never lock them, and organizations cannot be suspended.
- **No stored credentials.** Connecting Claude and saving integration credentials (Jira, GitHub, Slack, AWS and others) are refused, because every visitor shares the organization and could use them. AI analysis features therefore show as not connected on the demo.
- **No visitor addresses stored.** Client addresses are not recorded in the audit log or the session list, since every visitor can read those. Rate limits still use the real address.
- **Fixed defaults.** Self-service registration is off, private-network targets are refused, and the session signing key and encryption key are generated at each start.

## Deploy on Render

1. Push the repository to GitHub or GitLab.
2. In Render, choose **New → Blueprint**, select the repository and apply `render.yaml`. Or choose **New → Web Service → Existing image / Docker**, set the Dockerfile path to `Dockerfile.demo` and the context to the repository root, and add `CTEM_DEMO_MODE=true`.
3. Use an instance with at least 1 GB of memory. The demo uses about 430 MB at rest, so 512 MB instances (Free, Starter) run out of memory under load. The blueprint uses Standard (2 GB).
4. Open the service URL. The first start takes about a minute: database setup, migrations, seed, then the sample analysis in the background.

Render routes to the port in `PORT` (10000 by default). `CTEM_PUBLIC_BASE_URL` defaults to Render's `RENDER_EXTERNAL_URL`, so links in the app use the public address.

Free instances also sleep when idle, and a restart resets the demo. That reset is useful for a public demo, but anything visitors create is lost.

## Run locally

```bash
docker build -f Dockerfile.demo -t ctem-demo .
docker run --rm -p 10000:10000 ctem-demo
```

Then open http://localhost:10000.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTEM_DEMO_MODE` | `true` in the image | Seeds the accounts and applies the restrictions above |
| `CTEM_DEMO_PASSWORD` | `Demo-CTEM-2026!` | Password for every demo account |
| `CTEM_DEMO_SAMPLE_DATA` | `true` | Analyse the generated sample repository on first start |
| `PORT` | `10000` | Port the web server listens on |
| `CTEM_PUBLIC_BASE_URL` | `RENDER_EXTERNAL_URL`, else `http://localhost:$PORT` | Address used in links |
| `CTEM_SECRET_KEY`, `CTEM_ENCRYPTION_KEYS` | generated at start | Set them to keep sessions valid across restarts |

Any other `CTEM_` setting from [deployment.md](deployment.md) can be passed too.
