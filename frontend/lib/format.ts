export function formatDate(value: string | null | undefined, withTime = false): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return withTime
    ? date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : date.toLocaleDateString(undefined, { dateStyle: "medium" });
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return "—";
  const seconds = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  const abs = Math.abs(seconds);
  const units: [number, string][] = [[86400, "d"], [3600, "h"], [60, "m"]];
  for (const [size, label] of units) {
    if (abs >= size) return seconds >= 0 ? `${Math.floor(abs / size)}${label} ago` : `in ${Math.floor(abs / size)}${label}`;
  }
  return "just now";
}

const ACRONYMS: Record<string, string> = {
  ai: "AI", llm: "LLM", mcp: "MCP", rag: "RAG", api: "API", apis: "APIs", iam: "IAM", sbom: "SBOM", url: "URL", dns: "DNS", tls: "TLS",
  kev: "KEV", epss: "EPSS", cve: "CVE", osv: "OSV", sla: "SLA", mfa: "MFA", sso: "SSO", ip: "IP", id: "ID", http: "HTTP", https: "HTTPS",
  sast: "SAST", dast: "DAST", ci: "CI", cd: "CD", aws: "AWS", gcp: "GCP", ec2: "EC2", s3: "S3", rds: "RDS", vpc: "VPC", ssh: "SSH",
  saml: "SAML", oidc: "OIDC", ocsf: "OCSF", sarif: "SARIF", owasp: "OWASP", nist: "NIST", cis: "CIS", csv: "CSV", json: "JSON", pdf: "PDF",
  xlsx: "XLSX", smtp: "SMTP", jwt: "JWT", rbac: "RBAC", easm: "EASM", cspm: "CSPM", spm: "SPM", ttp: "TTP", xss: "XSS", sqli: "SQLi",
  ssrf: "SSRF", csrf: "CSRF", cors: "CORS",
};

/** snake_case or kebab-case identifier → sentence case, keeping acronyms ("llm_endpoint" → "LLM endpoint"). */
export function titleCase(value: string | null | undefined): string {
  if (!value) return "—";
  const words = value.replace(/[_-]+/g, " ").trim().split(/\s+/);
  return words
    .map((w, i) => ACRONYMS[w.toLowerCase()] ?? (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
