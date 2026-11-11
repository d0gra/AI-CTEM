// Minimal typed client for the CTEM API. Authentication uses the HttpOnly session cookie; the
// CSRF token returned at login is held in memory/sessionStorage and sent on unsafe requests.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

const CSRF_KEY = "ctem.csrf";
let csrfToken: string | null = null;

export function setCsrf(token: string | null) {
  csrfToken = token;
  if (typeof window === "undefined") return;
  if (token) window.sessionStorage.setItem(CSRF_KEY, token);
  else window.sessionStorage.removeItem(CSRF_KEY);
}

function getCsrf(): string | null {
  if (csrfToken) return csrfToken;
  if (typeof window !== "undefined") csrfToken = window.sessionStorage.getItem(CSRF_KEY);
  return csrfToken;
}

export type Params = Record<string, string | number | boolean | string[] | null | undefined>;

export function buildQuery(params?: Params): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

interface Options {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  form?: FormData;
  params?: Params;
}

async function ensureCsrf(): Promise<string | null> {
  const existing = getCsrf();
  if (existing) return existing;
  const response = await fetch("/api/v1/auth/csrf", { credentials: "same-origin" });
  if (!response.ok) return null;
  const data = (await response.json()) as { csrf_token: string };
  setCsrf(data.csrf_token);
  return data.csrf_token;
}

export async function api<T = unknown>(path: string, options: Options = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = {};
  if (method !== "GET") {
    const token = path.startsWith("/auth/login") || path.startsWith("/auth/register") ? null : await ensureCsrf();
    if (token) headers["X-CSRF-Token"] = token;
  }
  let body: BodyInit | undefined;
  if (options.form) body = options.form;
  else if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  const response = await fetch(`/api/v1${path}${buildQuery(options.params)}`, { method, headers, body, credentials: "same-origin" });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!response.ok) {
    const error = (data as { error?: { code?: string; message?: string; details?: Record<string, unknown> } } | null)?.error;
    throw new ApiError(response.status, error?.code ?? "error", error?.message ?? `Request failed (${response.status})`, error?.details ?? {});
  }
  return data as T;
}

export function downloadUrl(path: string): string {
  return `/api/v1${path}`;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const issues = error.details?.issues as { field: string; message: string }[] | undefined;
    if (issues?.length) return issues.map((i) => (i.field ? `${i.field}: ${i.message}` : i.message)).join("; ");
    return error.message;
  }
  return error instanceof Error ? error.message : "Unexpected error";
}
