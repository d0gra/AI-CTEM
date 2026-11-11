import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, buildQuery, errorMessage, setCsrf } from "@/lib/api";

function mockFetch(...responses: [number, unknown][]) {
  const fn = vi.fn();
  for (const [status, body] of responses) {
    fn.mockResolvedValueOnce(new Response(status === 204 ? null : JSON.stringify(body), { status }));
  }
  vi.stubGlobal("fetch", fn);
  return fn;
}

describe("api client", () => {
  beforeEach(() => setCsrf(null));

  it("serialises query parameters, dropping empty values and repeating arrays", () => {
    expect(buildQuery({ q: "web", page: 2, open_only: true, kev: false, status: "", domain: ["web", "api"], owner: null })).toBe(
      "?q=web&page=2&open_only=true&domain=web&domain=api",
    );
    expect(buildQuery({})).toBe("");
  });

  it("sends the CSRF token on unsafe requests and never on GET", async () => {
    setCsrf("token-1");
    const fetchMock = mockFetch([200, { ok: true }], [200, { ok: true }]);
    await api("/assets");
    await api("/assets", { method: "POST", body: { name: "x" } });
    expect(fetchMock.mock.calls[0][1].headers["X-CSRF-Token"]).toBeUndefined();
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/assets");
    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBe("token-1");
    expect(fetchMock.mock.calls[1][1].credentials).toBe("same-origin");
  });

  it("fetches a CSRF token after a page reload before the first unsafe request", async () => {
    const fetchMock = mockFetch([200, { csrf_token: "fresh" }], [204, null]);
    await api("/notifications/read", { method: "POST" });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/auth/csrf");
    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBe("fresh");
  });

  it("does not request a CSRF token for login", async () => {
    const fetchMock = mockFetch([200, { csrf_token: "t", mfa_required: false }]);
    await api("/auth/login", { method: "POST", body: { email: "a@b.co", password: "x" } });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("raises ApiError with the server's code, message and details", async () => {
    mockFetch([403, { error: { code: "out_of_scope", message: "Target 'x' is not covered by an authorized scope entry", details: {} } }]);
    const error = (await api("/assessments").catch((e) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(403);
    expect(error.code).toBe("out_of_scope");
    expect(errorMessage(error)).toContain("not covered");
  });

  it("formats validation issues field by field", () => {
    const error = new ApiError(422, "validation_failed", "Request validation failed", { issues: [{ field: "email", message: "invalid" }, { field: "", message: "bad" }] });
    expect(errorMessage(error)).toBe("email: invalid; bad");
  });

  it("survives a non-JSON error body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>Bad gateway</html>", { status: 502 })));
    const error = (await api("/assets").catch((e) => e)) as ApiError;
    expect(error.status).toBe(502);
    expect(error.message).toBe("Request failed (502)");
  });
});
