import { describe, expect, it } from "vitest";
import { acceptanceSchema, loginSchema, redTeamSchema, registerSchema, scopeSchema } from "@/lib/schemas";

const issues = (result: { success: boolean; error?: { issues: { path: PropertyKey[]; message: string }[] } }) =>
  Object.fromEntries((result.error?.issues ?? []).map((i) => [String(i.path[0]), i.message]));

describe("form validation", () => {
  it("login requires a valid email and a six-digit code when one is given", () => {
    expect(loginSchema.safeParse({ email: "a@b.co", password: "x", totp_code: "" }).success).toBe(true);
    expect(issues(loginSchema.safeParse({ email: "nope", password: "", totp_code: "12ab" }))).toMatchObject({
      email: "Enter a valid email address", password: "Enter your password", totp_code: "Enter the 6-digit code",
    });
  });

  it("registration enforces the password policy the server enforces", () => {
    const base = { organization_name: "Acme", full_name: "A", email: "a@acme.test" };
    expect(issues(registerSchema.safeParse({ ...base, password: "short" })).password).toBe("Use at least 12 characters");
    expect(issues(registerSchema.safeParse({ ...base, password: "aaaaaaaaaaaaaa" })).password).toBe("Avoid repeated characters");
    expect(registerSchema.safeParse({ ...base, password: "Correct-Horse-Battery-9" }).success).toBe(true);
  });

  it("scope entries need a meaningful authorization basis", () => {
    const base = { kind: "domain", value: "example.com", allow_active: true, allow_private_network: false };
    expect(scopeSchema.safeParse({ ...base, authorization_note: "ok" }).success).toBe(false);
    expect(scopeSchema.safeParse({ ...base, authorization_note: "Owned by Acme; ticket SEC-12" }).success).toBe(true);
    expect(scopeSchema.safeParse({ ...base, kind: "everything", authorization_note: "Owned by Acme; ticket SEC-12" }).success).toBe(false);
  });

  it("risk acceptance needs a reason, an owner and a future expiry", () => {
    const future = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);
    const ok = { reason: "Legacy system retired next quarter; isolated VLAN.", compensating_controls: "", owner_user_id: "u1", expires_at: future };
    expect(acceptanceSchema.safeParse(ok).success).toBe(true);
    expect(issues(acceptanceSchema.safeParse({ ...ok, reason: "because", expires_at: "2020-01-01", owner_user_id: "" }))).toMatchObject({
      reason: expect.stringContaining("at least 20"), expires_at: "Expiry must be in the future", owner_user_id: "Select a risk owner",
    });
  });

  it("AI red team assessments require authorization text and bounded budgets", () => {
    const ok = { name: "Bot", integration_id: "i1", authorization_statement: "Approved by the platform owner under AISEC-91, staging only.",
                 authorization_days: 14, request_budget: 60, rate_limit_per_minute: 20, attempts: 2, forbidden_markers: "" };
    expect(redTeamSchema.safeParse(ok).success).toBe(true);
    expect(redTeamSchema.safeParse({ ...ok, authorization_statement: "yes" }).success).toBe(false);
    expect(redTeamSchema.safeParse({ ...ok, request_budget: 5000 }).success).toBe(false);
    expect(redTeamSchema.safeParse({ ...ok, authorization_days: 90 }).success).toBe(false);
  });
});
