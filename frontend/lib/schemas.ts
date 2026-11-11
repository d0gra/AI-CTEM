import { z } from "zod";

export const loginSchema = z.object({
  email: z.email("Enter a valid email address"),
  password: z.string().min(1, "Enter your password"),
  totp_code: z.string().regex(/^\d{6}$/, "Enter the 6-digit code").optional().or(z.literal("")),
});
export type LoginValues = z.infer<typeof loginSchema>;

export const registerSchema = z.object({
  organization_name: z.string().min(2, "Enter your organization name").max(200),
  full_name: z.string().min(1, "Enter your name").max(200),
  email: z.email("Enter a valid email address"),
  password: z
    .string()
    .min(12, "Use at least 12 characters")
    .max(256)
    .refine((v) => new Set(v).size >= 5, "Avoid repeated characters"),
});
export type RegisterValues = z.infer<typeof registerSchema>;

export const scopeSchema = z.object({
  kind: z.enum(["domain", "cidr", "url", "path"]),
  value: z.string().min(1, "Enter a value").max(1024),
  allow_active: z.boolean(),
  allow_private_network: z.boolean(),
  authorization_note: z.string().min(10, "Describe who authorized this and under which agreement (at least 10 characters)").max(2000),
  expires_at: z.string().optional(),
});
export type ScopeValues = z.infer<typeof scopeSchema>;

export const acceptanceSchema = z.object({
  reason: z.string().min(20, "Explain the business reason (at least 20 characters)").max(5000),
  compensating_controls: z.string().max(5000),
  owner_user_id: z.string().min(1, "Select a risk owner"),
  expires_at: z.string().min(1, "Choose an expiry date").refine((v) => new Date(v).getTime() > Date.now(), "Expiry must be in the future"),
});
export type AcceptanceValues = z.infer<typeof acceptanceSchema>;

export const redTeamSchema = z.object({
  name: z.string().min(2, "Enter a name").max(200),
  integration_id: z.string().min(1, "Select a target"),
  authorization_statement: z.string().min(30, "State who authorized testing, under what agreement, and any constraints (at least 30 characters)").max(4000),
  authorization_days: z.number().int().min(1).max(30),
  request_budget: z.number().int().min(1).max(500),
  rate_limit_per_minute: z.number().int().min(1).max(120),
  attempts: z.number().int().min(1).max(5),
  forbidden_markers: z.string().max(2000),
});
export type RedTeamValues = z.infer<typeof redTeamSchema>;

export const claudeSchema = z
  .object({
    credential_source: z.enum(["api_key", "server"]),
    api_key: z.string().max(400).optional(),
    model: z.string().min(3, "Choose a model"),
    effort: z.enum(["low", "medium", "high"]),
  });
export type ClaudeValues = z.infer<typeof claudeSchema>;
