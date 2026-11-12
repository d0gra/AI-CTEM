/* eslint-disable @typescript-eslint/no-explicit-any */
// Loose record type for API payloads whose full shape is documented in the backend OpenAPI
// schema (/api/docs). Core entities used across pages are typed explicitly below.
export type Obj = Record<string, any>;

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Me {
  id: string;
  organization_id: string;
  email: string;
  full_name: string;
  role: string;
  permissions: string[];
  mfa_enabled: boolean;
  mfa_verified: boolean;
  email_verified: boolean;
  email_verification_required: boolean;
  email_delivery_configured: boolean;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Asset {
  id: string;
  type: string;
  identifier: string;
  name: string;
  environment: string;
  criticality: string;
  exposure: string;
  data_sensitivity: string;
  owner_user_id: string | null;
  owner_team_id: string | null;
  tags: string[];
  discovery_sources: string[];
  status: string;
  risk_score: number;
  first_seen_at: string;
  last_seen_at: string;
  open_findings: number;
}

export interface Finding {
  id: string;
  asset_id: string;
  asset_name: string;
  asset_type: string;
  title: string;
  domain: string;
  source: string;
  rule_id: string;
  severity: Severity;
  confidence: string;
  status: string;
  risk_score: number;
  risk_level: Severity;
  owner_user_id: string | null;
  owner_team_id: string | null;
  due_at: string | null;
  first_seen_at: string;
  last_seen_at: string;
  vulnerability_external_id: string | null;
  kev: boolean;
  overdue: boolean;
}
