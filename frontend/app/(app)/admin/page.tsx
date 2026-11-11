"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { PageHeader, Tabs } from "@/components/ui";
import { ClaudeConnection } from "@/features/admin/claude";
import { Jobs } from "@/features/admin/jobs";
import { NotificationRules } from "@/features/admin/notifications";
import { Organization, PlatformOrganizations } from "@/features/admin/organization";
import { Roles } from "@/features/admin/roles";
import { Scope } from "@/features/admin/scope";
import { Security } from "@/features/admin/security";
import { Teams } from "@/features/admin/teams";
import { Users } from "@/features/admin/users";
import { can, useMe } from "@/lib/hooks";

type TabId = "scope" | "users" | "teams" | "roles" | "notifications" | "jobs" | "analytics" | "organization" | "platform" | "security";

function Admin() {
  const { data: me } = useMe();
  const router = useRouter();
  const search = useSearchParams();
  const tabs: { id: TabId; label: string }[] = [
    { id: "scope", label: "Authorized scope" },
    ...(can(me, "admin:users") ? [{ id: "users" as const, label: "Users" }, { id: "teams" as const, label: "Teams" }] : []),
    { id: "roles", label: "Roles" },
    ...(can(me, "notifications:manage") ? [{ id: "notifications" as const, label: "Notifications" }] : []),
    ...(can(me, "assessments:read") ? [{ id: "jobs" as const, label: "Background jobs" }] : []),
    ...(can(me, "ai_analytics:use") ? [{ id: "analytics" as const, label: "AI analysis" }] : []),
    { id: "organization", label: "Organization" },
    ...(can(me, "platform:admin") ? [{ id: "platform" as const, label: "All organizations" }] : []),
    { id: "security", label: "My security" },
  ];
  const requested = search.get("tab") as TabId | null;
  const tab = tabs.some((t) => t.id === requested) ? (requested as TabId) : "scope";
  return (
    <>
      <PageHeader title="Administration" description="Authorized assessment scope, people and access, notification delivery, background work, AI analysis and your own account security." />
      <Tabs value={tab} onChange={(id) => router.replace(`/admin?tab=${id}`)} tabs={tabs} />
      {tab === "scope" && <Scope />}
      {tab === "users" && <Users />}
      {tab === "teams" && <Teams />}
      {tab === "roles" && <Roles />}
      {tab === "notifications" && <NotificationRules />}
      {tab === "jobs" && <Jobs />}
      {tab === "analytics" && <ClaudeConnection />}
      {tab === "organization" && <Organization />}
      {tab === "platform" && <PlatformOrganizations />}
      {tab === "security" && <Security />}
    </>
  );
}

export default function AdminPage() {
  return (
    <Suspense>
      <Admin />
    </Suspense>
  );
}
