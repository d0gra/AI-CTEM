"use client";

import clsx from "clsx";
import {
  Activity, Bell, Bot, Boxes, Cloud, FileText, Fingerprint, Gauge, Globe, KeyRound, LayoutDashboard, ListChecks, LogOut, Menu, Moon, Network,
  Plug, Radar, ScrollText, Server, Settings, ShieldAlert, ShieldCheck, Sun, Swords, Wrench, type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { api, ApiError, setCsrf } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import { useAction, useGet, useMe } from "@/lib/hooks";
import type { Obj } from "@/types/api";
import { Button, Dialog, EmptyState, SeverityBadge, Skeleton } from "./ui";

export const NAV: { href: string; label: string; icon: LucideIcon; group: string }[] = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard, group: "Exposure" },
  { href: "/assets", label: "Assets", icon: Boxes, group: "Exposure" },
  { href: "/attack-surface", label: "Attack Surface", icon: Globe, group: "Exposure" },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, group: "Exposure" },
  { href: "/web-api", label: "Web & API Security", icon: Server, group: "Exposure" },
  { href: "/cloud", label: "Cloud Security", icon: Cloud, group: "Exposure" },
  { href: "/identity", label: "Identity Security", icon: Fingerprint, group: "Exposure" },
  { href: "/supply-chain", label: "Containers & Supply Chain", icon: KeyRound, group: "Exposure" },
  { href: "/ai-security", label: "AI Security", icon: Bot, group: "AI" },
  { href: "/ai-redteam", label: "AI Red Team", icon: Swords, group: "AI" },
  { href: "/threat-intel", label: "Threat Intelligence", icon: Radar, group: "Prioritize" },
  { href: "/attack-paths", label: "Attack Paths", icon: Network, group: "Prioritize" },
  { href: "/risk", label: "Risk Management", icon: Gauge, group: "Prioritize" },
  { href: "/remediation", label: "Remediation", icon: Wrench, group: "Respond" },
  { href: "/policies", label: "Policies & Compliance", icon: ShieldCheck, group: "Respond" },
  { href: "/integrations", label: "Integrations", icon: Plug, group: "Platform" },
  { href: "/reports", label: "Reports", icon: FileText, group: "Platform" },
  { href: "/audit", label: "Audit Logs", icon: ScrollText, group: "Platform" },
  { href: "/admin", label: "Administration", icon: Settings, group: "Platform" },
];

function ThemeToggle() {
  // The theme is applied to <html> before hydration by the inline script in the root layout.
  const [theme, setTheme] = useState<string>(() => (typeof document === "undefined" ? "light" : document.documentElement.dataset.theme ?? "light"));
  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("ctem.theme", next);
    setTheme(next);
  };
  return (
    <Button variant="ghost" size="sm" onClick={toggle} aria-label="Toggle colour theme" suppressHydrationWarning>
      <span suppressHydrationWarning>{theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</span>
    </Button>
  );
}

function Notifications() {
  const [open, setOpen] = useState(false);
  const { data } = useGet<Obj>("/notifications", { page_size: 15 }, { refetchInterval: 30_000 });
  const markRead = useAction("POST", "/notifications/read");
  const links: Record<string, string> = { finding: "/findings", asset: "/assets", attack_path: "/attack-paths" };
  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)} aria-label={`Notifications, ${data?.unread ?? 0} unread`} className="relative">
        <Bell className="h-4 w-4" />
        {!!data?.unread && <span className="tabular absolute -right-0.5 -top-0.5 rounded-full bg-critical px-1 text-[10px] leading-4 text-white">{data.unread > 99 ? "99+" : data.unread}</span>}
      </Button>
      <Dialog open={open} onClose={() => setOpen(false)} title="Notifications">
        {!data?.items?.length ? (
          <EmptyState title="No notifications" />
        ) : (
          <ul className="divide-y divide-border">
            {data.items.map((n: Obj) => (
              <li key={n.id} className={clsx("py-2", !n.read && "font-medium")}>
                <div className="flex items-start justify-between gap-2">
                  {links[n.entity_type] && n.entity_id ? (
                    <Link href={`${links[n.entity_type]}/${n.entity_id}`} onClick={() => setOpen(false)} className="text-sm hover:underline">
                      {n.title}
                    </Link>
                  ) : (
                    <span className="text-sm">{n.title}</span>
                  )}
                  <SeverityBadge value={n.severity} />
                </div>
                <div className="mt-0.5 text-xs font-normal text-muted">
                  {relativeTime(n.created_at)}
                  {n.occurrences > 1 && ` · ${n.occurrences} occurrences`}
                  {n.body && ` · ${n.body}`}
                </div>
              </li>
            ))}
          </ul>
        )}
        {!!data?.unread && (
          <div className="mt-3 text-right">
            <Button size="sm" loading={markRead.isPending} onClick={() => markRead.mutate({})}>
              Mark all read
            </Button>
          </div>
        )}
      </Dialog>
    </>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { data: me, error, isLoading } = useMe();
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    if (error instanceof ApiError && error.status === 401) {
      router.replace(error.details?.mfa_required ? "/login?mfa=1" : "/login");
    }
  }, [error, router]);

  const logout = async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } finally {
      setCsrf(null);
      window.location.assign("/login"); // full reload clears all cached tenant data from memory
    }
  };

  if (isLoading || !me) {
    return (
      <div className="mx-auto max-w-md space-y-3 p-10" aria-busy="true">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }
  const groups = [...new Set(NAV.map((n) => n.group))];
  return (
    <div className="flex min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">
        Skip to content
      </a>
      <aside className={clsx("fixed inset-y-0 left-0 z-30 w-60 shrink-0 overflow-y-auto border-r border-border bg-surface lg:static lg:block", menu ? "block" : "hidden")}>
        <div className="flex h-12 items-center gap-2 border-b border-border px-4">
          <Activity className="h-4 w-4 text-accent" aria-hidden />
          <span className="text-sm font-semibold tracking-tight">CTEM Platform</span>
        </div>
        <nav aria-label="Main" className="p-2">
          {groups.map((group) => (
            <div key={group} className="mb-2">
              <div className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-muted">{group}</div>
              {NAV.filter((n) => n.group === group).map(({ href, label, icon: Icon }) => {
                const active = pathname === href || pathname.startsWith(href + "/");
                return (
                  <Link
                    key={href}
                    href={href}
                    aria-current={active ? "page" : undefined}
                    onClick={() => setMenu(false)}
                    className={clsx("flex items-center gap-2 rounded-md px-2 py-1.5 text-[13px]", active ? "bg-surface-2 font-medium text-text" : "text-muted hover:bg-surface-2 hover:text-text")}
                  >
                    <Icon className="h-4 w-4 shrink-0" aria-hidden />
                    {label}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>
      {menu && <button aria-label="Close menu" className="fixed inset-0 z-20 bg-black/40 lg:hidden" onClick={() => setMenu(false)} />}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-12 items-center justify-between gap-2 border-b border-border bg-surface px-3">
          <Button variant="ghost" size="sm" className="lg:hidden" aria-label="Open menu" onClick={() => setMenu(true)}>
            <Menu className="h-4 w-4" />
          </Button>
          <Link href="/findings" className="hidden items-center gap-1.5 text-xs text-muted hover:text-text sm:flex">
            <ListChecks className="h-3.5 w-3.5" aria-hidden /> All findings
          </Link>
          <div className="flex items-center gap-1">
            <Notifications />
            <ThemeToggle />
            <div className="hidden px-2 text-right leading-tight sm:block">
              <div className="text-xs font-medium">{me.full_name}</div>
              <div className="text-[11px] text-muted">{me.role.replace(/_/g, " ")}</div>
            </div>
            <Button variant="ghost" size="sm" onClick={logout} aria-label="Sign out">
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </header>
        <main id="main" className="min-w-0 flex-1 p-4 lg:p-6">
          {!me.email_verified && (
            <div className="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-md border border-medium/40 bg-medium/10 px-3 py-2 text-xs text-medium" role="status">
              <span>{me.email_verification_required ? "Verify your email address to use the platform." : "Your email address is not verified."} Check your inbox for the link.</span>
              <Link href="/admin?tab=security" className="font-medium underline">Resend link</Link>
            </div>
          )}
          {children}
        </main>
      </div>
    </div>
  );
}
