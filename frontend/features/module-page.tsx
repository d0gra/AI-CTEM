"use client";

import type { ReactNode } from "react";
import { PageHeader, Stat } from "@/components/ui";
import { useGet } from "@/lib/hooks";
import { titleCase } from "@/lib/format";
import type { Obj } from "@/types/api";
import { AssessmentsPanel } from "./assessments";
import { FindingsTable } from "./findings-table";

/** Shared layout for security modules: open-finding counts, the module's assessments and its findings. */
export function ModulePage({ title, description, module, domains, allowImport, children }: {
  title: string; description: string; module: string; domains: string[]; allowImport?: boolean; children?: ReactNode;
}) {
  const { data } = useGet<Obj>("/dashboard/overview");
  const byDomain: Record<string, number> = data?.findings?.by_domain ?? {};
  return (
    <>
      <PageHeader title={title} description={description} />
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        {domains.slice(0, 4).map((d) => (
          <Stat key={d} label={`Open ${titleCase(d)} findings`} value={data ? byDomain[d] ?? 0 : "—"} />
        ))}
      </div>
      <div className="space-y-4">
        {children}
        <AssessmentsPanel module={module} allowImport={allowImport} />
        <FindingsTable params={{ domain: domains }} />
      </div>
    </>
  );
}
