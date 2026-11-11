"use client";

import { PageHeader } from "@/components/ui";
import { FindingsTable } from "@/features/findings-table";

export default function FindingsPage() {
  return (
    <>
      <PageHeader title="Findings" description="Every finding across all modules, ranked by contextual risk. Sorting, filtering and paging are performed by the server." />
      <FindingsTable />
    </>
  );
}
