"use client";

import { ModulePage } from "@/features/module-page";

export default function WebApiPage() {
  return (
    <ModulePage
      title="Web & API Security"
      description="Web application and API weaknesses from OpenAPI analysis, safe read-only probes, static analysis and imported DAST results."
      module="web_api"
      domains={["web", "api"]}
      allowImport
    />
  );
}
