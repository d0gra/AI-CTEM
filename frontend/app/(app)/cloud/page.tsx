"use client";

import { ModulePage } from "@/features/module-page";

export default function CloudPage() {
  return (
    <ModulePage
      title="Cloud Security"
      description="Cloud misconfigurations, public exposure, logging gaps and risky network rules. AWS is assessed natively; Azure and GCP are ingested from Prowler output."
      module="cloud"
      domains={["cloud", "identity", "container", "iac"]}
      allowImport
    />
  );
}
