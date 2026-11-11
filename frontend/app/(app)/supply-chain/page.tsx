"use client";

import { ModulePage } from "@/features/module-page";

export default function SupplyChainPage() {
  return (
    <ModulePage
      title="Containers & Supply Chain"
      description="Vulnerable dependencies, container images, infrastructure-as-code misconfigurations and committed secrets. SBOMs (CycloneDX, SPDX) are checked against OSV."
      module="supply_chain"
      domains={["supply_chain", "container", "iac", "secrets"]}
      allowImport
    />
  );
}
