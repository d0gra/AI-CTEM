"use client";

import { ModulePage } from "@/features/module-page";

export default function AttackSurfacePage() {
  return (
    <ModulePage
      title="Attack Surface"
      description="Externally reachable assets and the weaknesses visible from outside: DNS, certificates, HTTP services, exposed management interfaces and network services."
      module="attack_surface"
      domains={["attack_surface", "network", "web"]}
      allowImport
    />
  );
}
