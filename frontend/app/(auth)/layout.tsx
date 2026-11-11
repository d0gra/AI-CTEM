import { Activity } from "lucide-react";
import type { ReactNode } from "react";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="mb-5 flex items-center justify-center gap-2">
          <Activity className="h-5 w-5 text-accent" aria-hidden />
          <span className="text-base font-semibold tracking-tight">CTEM Platform</span>
        </div>
        <div className="rounded-lg border border-border bg-surface p-5">{children}</div>
      </div>
    </main>
  );
}
