"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { Alert, Skeleton } from "@/components/ui";
import { api, errorMessage } from "@/lib/api";

function Verify() {
  const token = useSearchParams().get("token") ?? "";
  const [state, setState] = useState<"pending" | "ok" | "error">(token ? "pending" : "error");
  const [error, setError] = useState(token ? "" : "This verification link is incomplete.");
  const started = useRef(false);
  useEffect(() => {
    if (!token || started.current) return;
    started.current = true; // tokens are single-use; never submit twice
    api("/auth/email/verify", { method: "POST", body: { token } })
      .then(() => setState("ok"))
      .catch((err) => { setState("error"); setError(errorMessage(err)); });
  }, [token]);
  if (state === "pending") return <Skeleton className="h-10" />;
  return state === "ok" ? <Alert tone="ok">Your email address is verified.</Alert> : <Alert tone="critical">{error}</Alert>;
}

export default function VerifyEmailPage() {
  return (
    <div className="space-y-3">
      <h1 className="text-base font-semibold">Email verification</h1>
      <Suspense><Verify /></Suspense>
      <p className="text-center text-xs"><Link href="/overview" className="text-accent hover:underline">Continue to the platform</Link></p>
    </div>
  );
}
