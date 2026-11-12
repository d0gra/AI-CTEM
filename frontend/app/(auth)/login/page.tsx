"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { Alert, Button, Field, Input } from "@/components/ui";
import { api, errorMessage, setCsrf } from "@/lib/api";
import { loginSchema, type LoginValues } from "@/lib/schemas";

type DemoInfo = { password: string; accounts: { role: string; email: string; name: string; purpose: string }[]; restrictions: string[] };

/** On a public demo deployment, lists the shared accounts (one per role) with one-click sign-in. */
function DemoAccounts({ info, onPick, busy }: { info: DemoInfo; onPick: (email: string, password: string) => void; busy: string | null }) {
  return (
    <div className="space-y-2 border-t border-border pt-4">
      <h2 className="text-sm font-semibold">Demo accounts</h2>
      <p className="text-xs text-muted">Every role has its own account. Password for all: <code className="rounded bg-surface-2 px-1 font-mono">{info.password}</code></p>
      <ul className="divide-y divide-border rounded-md border border-border">
        {info.accounts.map((a) => (
          <li key={a.email} className="flex items-center justify-between gap-2 px-2.5 py-1.5">
            <div className="min-w-0">
              <div className="truncate text-xs font-medium">{a.name.replace(/^Demo /, "")}</div>
              <div className="truncate font-mono text-[11px] text-muted" title={a.purpose}>{a.email}</div>
            </div>
            <Button size="sm" type="button" loading={busy === a.email} disabled={!!busy} onClick={() => onPick(a.email, info.password)}>Sign in</Button>
          </li>
        ))}
      </ul>
      <ul className="list-disc space-y-0.5 pl-4 text-[11px] text-muted">{info.restrictions.map((r) => <li key={r}>{r}</li>)}</ul>
    </div>
  );
}

function LoginForm() {
  const router = useRouter();
  const search = useSearchParams();
  const [needsMfa, setNeedsMfa] = useState(search.get("mfa") === "1");
  const [error, setError] = useState<string | null>(null);
  const [demoBusy, setDemoBusy] = useState<string | null>(null);
  const [demo, setDemo] = useState<DemoInfo | null>(null);
  useEffect(() => {
    api<DemoInfo>("/demo")
      .then((info) => setDemo(Array.isArray(info?.accounts) ? info : null))
      .catch(() => setDemo(null)); // 404 outside demo mode
  }, []);
  const { register, handleSubmit, formState } = useForm<LoginValues>({ resolver: zodResolver(loginSchema), defaultValues: { email: "", password: "", totp_code: "" } });

  const signIn = async (values: LoginValues) => {
    setError(null);
    try {
      const result = await api<{ mfa_required: boolean; csrf_token: string }>("/auth/login", {
        method: "POST",
        body: { email: values.email, password: values.password, totp_code: values.totp_code || null },
      });
      setCsrf(result.csrf_token);
      if (result.mfa_required) {
        setNeedsMfa(true);
        setError("Enter the 6-digit code from your authenticator app.");
        return;
      }
      router.replace("/overview");
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const onSubmit = handleSubmit(signIn);
  const demoSignIn = async (email: string, password: string) => {
    setDemoBusy(email);
    await signIn({ email, password, totp_code: "" });
    setDemoBusy(null);
  };

  return (
    <div className="space-y-4">
    <form onSubmit={onSubmit} noValidate className="space-y-3">
      <h1 className="text-base font-semibold">Sign in</h1>
      {search.get("registered") && <Alert tone="ok">Organization created. Sign in to continue.</Alert>}
      {error && <Alert tone="critical">{error}</Alert>}
      <Field label="Email" error={formState.errors.email?.message}>
        <Input type="email" autoComplete="username" {...register("email")} />
      </Field>
      <div className="-mb-2 text-right"><Link href="/forgot-password" className="text-xs text-accent hover:underline">Forgot password?</Link></div>
      <Field label="Password" error={formState.errors.password?.message}>
        <Input type="password" autoComplete="current-password" {...register("password")} />
      </Field>
      {needsMfa && (
        <Field label="Verification code" error={formState.errors.totp_code?.message}>
          <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} {...register("totp_code")} />
        </Field>
      )}
      <Button type="submit" variant="primary" className="w-full" loading={formState.isSubmitting}>
        Sign in
      </Button>
      {!demo && <p className="text-center text-xs text-muted">
        New organization?{" "}
        <Link href="/register" className="text-accent hover:underline">
          Create an account
        </Link>
      </p>}
    </form>
    {demo && <DemoAccounts info={demo} onPick={demoSignIn} busy={demoBusy} />}
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
