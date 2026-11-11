"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { useForm } from "react-hook-form";
import { Alert, Button, Field, Input } from "@/components/ui";
import { api, errorMessage, setCsrf } from "@/lib/api";
import { loginSchema, type LoginValues } from "@/lib/schemas";

function LoginForm() {
  const router = useRouter();
  const search = useSearchParams();
  const [needsMfa, setNeedsMfa] = useState(search.get("mfa") === "1");
  const [error, setError] = useState<string | null>(null);
  const { register, handleSubmit, formState } = useForm<LoginValues>({ resolver: zodResolver(loginSchema), defaultValues: { email: "", password: "", totp_code: "" } });

  const onSubmit = handleSubmit(async (values) => {
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
  });

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-3">
      <h1 className="text-base font-semibold">Sign in</h1>
      {search.get("registered") && <Alert tone="ok">Organization created. Sign in to continue.</Alert>}
      {error && <Alert tone="critical">{error}</Alert>}
      <Field label="Email" error={formState.errors.email?.message}>
        <Input type="email" autoComplete="username" {...register("email")} />
      </Field>
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
      <p className="text-center text-xs text-muted">
        New organization?{" "}
        <Link href="/register" className="text-accent hover:underline">
          Create an account
        </Link>
      </p>
    </form>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
