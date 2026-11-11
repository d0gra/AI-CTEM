"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Alert, Button, Field, Input } from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { registerSchema, type RegisterValues } from "@/lib/schemas";

export default function RegisterPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const { register, handleSubmit, formState } = useForm<RegisterValues>({ resolver: zodResolver(registerSchema) });

  const onSubmit = handleSubmit(async (values) => {
    setError(null);
    try {
      await api("/auth/register", { method: "POST", body: values });
      router.replace("/login?registered=1");
    } catch (e) {
      setError(errorMessage(e));
    }
  });

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-3">
      <h1 className="text-base font-semibold">Create an organization</h1>
      {error && <Alert tone="critical">{error}</Alert>}
      <Field label="Organization name" error={formState.errors.organization_name?.message}>
        <Input autoComplete="organization" {...register("organization_name")} />
      </Field>
      <Field label="Your name" error={formState.errors.full_name?.message}>
        <Input autoComplete="name" {...register("full_name")} />
      </Field>
      <Field label="Work email" error={formState.errors.email?.message}>
        <Input type="email" autoComplete="username" {...register("email")} />
      </Field>
      <Field label="Password" error={formState.errors.password?.message} hint="At least 12 characters.">
        <Input type="password" autoComplete="new-password" {...register("password")} />
      </Field>
      <Button type="submit" variant="primary" className="w-full" loading={formState.isSubmitting}>
        Create organization
      </Button>
      <p className="text-center text-xs text-muted">
        Already registered?{" "}
        <Link href="/login" className="text-accent hover:underline">
          Sign in
        </Link>
      </p>
    </form>
  );
}
