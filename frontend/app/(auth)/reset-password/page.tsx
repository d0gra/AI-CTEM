"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import { Alert, Button, Field, Input } from "@/components/ui";
import { api, errorMessage } from "@/lib/api";

function ResetForm() {
  const search = useSearchParams();
  const token = search.get("token") ?? "";
  const invited = search.get("invite") === "1";
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const password = String(form.get("password"));
    if (password !== String(form.get("confirm"))) {
      setError("The passwords do not match");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api("/auth/password/reset", { method: "POST", body: { token, new_password: password } });
      setDone(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  if (!token) return <Alert tone="critical">This link is incomplete. Request a new one.</Alert>;
  return done ? (
    <div className="space-y-3">
      <Alert tone="ok">{invited ? "Your password is set. Sign in to continue." : "Your password has been changed and all other sessions were signed out."}</Alert>
      <Link href="/login" className="block text-center text-sm text-accent hover:underline">Sign in</Link>
    </div>
  ) : (
    <form onSubmit={submit} className="space-y-3">
      <h1 className="text-base font-semibold">{invited ? "Welcome. Choose your password" : "Choose a new password"}</h1>
      {invited && <p className="text-xs text-muted">An administrator created an account for you. Invitation links expire 7 days after they are issued.</p>}
      {error && <Alert tone="critical">{error}</Alert>}
      <Field label="New password" hint="At least 12 characters."><Input type="password" name="password" required minLength={12} autoComplete="new-password" /></Field>
      <Field label="Confirm new password"><Input type="password" name="confirm" required minLength={12} autoComplete="new-password" /></Field>
      <Button type="submit" variant="primary" className="w-full" loading={busy}>Set password</Button>
    </form>
  );
}

export default function ResetPasswordPage() {
  return (
    <div className="space-y-3">
      <Suspense><ResetForm /></Suspense>
      <p className="text-center text-xs"><Link href="/forgot-password" className="text-accent hover:underline">Request a new link</Link></p>
    </div>
  );
}
