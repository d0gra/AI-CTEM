"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Alert, Button, Field, Input } from "@/components/ui";
import { api, errorMessage } from "@/lib/api";

export default function ForgotPasswordPage() {
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/auth/password/forgot", { method: "POST", body: { email: String(new FormData(e.currentTarget).get("email")) } });
      setSent(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-3">
      <h1 className="text-base font-semibold">Reset your password</h1>
      {sent ? (
        <Alert tone="ok">If an account exists for that address, a reset link has been sent. The link is valid for one hour.</Alert>
      ) : (
        <form onSubmit={submit} className="space-y-3">
          {error && <Alert tone="critical">{error}</Alert>}
          <Field label="Email"><Input type="email" name="email" required autoComplete="username" /></Field>
          <Button type="submit" variant="primary" className="w-full" loading={busy}>Send reset link</Button>
        </form>
      )}
      <p className="text-center text-xs"><Link href="/login" className="text-accent hover:underline">Back to sign in</Link></p>
    </div>
  );
}
