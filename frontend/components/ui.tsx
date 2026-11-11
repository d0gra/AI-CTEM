"use client";

import clsx from "clsx";
import { AlertTriangle, Inbox, Loader2, X } from "lucide-react";
import { forwardRef, useEffect, useRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { titleCase } from "@/lib/format";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "sm" | "md"; loading?: boolean };

export function Button({ variant = "secondary", size = "md", loading, className, children, disabled, ...props }: ButtonProps) {
  return (
    <button
      {...props}
      disabled={disabled || loading}
      className={clsx(
        "inline-flex items-center justify-center gap-1.5 rounded-md border font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-9 px-3.5 text-sm",
        variant === "primary" && "border-transparent bg-accent text-accent-fg hover:opacity-90",
        variant === "secondary" && "border-border bg-surface text-text hover:bg-surface-2",
        variant === "ghost" && "border-transparent text-muted hover:bg-surface-2 hover:text-text",
        variant === "danger" && "border-transparent bg-critical text-white hover:opacity-90",
        className,
      )}
    >
      {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

const fieldClass =
  "w-full rounded-md border border-border bg-surface px-3 text-sm text-text placeholder:text-muted focus:border-accent disabled:opacity-60";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...props }, ref) {
  return <input ref={ref} {...props} className={clsx(fieldClass, "h-9", className)} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, children, ...props }, ref) {
  return (
    <select ref={ref} {...props} className={clsx(fieldClass, "h-9 pr-8", className)}>
      {children}
    </select>
  );
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...props }, ref) {
  return <textarea ref={ref} {...props} className={clsx(fieldClass, "min-h-20 py-2", className)} />;
});

export function Field({ label, error, hint, children }: { label: string; error?: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="text-xs font-medium text-muted">{label}</span>
      {children}
      {hint && !error && <span className="block text-xs text-muted">{hint}</span>}
      {error && (
        <span role="alert" className="block text-xs text-critical">
          {error}
        </span>
      )}
    </label>
  );
}

export function Card({ title, action, children, className }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={clsx("rounded-lg border border-border bg-surface", className)}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "critical" | "high" | "ok" }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <div className="text-xs font-medium text-muted">{label}</div>
      <div className={clsx("tabular mt-1 text-2xl font-semibold", tone === "critical" && "text-critical", tone === "high" && "text-high", tone === "ok" && "text-ok")}>
        {value}
      </div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

const toneClass: Record<string, string> = {
  critical: "border-critical/40 text-critical bg-critical/10",
  high: "border-high/40 text-high bg-high/10",
  medium: "border-medium/40 text-medium bg-medium/10",
  low: "border-low/40 text-low bg-low/10",
  info: "border-border text-muted bg-surface-2",
  ok: "border-ok/40 text-ok bg-ok/10",
};

export function Badge({ tone = "info", children }: { tone?: string; children: ReactNode }) {
  return (
    <span className={clsx("inline-flex items-center whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] font-medium leading-none", toneClass[tone] ?? toneClass.info)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ value }: { value: string | null | undefined }) {
  return <Badge tone={value ?? "info"}>{titleCase(value ?? "unknown")}</Badge>;
}

const statusTone: Record<string, string> = {
  new: "high", triaged: "medium", assigned: "medium", in_progress: "low", pending_validation: "low", remediated: "ok", closed: "ok",
  accepted_risk: "info", false_positive: "info", succeeded: "ok", ready: "ok", healthy: "ok", compliant: "ok", approved: "ok", done: "ok", sent: "ok",
  failed: "critical", dead: "critical", error: "critical", non_compliant: "critical", unapproved: "high", vulnerable: "critical",
  running: "low", queued: "info", verified: "critical", probable: "high", theoretical: "info", internet: "high", not_vulnerable: "ok",
};

export function StatusBadge({ value }: { value: string | null | undefined }) {
  return <Badge tone={statusTone[value ?? ""] ?? "info"}>{titleCase(value ?? "unknown")}</Badge>;
}

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={clsx("animate-pulse rounded bg-surface-2", className ?? "h-4 w-full")} />;
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-1 px-6 py-10 text-center">
      <Inbox className="h-6 w-6 text-muted" aria-hidden />
      <p className="text-sm font-medium">{title}</p>
      {children && <div className="max-w-md text-xs text-muted">{children}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center gap-2 px-6 py-8 text-center">
      <AlertTriangle className="h-6 w-6 text-critical" aria-hidden />
      <p className="text-sm">{message}</p>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Alert({ tone = "info", children }: { tone?: "info" | "critical" | "ok" | "medium"; children: ReactNode }) {
  return (
    <div role={tone === "critical" ? "alert" : "status"} className={clsx("rounded-md border px-3 py-2 text-xs", toneClass[tone])}>
      {children}
    </div>
  );
}

export function Dialog({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    if (open && !node.open) node.showModal();
    if (!open && node.open) node.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      aria-label={title}
      className={clsx("m-auto w-[calc(100%-2rem)] rounded-lg border border-border bg-surface p-0 text-text shadow-xl", wide ? "max-w-3xl" : "max-w-lg")}
    >
      {open && (
        <>
          <header className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-sm font-semibold">{title}</h2>
            <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-muted hover:bg-surface-2">
              <X className="h-4 w-4" />
            </button>
          </header>
          <div className="max-h-[75vh] overflow-y-auto p-4">{children}</div>
        </>
      )}
    </dialog>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-0.5 max-w-3xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; count?: number }[]; value: T; onChange: (id: T) => void }) {
  return (
    <div role="tablist" className="mb-4 flex gap-1 overflow-x-auto border-b border-border">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={tab.id === value}
          onClick={() => onChange(tab.id)}
          className={clsx(
            "-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm",
            tab.id === value ? "border-accent font-medium text-text" : "border-transparent text-muted hover:text-text",
          )}
        >
          {tab.label}
          {tab.count !== undefined && <span className="tabular ml-1.5 text-xs text-muted">{tab.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1.5 text-sm">
      {items.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-muted">{key}</dt>
          <dd className="min-w-0 break-words">{value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="max-h-80 overflow-auto rounded-md bg-surface-2 p-3 font-mono text-xs leading-relaxed">{JSON.stringify(value, null, 2)}</pre>;
}
