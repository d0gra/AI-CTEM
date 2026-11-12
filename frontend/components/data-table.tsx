"use client";

import { flexRender, getCoreRowModel, useReactTable, type ColumnDef, type SortingState } from "@tanstack/react-table";
import clsx from "clsx";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, Search, X } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState, type ReactNode } from "react";
import { errorMessage, type Params } from "@/lib/api";
import { useGet } from "@/lib/hooks";
import { titleCase } from "@/lib/format";
import type { Page } from "@/types/api";
import { Button, EmptyState, ErrorState, Input, Select, Skeleton } from "./ui";

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  sortable?: boolean;
  className?: string;
}

export interface Filter {
  key: string;
  label: string;
  options: string[] | { value: string; label: string }[];
}

interface Props<T> {
  path: string;
  columns: Column<T>[];
  params?: Params;
  filters?: Filter[];
  toggles?: { key: string; label: string }[];
  searchable?: boolean;
  searchPlaceholder?: string;
  defaultSort?: { key: string; order: "asc" | "desc" };
  rowHref?: (row: T) => string;
  pageSize?: number;
  empty?: { title: string; body?: ReactNode };
  refetchInterval?: number;
  /** Keep search, filters, sorting and page in the address bar so views can be bookmarked and linked to.
   *  Use on the main table of a page only: two URL-bound tables on one page would share parameters. */
  urlState?: boolean;
  /** Extra URL parameters forwarded to the API and shown as removable chips (for example a deep link's source). */
  passthrough?: { key: string; label: string }[];
}

type State = Record<string, string>;

/** Table state held either in the address bar or in component state. */
function useTableState(urlState: boolean, keys: string[]): [State, (changes: Record<string, string | null>) => void] {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [local, setLocal] = useState<State>({});
  const fromUrl: State = {};
  if (urlState) for (const key of keys) { const v = searchParams.get(key); if (v !== null && v !== "") fromUrl[key] = v; }
  const update = (changes: Record<string, string | null>) => {
    if (!urlState) {
      setLocal((current) => {
        const next = { ...current };
        for (const [k, v] of Object.entries(changes)) { if (v === null || v === "") delete next[k]; else next[k] = v; }
        return next;
      });
      return;
    }
    const next = new URLSearchParams(window.location.search);
    for (const [k, v] of Object.entries(changes)) { if (v === null || v === "") next.delete(k); else next.set(k, v); }
    const text = next.toString();
    router.replace(text ? `${pathname}?${text}` : pathname, { scroll: false });
  };
  return [urlState ? fromUrl : local, update];
}

export function DataTable<T extends { id?: string }>(props: Props<T>) {
  return (
    <Suspense fallback={<div className="rounded-lg border border-border bg-surface p-4"><Skeleton className="h-24" /></div>}>
      <Table {...props} />
    </Suspense>
  );
}

/** Server-driven table: pagination, sorting, search and filters are all sent to the API. */
function Table<T extends { id?: string }>({
  path, columns, params, filters = [], toggles = [], searchable, searchPlaceholder, defaultSort, rowHref, pageSize = 25, empty, refetchInterval,
  urlState = false, passthrough = [],
}: Props<T>) {
  const router = useRouter();
  const keys = ["q", "page", "sort", "order", ...filters.map((f) => f.key), ...toggles.map((t) => t.key), ...passthrough.map((p) => p.key)];
  const [state, update] = useTableState(urlState, keys);
  const page = Math.max(1, Number(state.page) || 1);
  const setPage = (next: number) => update({ page: next > 1 ? String(next) : null });
  const [search, setSearch] = useState(state.q ?? "");
  const sorting: SortingState = state.sort
    ? [{ id: state.sort, desc: state.order !== "asc" }]
    : defaultSort ? [{ id: defaultSort.key, desc: defaultSort.order === "desc" }] : [];

  useEffect(() => {
    const timer = setTimeout(() => {
      if (search.trim() !== (state.q ?? "")) update({ q: search.trim() || null, page: null });
    }, 300);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the typed text should restart the debounce
  }, [search]);

  const selected: Params = Object.fromEntries(filters.filter((f) => state[f.key]).map((f) => [f.key, state[f.key]]));
  const flags: Params = Object.fromEntries(toggles.filter((t) => state[t.key] === "true").map((t) => [t.key, true]));
  const extra: Params = Object.fromEntries(passthrough.filter((p) => state[p.key]).map((p) => [p.key, state[p.key]]));
  const query: Params = {
    ...params,
    ...extra,
    ...selected,
    ...flags,
    page,
    page_size: pageSize,
    q: state.q || undefined,
    sort: sorting[0]?.id,
    order: sorting[0] ? (sorting[0].desc ? "desc" : "asc") : undefined,
  };
  const { data, error, isLoading, isFetching, refetch } = useGet<Page<T>>(path, query, { refetchInterval });

  const defs = useMemo<ColumnDef<T>[]>(
    () =>
      columns.map((c) => ({
        id: c.key,
        accessorFn: (row) => (row as Record<string, unknown>)[c.key],
        header: c.header,
        enableSorting: !!c.sortable,
        cell: ({ row }) => (c.render ? c.render(row.original) : String((row.original as Record<string, unknown>)[c.key] ?? "—")),
      })),
    [columns],
  );
  const table = useReactTable({
    data: data?.items ?? [],
    columns: defs,
    state: { sorting },
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      update({ sort: next[0]?.id ?? null, order: next[0] ? (next[0].desc ? "desc" : "asc") : null, page: null });
    },
    manualSorting: true,
    manualPagination: true,
    enableSortingRemoval: false,
    getCoreRowModel: getCoreRowModel(),
  });

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const chips = passthrough.filter((p) => state[p.key]);
  const hasControls = searchable || filters.length > 0 || toggles.length > 0 || chips.length > 0;

  return (
    <div className="rounded-lg border border-border bg-surface">
      {hasControls && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          {searchable && (
            <div className="relative min-w-52 flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" aria-hidden />
              <Input aria-label="Search" placeholder={searchPlaceholder ?? "Search"} value={search} onChange={(e) => setSearch(e.target.value)} className="pl-8" />
            </div>
          )}
          {filters.map((f) => (
            <Select
              key={f.key}
              aria-label={f.label}
              className="w-auto min-w-32"
              value={state[f.key] ?? ""}
              onChange={(e) => update({ [f.key]: e.target.value || null, page: null })}
            >
              <option value="">{f.label}: all</option>
              {f.options.map((o) => {
                const option = typeof o === "string" ? { value: o, label: titleCase(o) } : o;
                return (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                );
              })}
            </Select>
          ))}
          {toggles.map((t) => (
            <label key={t.key} className="flex items-center gap-1.5 text-xs text-muted">
              <input
                type="checkbox"
                checked={state[t.key] === "true"}
                onChange={(e) => update({ [t.key]: e.target.checked ? "true" : null, page: null })}
              />
              {t.label}
            </label>
          ))}
          {chips.map((p) => (
            <span key={p.key} className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2 py-1 text-xs">
              {p.label}: <span className="font-mono">{state[p.key]}</span>
              <button type="button" aria-label={`Clear ${p.label}`} onClick={() => update({ [p.key]: null, page: null })} className="rounded text-muted hover:text-text"><X className="h-3 w-3" /></button>
            </span>
          ))}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-border text-xs text-muted">
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  return (
                    <th key={header.id} scope="col" aria-sort={sorted ? (sorted === "desc" ? "descending" : "ascending") : undefined} className="whitespace-nowrap px-3 py-2 font-medium">
                      {header.column.getCanSort() ? (
                        <button type="button" onClick={header.column.getToggleSortingHandler()} className="inline-flex items-center gap-1 hover:text-text">
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {sorted === "desc" && <ArrowDown className="h-3 w-3" aria-hidden />}
                          {sorted === "asc" && <ArrowUp className="h-3 w-3" aria-hidden />}
                        </button>
                      ) : (
                        flexRender(header.column.columnDef.header, header.getContext())
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody className={clsx(isFetching && !isLoading && "opacity-60")}>
            {isLoading &&
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="border-b border-border last:border-0">
                  {columns.map((c) => (
                    <td key={c.key} className="px-3 py-2.5">
                      <Skeleton />
                    </td>
                  ))}
                </tr>
              ))}
            {!isLoading &&
              table.getRowModel().rows.map((row) => {
                const href = rowHref?.(row.original);
                return (
                  <tr
                    key={row.id}
                    tabIndex={href ? 0 : undefined}
                    onClick={href ? () => router.push(href) : undefined}
                    onKeyDown={href ? (e) => e.key === "Enter" && router.push(href) : undefined}
                    className={clsx("border-b border-border last:border-0", href && "cursor-pointer hover:bg-surface-2")}
                  >
                    {row.getVisibleCells().map((cell, index) => (
                      <td key={cell.id} className={clsx("px-3 py-2 align-middle", columns[index]?.className)}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>
      {error && <ErrorState message={errorMessage(error)} onRetry={() => refetch()} />}
      {!error && !isLoading && total === 0 && <EmptyState title={empty?.title ?? "Nothing to show"}>{empty?.body}</EmptyState>}
      {total > 0 && (
        <div className="flex items-center justify-between border-t border-border px-3 py-2 text-xs text-muted">
          <span className="tabular">
            {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
          </span>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="ghost" aria-label="Previous page" disabled={page <= 1} onClick={() => setPage(page - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="tabular">
              Page {page} of {pages}
            </span>
            <Button size="sm" variant="ghost" aria-label="Next page" disabled={page >= pages} onClick={() => setPage(page + 1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
