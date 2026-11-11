"use client";

import { useMutation, useQuery, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { api, type Params } from "./api";
import type { Me } from "@/types/api";

export function useGet<T>(path: string | null, params?: Params, options?: { refetchInterval?: number | false }) {
  return useQuery<T>({
    queryKey: [path, params ?? {}],
    queryFn: () => api<T>(path as string, { params }),
    enabled: path !== null,
    placeholderData: keepPreviousData,
    refetchInterval: options?.refetchInterval,
  });
}

/** Mutation that invalidates every cached query on success (data on most pages is interrelated). */
export function useAction<TBody = unknown, TResult = unknown>(
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  path: string | ((body: TBody) => string),
) {
  const client = useQueryClient();
  return useMutation<TResult, Error, TBody>({
    mutationFn: (body) =>
      api<TResult>(typeof path === "function" ? path(body) : path, {
        method,
        body: method === "DELETE" ? undefined : body,
      }),
    onSuccess: () => client.invalidateQueries(),
  });
}

export function useMe() {
  return useQuery<Me>({ queryKey: ["/auth/me"], queryFn: () => api<Me>("/auth/me"), retry: false, staleTime: 60_000 });
}

export function can(me: Me | undefined, ...permissions: string[]): boolean {
  return !!me && permissions.every((p) => me.permissions.includes(p));
}
