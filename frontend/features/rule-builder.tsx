"use client";

import { Plus, Trash2 } from "lucide-react";
import { useId, useState } from "react";
import { Button, Input, Select, Textarea } from "@/components/ui";
import type { Obj } from "@/types/api";

/** Policy rule language (see backend app/domains/policy/rules.py):
 *  {field, op, value} | {all: [rule]} | {any: [rule]} | {not: rule}; {} matches everything. */
export type Rule = Obj;

const UNARY = new Set(["exists", "not_exists", "is_true", "is_false"]);
const LIST = new Set(["in", "not_in"]);
const NUMERIC = new Set(["gt", "gte", "lt", "lte"]);
const OP_LABEL: Record<string, string> = {
  eq: "equals", ne: "does not equal", in: "is one of", not_in: "is none of", exists: "is recorded", not_exists: "is not recorded",
  gt: ">", gte: "≥", lt: "<", lte: "≤", contains: "contains", is_true: "is yes", is_false: "is no",
};

type Row = { field: string; op: string; value: string };

function parseValue(op: string, text: string): unknown {
  if (UNARY.has(op)) return undefined;
  if (LIST.has(op)) return text.split(",").map((v) => v.trim()).filter(Boolean);
  if (NUMERIC.has(op)) return Number(text);
  if (text === "true" || text === "false") return text === "true";
  return text;
}

function rowToRule(r: Row): Rule {
  const value = parseValue(r.op, r.value);
  return value === undefined ? { field: r.field, op: r.op } : { field: r.field, op: r.op, value };
}

function isLeaf(rule: Rule): boolean {
  return typeof rule?.field === "string" && typeof rule?.op === "string";
}

function leafToRow(rule: Rule): Row {
  const v = rule.value;
  return { field: rule.field, op: rule.op, value: v === undefined || v === null ? "" : Array.isArray(v) ? v.join(", ") : String(v) };
}

/** Rows editable in the builder, or null when the rule needs the JSON editor (nesting, "not"). */
function toRows(rule: Rule): { mode: "all" | "any"; rows: Row[] } | null {
  if (!rule || Object.keys(rule).length === 0) return { mode: "all", rows: [] };
  if (isLeaf(rule)) return { mode: "all", rows: [leafToRow(rule)] };
  for (const mode of ["all", "any"] as const) {
    const items = rule[mode];
    if (Array.isArray(items) && Object.keys(rule).length === 1 && items.every(isLeaf)) return { mode, rows: items.map(leafToRow) };
  }
  return null;
}

function fromRows(mode: "all" | "any", rows: Row[]): Rule {
  const complete = rows.filter((r) => r.field && r.op);
  if (complete.length === 0) return {};
  if (complete.length === 1) return rowToRule(complete[0]);
  return { [mode]: complete.map(rowToRule) };
}

/** Plain-language rendering of a rule, for read-only display. */
export function describeRule(rule: Rule): string {
  if (!rule || Object.keys(rule).length === 0) return "everything";
  if (isLeaf(rule)) {
    const v = rule.value;
    const shown = UNARY.has(rule.op) ? "" : ` ${Array.isArray(v) ? v.join(", ") : String(v)}`;
    return `${rule.field} ${OP_LABEL[rule.op] ?? rule.op}${shown}`;
  }
  if (Array.isArray(rule.all)) return rule.all.map((r: Rule) => (isLeaf(r) ? describeRule(r) : `(${describeRule(r)})`)).join(" and ");
  if (Array.isArray(rule.any)) return rule.any.map((r: Rule) => (isLeaf(r) ? describeRule(r) : `(${describeRule(r)})`)).join(" or ");
  if (rule.not) return `not (${describeRule(rule.not)})`;
  return JSON.stringify(rule);
}

export function RuleBuilder({ initial, fields, operators, emptyLabel, onChange }: {
  initial: Rule; fields: string[]; operators: string[]; emptyLabel: string; onChange: (rule: Rule | null) => void;
}) {
  const listId = useId();
  const parsed = toRows(initial);
  const [json, setJson] = useState<string | null>(parsed ? null : JSON.stringify(initial, null, 2));
  const [mode, setMode] = useState<"all" | "any">(parsed?.mode ?? "all");
  const [rows, setRows] = useState<Row[]>(parsed?.rows ?? []);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const ops = operators.length ? operators : Object.keys(OP_LABEL);
  const fieldOptions = fields.map((f) => (f.endsWith(".*") ? f.slice(0, -1) : f));

  const commit = (nextMode: "all" | "any", nextRows: Row[]) => {
    setMode(nextMode);
    setRows(nextRows);
    onChange(fromRows(nextMode, nextRows));
  };
  const change = (i: number, patch: Partial<Row>) => commit(mode, rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  if (json !== null) {
    return (
      <div className="space-y-1.5">
        <Textarea className="font-mono text-xs" rows={6} value={json} onChange={(e) => {
          setJson(e.target.value);
          try {
            onChange(JSON.parse(e.target.value || "{}"));
            setJsonError(null);
          } catch {
            onChange(null);
            setJsonError("Not valid JSON yet.");
          }
        }} />
        <div className="flex items-center justify-between text-xs">
          <span className={jsonError ? "text-critical" : "text-muted"}>{jsonError ?? 'Combine rules with {"all": [...]}, {"any": [...]} or {"not": {...}}.'}</span>
          <Button size="sm" type="button" variant="ghost" onClick={() => {
            try {
              const back = toRows(JSON.parse(json || "{}"));
              if (!back) { setJsonError("This rule uses nesting or “not”, which only the JSON editor can show."); return; }
              setJson(null);
              commit(back.mode, back.rows);
            } catch {
              setJsonError("Fix the JSON before switching back.");
            }
          }}>Use the form</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <datalist id={listId}>{fieldOptions.map((f) => <option key={f} value={f} />)}</datalist>
      {rows.length === 0 && <p className="text-xs text-muted">{emptyLabel}</p>}
      {rows.length > 1 && (
        <div className="flex items-center gap-2 text-xs">
          Match
          <Select aria-label="Combine conditions" value={mode} onChange={(e) => commit(e.target.value as "all" | "any", rows)} className="h-7 w-auto text-xs">
            <option value="all">all of these</option><option value="any">any of these</option>
          </Select>
        </div>
      )}
      {rows.map((r, i) => (
        <div key={i} className="grid grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_minmax(0,1.3fr)_auto] gap-2">
          <Input aria-label="Field" list={listId} value={r.field} placeholder="field, e.g. exposure" onChange={(e) => change(i, { field: e.target.value })} className="font-mono text-xs" />
          <Select aria-label="Operator" value={r.op} onChange={(e) => change(i, { op: e.target.value })}>
            {ops.map((o) => <option key={o} value={o}>{OP_LABEL[o] ?? o}</option>)}
          </Select>
          {UNARY.has(r.op) ? <span /> : (
            <Input aria-label="Value" value={r.value} type={NUMERIC.has(r.op) ? "number" : "text"} onChange={(e) => change(i, { value: e.target.value })}
                   placeholder={LIST.has(r.op) ? "comma-separated values" : "value"} />
          )}
          <Button type="button" size="md" variant="ghost" aria-label="Remove condition" onClick={() => commit(mode, rows.filter((_, j) => j !== i))}><Trash2 className="h-4 w-4" /></Button>
        </div>
      ))}
      <div className="flex items-center justify-between">
        <Button size="sm" type="button" onClick={() => commit(mode, [...rows, { field: "", op: "eq", value: "" }])}><Plus className="h-3.5 w-3.5" /> Add condition</Button>
        <Button size="sm" type="button" variant="ghost" onClick={() => setJson(JSON.stringify(fromRows(mode, rows), null, 2))}>Edit as JSON</Button>
      </div>
    </div>
  );
}
