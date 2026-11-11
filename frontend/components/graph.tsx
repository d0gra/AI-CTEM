"use client";

import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";

export interface GraphNode {
  id: string;
  label: string;
  sub?: string;
  tone?: "critical" | "high" | "accent" | "muted";
  column?: number;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  tone?: "critical" | "high" | "muted";
  dashed?: boolean;
}

const toneColor = { critical: "var(--critical)", high: "var(--high)", accent: "var(--accent)", muted: "var(--border)" } as const;

/** Lays nodes out in columns (explicit `column`, or breadth-first depth from `rootId`). */
export function Graph({ nodes, edges, rootId, height = 420, onNodeClick }: {
  nodes: GraphNode[]; edges: GraphEdge[]; rootId?: string; height?: number; onNodeClick?: (id: string) => void;
}) {
  const { flowNodes, flowEdges } = useMemo(() => {
    const depth = new Map<string, number>();
    if (nodes.every((n) => n.column !== undefined)) nodes.forEach((n) => depth.set(n.id, n.column as number));
    else {
      const start = rootId ?? nodes[0]?.id;
      const queue = start ? [start] : [];
      if (start) depth.set(start, 0);
      while (queue.length) {
        const current = queue.shift() as string;
        for (const e of edges) {
          const next = e.source === current ? e.target : e.target === current ? e.source : null;
          if (next && !depth.has(next)) {
            depth.set(next, (depth.get(current) ?? 0) + 1);
            queue.push(next);
          }
        }
      }
      nodes.forEach((n) => !depth.has(n.id) && depth.set(n.id, 0));
    }
    const perColumn = new Map<number, number>();
    const flowNodes: Node[] = nodes.map((n) => {
      const column = depth.get(n.id) ?? 0;
      const row = perColumn.get(column) ?? 0;
      perColumn.set(column, row + 1);
      return {
        id: n.id,
        position: { x: column * 250, y: row * 86 },
        data: { label: (<div className="text-left"><div className="truncate text-xs font-medium">{n.label}</div>{n.sub && <div className="truncate text-[10px] opacity-70">{n.sub}</div>}</div>) },
        style: { width: 200, borderRadius: 8, border: `1.5px solid ${toneColor[n.tone ?? "muted"]}`, background: "var(--surface)", color: "var(--text)", padding: "6px 10px" },
        sourcePosition: "right" as Node["sourcePosition"],
        targetPosition: "left" as Node["targetPosition"],
      };
    });
    const flowEdges: Edge[] = edges.map((e) => ({
      id: e.id, source: e.source, target: e.target, label: e.label,
      labelStyle: { fontSize: 10, fill: "var(--muted)" }, labelBgStyle: { fill: "var(--surface)" },
      style: { stroke: toneColor[e.tone ?? "muted"], strokeWidth: 1.5, strokeDasharray: e.dashed ? "5 4" : undefined },
      markerEnd: { type: MarkerType.ArrowClosed, color: toneColor[e.tone ?? "muted"] },
    }));
    return { flowNodes, flowEdges };
  }, [nodes, edges, rootId]);

  return (
    <div style={{ height }} className="rounded-md border border-border bg-surface-2" role="img" aria-label={`Graph with ${nodes.length} nodes and ${edges.length} relationships`}>
      <ReactFlow nodes={flowNodes} edges={flowEdges} fitView nodesDraggable nodesConnectable={false} proOptions={{ hideAttribution: true }}
                 onNodeClick={onNodeClick ? (_e, node) => onNodeClick(node.id) : undefined} minZoom={0.2}>
        <Background color="var(--border)" gap={18} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
