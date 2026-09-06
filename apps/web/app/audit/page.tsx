"use client";

import { useCallback, useEffect, useState } from "react";
import { decisionBadgeClass, decisionLabel, fmtTime } from "../_lib/runui";

type AuditEntry = {
  id: number;
  run_id: number;
  tool: string;
  target: string;
  decision: string; // allowed | blocked_out_of_scope | blocked_non_prod
  reason: string | null;
  ts: string;
  program_name: string;
  platform: string;
};

export default function AuditPage() {
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [runId, setRunId] = useState("");
  const [target, setTarget] = useState("");
  const [runIdInput, setRunIdInput] = useState("");
  const [targetInput, setTargetInput] = useState("");

  const load = useCallback(async (rid: string, tgt: string) => {
    setLoading(true);
    const params = new URLSearchParams();
    if (rid) params.set("run_id", rid);
    if (tgt) params.set("target", tgt);
    try {
      const res = await fetch(`/api/audit?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setItems(data.items ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load("", "");
  }, [load]);

  // debounce ô lọc
  useEffect(() => {
    const t = setTimeout(() => {
      setRunId(runIdInput);
      setTarget(targetInput);
    }, 400);
    return () => clearTimeout(t);
  }, [runIdInput, targetInput]);

  useEffect(() => {
    if (runId !== "" || target !== "") load(runId, target);
  }, [runId, target, load]);

  const blocked = items.filter((a) => a.decision !== "allowed").length;

  return (
    <main className="page wide">
      <div className="pagehead">
        <div>
          <h1>Audit — Scope Validator</h1>
          <p className="sub">
            Mọi target mà Tool Execution định chạm tới đều được ghi lại — cả khi
            được phép lẫn khi bị chặn cứng.
          </p>
        </div>
      </div>

      <div className="toolbar">
        <input
          type="number"
          min="1"
          placeholder="Lọc theo Run #"
          value={runIdInput}
          onChange={(e) => setRunIdInput(e.target.value)}
          style={{ maxWidth: 140 }}
        />
        <input
          placeholder="Lọc theo asset (target)…"
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
        />
      </div>

      {error && <p className="alert">{error}</p>}

      <table className="tbl">
        <thead>
          <tr>
            <th>Thời gian</th>
            <th>Run</th>
            <th>Program</th>
            <th>Tool</th>
            <th>Target</th>
            <th>Quyết định</th>
            <th>Lý do</th>
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr><td colSpan={7}>Đang tải…</td></tr>
          )}
          {!loading && items.length === 0 && (
            <tr><td colSpan={7}>Chưa có mục audit nào.</td></tr>
          )}
          {items.map((a) => (
            <tr key={a.id}>
              <td>{fmtTime(a.ts)}</td>
              <td>
                <a className="plink" href={`/runs/${a.run_id}`}>#{a.run_id}</a>
              </td>
              <td>{a.program_name}</td>
              <td><code>{a.tool}</code></td>
              <td><code>{a.target}</code></td>
              <td>
                <span className={decisionBadgeClass(a.decision)}>
                  {decisionLabel(a.decision)}
                </span>
              </td>
              <td className="note">{a.reason ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {!loading && items.length > 0 && (
        <p className="updated">
          {items.length} mục · trong đó {blocked} bị chặn
        </p>
      )}
    </main>
  );
}
