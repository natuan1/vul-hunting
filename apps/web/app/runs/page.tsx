"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fmtTime, statusBadgeClass } from "../_lib/runui";

type Run = {
  id: number;
  program_id: number;
  program_name: string;
  program_handle: string;
  platform: string;
  status: string;
  rate_limit_rps: number | null;
  ident_header_name: string | null;
  ident_header_value: string | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  subdomains: number;
  live_hosts: number;
};

export default function RunsPage() {
  const [items, setItems] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    const res = await fetch("/api/runs");
    if (!res.ok) {
      setError(`Không tải được danh sách Run (HTTP ${res.status})`);
      return;
    }
    setError(null);
    const data = await res.json();
    setItems(data.items ?? []);
    return data.items as Run[];
  }, []);

  useEffect(() => {
    (async () => {
      const list = await load();
      setLoading(false);
      if (list?.some((r) => r.status === "pending" || r.status === "running")) {
        pollRef.current = setInterval(async () => {
          const next = await load();
          if (!next?.some((r) => r.status === "pending" || r.status === "running")) {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
          }
        }, 3000);
      }
    })();
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [load]);

  return (
    <main className="page wide">
      <div className="pagehead">
        <div>
          <h1>Runs</h1>
          <p className="sub">
            Các lần quét Program — mỗi Run giữ Scope snapshot, config (rate limit,
            header định danh) và log Tool Execution theo thời gian thực.
          </p>
        </div>
      </div>

      {error && <p className="alert">{error}</p>}

      <table className="tbl">
        <thead>
          <tr>
            <th>Run</th>
            <th>Program</th>
            <th>Status</th>
            <th>Subdomain</th>
            <th>Live host</th>
            <th>Rate limit</th>
            <th>Header định danh</th>
            <th>Bắt đầu</th>
            <th>Kết thúc</th>
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr><td colSpan={9}>Đang tải…</td></tr>
          )}
          {!loading && items.length === 0 && (
            <tr>
              <td colSpan={9}>
                Chưa có Run nào — mở một Program rồi bấm “Chạy Run”.
              </td>
            </tr>
          )}
          {items.map((r) => (
            <tr key={r.id}>
              <td>
                <a className="plink" href={`/runs/${r.id}`}>
                  <span className="pname">#{r.id}</span>
                </a>
              </td>
              <td>
                <a className="plink" href={`/programs/${r.program_id}`}>
                  <span className="pname">{r.program_name}</span>
                  <span className="phandle">{r.platform} · {r.program_handle}</span>
                </a>
              </td>
              <td>
                <span className={statusBadgeClass(r.status)}>{r.status}</span>
                {r.error && <div className="phandle">{r.error}</div>}
              </td>
              <td>
                <span className={`badge ${r.subdomains > 0 ? "ok" : ""}`}>
                  {r.subdomains}
                </span>
              </td>
              <td>
                <span className={`badge ${r.live_hosts > 0 ? "ok" : ""}`}>
                  {r.live_hosts}
                </span>
              </td>
              <td>{r.rate_limit_rps ? `${r.rate_limit_rps} req/s` : "—"}</td>
              <td>
                {r.ident_header_name
                  ? <code>{r.ident_header_name}: {r.ident_header_value ?? "—"}</code>
                  : "—"}
              </td>
              <td>{fmtTime(r.started_at)}</td>
              <td>{fmtTime(r.finished_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
