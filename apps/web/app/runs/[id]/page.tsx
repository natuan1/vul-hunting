"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { fmtTime, statusBadgeClass } from "../../_lib/runui";

type ToolExec = {
  id: number;
  seq: number;
  tool: string;
  args: string | null;
  status: string;
  exit_code: number | null;
  stdout: string | null;
  started_at: string;
  finished_at: string | null;
};

type ScopeAsset = {
  asset_identifier: string;
  asset_type: string;
  eligible_for_bounty: boolean;
  eligible_for_submission: boolean;
  max_severity: string | null;
  tier: string | null;
  instruction: string | null;
};

type RunDetail = {
  id: number;
  program_id: number;
  program_name: string;
  program_handle: string;
  platform: string;
  platform_name: string;
  status: string;
  rate_limit_rps: number | null;
  ident_header_name: string | null;
  ident_header_value: string | null;
  scope_snapshot: ScopeAsset[];
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  tool_executions: ToolExec[];
};

type LogLine = { id: number; level: string; message: string; ts: string };

export default function RunDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [run, setRun] = useState<RunDetail | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [error, setError] = useState<string | null>(null);
  const lastIdRef = useRef(0);
  const logBoxRef = useRef<HTMLDivElement | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const doneRef = useRef(false);

  const load = useCallback(async () => {
    const res = await fetch(`/api/runs/${id}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? `HTTP ${res.status}`);
    }
    return (await res.json()) as RunDetail;
  }, [id]);

  // ── SSE log stream — đứt kết nối thì tự nối lại từ log cuối đã thấy ──
  const openStream = useCallback(() => {
    if (doneRef.current) return;
    esRef.current?.close();
    const es = new EventSource(`/api/runs/${id}/stream?after=${lastIdRef.current}`);
    esRef.current = es;
    es.addEventListener("log", (e) => {
      const data = JSON.parse((e as MessageEvent).data);
      const logId = Number((e as MessageEvent).lastEventId);
      if (logId <= lastIdRef.current) return; // bỏ dòng trùng khi reconnect
      lastIdRef.current = logId;
      setLogs((prev) => [...prev, { id: logId, ...data }]);
    });
    es.addEventListener("done", (e) => {
      doneRef.current = true;
      es.close();
      const { status } = JSON.parse((e as MessageEvent).data);
      setRun((r) => (r ? { ...r, status } : r));
      load().then(setRun).catch(() => {}); // nạp lại chi tiết (tool executions, finished_at)
    });
    es.onerror = () => {
      es.close();
      if (!doneRef.current) setTimeout(openStream, 2000);
    };
  }, [id, load]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await load();
        if (cancelled) return;
        setRun(r);
        // chạy lại run cũ: stream phát lại từ đầu, mọi dòng có id nên UI không lo trùng
        openStream();
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
      doneRef.current = true;
      esRef.current?.close();
    };
  }, [load, openStream]);

  // tự trượt xuống dòng log mới nhất
  useEffect(() => {
    const box = logBoxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [logs]);

  if (!run && !error) {
    return <main className="page"><p>Đang tải…</p></main>;
  }
  if (error)
    return (
      <main className="page">
        <p className="alert">Không tải được Run: {error}</p>
        <a className="btn" href="/runs">← Về danh sách Run</a>
      </main>
    );
  if (!run) return null;

  const finished = run.status === "completed" || run.status === "failed";

  return (
    <main className="page wide">
      <p className="breadcrumb"><a href="/runs">← Runs</a></p>

      <div className="pagehead">
        <div>
          <h1>Run #{run.id}</h1>
          <p className="sub">
            <a href={`/programs/${run.program_id}`}>{run.program_name}</a> ·{" "}
            {run.platform_name} · <code>{run.program_handle}</code>
          </p>
        </div>
        <div className="btnrow badges">
          <span className={statusBadgeClass(run.status)}>{run.status}</span>
          {run.rate_limit_rps !== null && (
            <span className="badge info">{run.rate_limit_rps} req/s</span>
          )}
          {run.ident_header_name && (
            <span className="badge info">
              <code>{run.ident_header_name}: {run.ident_header_value ?? "—"}</code>
            </span>
          )}
        </div>
      </div>

      {run.error && <p className="alert">Run thất bại: {run.error}</p>}

      <p className="meta">
        Tạo {fmtTime(run.created_at)} · bắt đầu {fmtTime(run.started_at)} · kết thúc{" "}
        {fmtTime(run.finished_at)}
      </p>

      {/* ── Log stream ── */}
      <h2 className="section-title">Log Tool Execution {finished ? "" : "· đang chạy…"}</h2>
      <div className="logstream" ref={logBoxRef}>
        {logs.length === 0 && <div className="logline">— chưa có log —</div>}
        {logs.map((l) => (
          <div key={l.id} className={`logline${l.level === "error" ? " err" : ""}`}>
            <span className="logts">
              {new Date(l.ts).toLocaleTimeString("vi-VN")}
            </span>
            {l.message}
          </div>
        ))}
        {!finished && <div className="logline cursor">▌</div>}
      </div>

      {/* ── Tool Execution ── */}
      <h2 className="section-title">
        Tool Execution ({run.tool_executions.length})
      </h2>
      {run.tool_executions.length === 0 ? (
        <p className="meta">Chưa có Tool Execution nào.</p>
      ) : (
        <table className="tbl">
          <thead>
            <tr>
              <th>#</th>
              <th>Tool</th>
              <th>Args</th>
              <th>Exit</th>
              <th>Thời gian</th>
            </tr>
          </thead>
          <tbody>
            {run.tool_executions.map((t) => (
              <tr key={t.id}>
                <td>{t.seq}</td>
                <td><code>{t.tool}</code></td>
                <td className="note">{t.args}</td>
                <td>
                  <span className={`badge ${t.exit_code === 0 ? "ok" : "down"}`}>
                    {t.exit_code ?? "…"}
                  </span>
                </td>
                <td className="note">
                  {fmtTime(t.started_at)}
                  {t.finished_at && ` → ${new Date(t.finished_at).toLocaleTimeString("vi-VN")}`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* ── Scope snapshot ── */}
      <h2 className="section-title">Scope snapshot</h2>
      <p className="meta">
        Bản chụp Scope lúc tạo Run — Run thao tác trên bản này, không đọc Scope hiện tại.
      </p>
      <details>
        <summary>Xem Scope snapshot ({run.scope_snapshot.length} Asset)</summary>
        <table className="tbl">
          <thead>
            <tr>
              <th>Asset</th>
              <th>Loại</th>
              <th>Bounty</th>
              <th>Submission</th>
              <th>Max severity</th>
              <th>Tier</th>
            </tr>
          </thead>
          <tbody>
            {run.scope_snapshot.map((a) => (
              <tr key={`${a.asset_identifier}-${a.asset_type}`}>
                <td><code>{a.asset_identifier}</code></td>
                <td>{a.asset_type}</td>
                <td>{a.eligible_for_bounty ? "có" : "không"}</td>
                <td>{a.eligible_for_submission ? "có" : "không"}</td>
                <td>{a.max_severity ?? "—"}</td>
                <td>{a.tier ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </main>
  );
}
