"use client";

import { useCallback, useEffect, useState } from "react";
import {
  candidateStatusBadgeClass,
  candidateStatusLabel,
  confidenceBadgeClass,
  confidenceText,
  fmtTime,
  severityBadgeClass,
  type Candidate,
} from "../_lib/runui";

type Counts = {
  total: number;
  new: number;
  verifying: number;
  verified: number;
  rejected: number;
};

const STATUSES = ["new", "verifying", "verified", "rejected"] as const;

export default function FindingsPage() {
  const [items, setItems] = useState<Candidate[]>([]);
  const [counts, setCounts] = useState<Counts | null>(null);
  const [status, setStatus] = useState("");
  const [class_, setClass] = useState("");
  const [severity, setSeverity] = useState("");
  const [runId, setRunId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const qs = new URLSearchParams();
    if (status) qs.set("status", status);
    if (class_) qs.set("class", class_);
    if (severity) qs.set("severity", severity);
    if (runId) qs.set("run_id", runId);
    const res = await fetch(`/api/findings?${qs.toString()}`);
    if (!res.ok) {
      setError(`Không tải được Findings (HTTP ${res.status})`);
      return;
    }
    setError(null);
    const data = await res.json();
    setItems(data.items ?? []);
    setCounts(data.counts ?? null);
  }, [status, class_, severity, runId]);

  useEffect(() => {
    // run_id từ URL (vd /findings?run_id=3) — nạp 1 lần lúc mount
    const fromUrl = new URLSearchParams(window.location.search).get("run_id");
    if (fromUrl) setRunId(fromUrl);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <main className="page wide">
      <div className="pagehead">
        <div>
          <h1>Findings</h1>
          <p className="sub">
            Candidate từ Detection Phase (nuclei) — nguồn cho vòng xác minh.
            Bấm từng dòng để xem chi tiết + evidence.
          </p>
        </div>
      </div>

      <div className="btnrow" style={{ flexWrap: "wrap", gap: 8 }}>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Mọi trạng thái</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {candidateStatusLabel(s)}
            </option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">Mọi severity</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <input
          type="text"
          placeholder="class (vd: xss, sqli)"
          value={class_}
          onChange={(e) => setClass(e.target.value)}
          style={{ minWidth: 160 }}
        />
        <input
          type="text"
          placeholder="Run #"
          value={runId}
          onChange={(e) => setRunId(e.target.value.replace(/\D/g, ""))}
          style={{ minWidth: 90 }}
        />
        <button className="btn" onClick={() => load()}>
          Lọc
        </button>
      </div>

      {counts && (
        <p className="badges">
          <span className="badge">{counts.total} tổng</span>
          <span className="badge info">{counts.new} mới</span>
          <span className="badge">{counts.verifying} đang xác minh</span>
          <span className="badge ok">{counts.verified} đã xác minh</span>
          <span className="badge down">{counts.rejected} loại bỏ</span>
        </p>
      )}

      {error && <p className="alert">{error}</p>}

      {items.length === 0 && !error ? (
        <p className="meta">Chưa có Candidate nào khớp bộ lọc.</p>
      ) : (
        <table className="tbl">
          <thead>
            <tr>
              <th>Target</th>
              <th>Class</th>
              <th>Severity</th>
              <th>Template</th>
              <th>Trạng thái</th>
              <th>Confidence</th>
              <th>Run</th>
              <th>Phát hiện</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id}>
                <td>
                  <a className="plink" href={`/findings/${c.id}`}>
                    <code>{c.target}</code>
                  </a>
                </td>
                <td>
                  <span className="badge info">{c.class}</span>
                </td>
                <td>
                  <span className={severityBadgeClass(c.severity)}>{c.severity}</span>
                </td>
                <td className="note">
                  <code>{c.template_id}</code>
                  {c.title ? ` — ${c.title}` : ""}
                </td>
                <td>
                  <span className={candidateStatusBadgeClass(c.status)}>
                    {candidateStatusLabel(c.status)}
                  </span>
                </td>
                <td>
                  <span className={confidenceBadgeClass(c.status, c.confidence)}>
                    {confidenceText(c.confidence, c.confidence_threshold)}
                  </span>
                </td>
                <td>
                  <a className="plink" href={`/runs/${c.run_id}`}>#{c.run_id}</a>
                </td>
                <td className="note">{fmtTime(c.first_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
