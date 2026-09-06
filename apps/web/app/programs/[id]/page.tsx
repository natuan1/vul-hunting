"use client";

import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

type Asset = {
  id: number;
  asset_identifier: string;
  asset_type: string;
  eligible_for_bounty: boolean;
  eligible_for_submission: boolean;
  max_severity: string | null;
  tier: string | null;
  instruction: string | null;
};

type ProgramDetail = {
  id: number;
  handle: string;
  name: string;
  currency: string | null;
  policy: string | null;
  submission_state: string | null;
  state: string | null;
  offers_bounties: boolean;
  min_bounty: number | null;
  max_bounty: number | null;
  open_scope: boolean | null;
  triage_active: boolean | null;
  platform: string;
  platform_name: string;
  assets: Asset[];
  summary: string | null;
  summary_model: string | null;
  summary_status: "none" | "generating" | "ready" | "error";
  summary_error: string | null;
  summary_generated_at: string | null;
};

// ── renderer markdown tối giản (đủ cho output của summary: heading, bullet, bold) ──

function renderInline(text: string) {
  const parts = text.split("**");
  return parts.map((p, i) => (i % 2 === 1 ? <strong key={i}>{p}</strong> : p));
}

function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  const out: React.ReactNode[] = [];
  let bullets: string[] = [];
  let table: string[] = [];

  const flushBullets = () => {
    if (bullets.length) {
      out.push(
        <ul key={`ul-${out.length}`}>
          {bullets.map((b, i) => (
            <li key={i}>{renderInline(b)}</li>
          ))}
        </ul>,
      );
      bullets = [];
    }
  };
  const flushTable = () => {
    if (table.length) {
      out.push(
        <pre key={`tb-${out.length}`} className="md-table">
          {table.join("\n")}
        </pre>,
      );
      table = [];
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith("|")) {
      flushBullets();
      table.push(line);
      continue;
    }
    flushTable();
    if (line.startsWith("- ")) {
      bullets.push(line.slice(2));
      continue;
    }
    flushBullets();
    if (line.startsWith("### ")) out.push(<h4 key={out.length}>{renderInline(line.slice(4))}</h4>);
    else if (line.startsWith("## ") || line.startsWith("# "))
      out.push(<h3 key={out.length}>{renderInline(line.replace(/^#+ /, ""))}</h3>);
    else if (line.trim()) out.push(<p key={out.length}>{renderInline(line)}</p>);
  }
  flushBullets();
  flushTable();
  return <div className="md">{out}</div>;
}

// ───────────────────────────── trang Program Detail ─────────────────────────────

export default function ProgramDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [program, setProgram] = useState<ProgramDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const autoTriggeredRef = useRef(false);

  // config Run mới (ticket #6) — header để trống thì worker lấy mặc định từ env
  const [runRate, setRunRate] = useState("1");
  const [runHeaderName, setRunHeaderName] = useState("X-Bug-Bounty");
  const [runHeaderValue, setRunHeaderValue] = useState("");
  const [allowNonProd, setAllowNonProd] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [creatingRun, setCreatingRun] = useState(false);

  const startRun = async () => {
    setCreatingRun(true);
    setRunError(null);
    try {
      const body: Record<string, unknown> = {};
      const rate = parseFloat(runRate);
      if (!Number.isNaN(rate)) body.rate_limit_rps = rate;
      if (runHeaderName.trim()) body.ident_header_name = runHeaderName.trim();
      if (runHeaderValue.trim()) body.ident_header_value = runHeaderValue.trim();
      if (allowNonProd) body.allow_non_prod = true;
      const res = await fetch(`/api/programs/${id}/runs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail ?? `HTTP ${res.status}`);
      router.push(`/runs/${data.run.id}`);
    } catch (e) {
      setRunError(e instanceof Error ? e.message : String(e));
      setCreatingRun(false);
    }
  };

  const load = useCallback(async () => {
    const res = await fetch(`/api/programs/${id}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? `HTTP ${res.status}`);
    }
    return (await res.json()) as ProgramDetail;
  }, [id]);

  // mở trang: tải program (scope/policy) ngay — không bị chặn bởi summary
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const p = await load();
        if (!cancelled) setProgram(p);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [load]);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const pollUntilDone = useCallback(async () => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const p = await load();
        setProgram(p);
        if (p.summary_status !== "generating") stopPolling();
      } catch {
        /* lỗi tạm thời khi poll — thử tick sau */
      }
    }, 3000);
  }, [load, stopPolling]);

  const triggerSummary = useCallback(async () => {
    setTriggering(true);
    try {
      const res = await fetch(`/api/programs/${id}/summary`, { method: "POST" });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail ?? `HTTP ${res.status}`);
      setProgram((p) => (p ? { ...p, summary_status: "generating", summary_error: null } : p));
      await pollUntilDone();
    } catch (e) {
      setProgram((p) =>
        p
          ? {
              ...p,
              summary_status: "error",
              summary_error: e instanceof Error ? e.message : String(e),
            }
          : p,
      );
    } finally {
      setTriggering(false);
    }
  }, [id, pollUntilDone]);

  // lazy: lần đầu mở mà chưa có summary → tự sinh 1 lần
  useEffect(() => {
    if (!program || autoTriggeredRef.current) return;
    autoTriggeredRef.current = true;
    if (program.summary_status === "none") triggerSummary();
    else if (program.summary_status === "generating") pollUntilDone();
  }, [program, triggerSummary, pollUntilDone]);

  useEffect(() => stopPolling, [stopPolling]);

  if (loading) return <main className="page"><p>Đang tải…</p></main>;
  if (error)
    return (
      <main className="page">
        <p className="alert">Không tải được program: {error}</p>
        <a className="btn" href="/programs">← Về danh sách</a>
      </main>
    );
  if (!program) return null;

  const p = program;
  const bountyLabel = p.offers_bounties
    ? p.max_bounty
      ? `tới ${Number(p.max_bounty).toLocaleString("vi-VN")} ${p.currency ?? ""}`
      : "có"
    : "không";

  return (
    <main className="page wide">
      <p className="breadcrumb">
        <a href="/programs">← Programs</a>
      </p>

      <div className="pagehead">
        <div>
          <h1>{p.name}</h1>
          <p className="sub">
            <code>{p.handle}</code> · {p.platform_name}
            {p.submission_state ? ` · submission: ${p.submission_state}` : ""}
          </p>
        </div>
        <div className="btnrow badges">
          <span className={`badge ${p.offers_bounties ? "ok" : "down"}`}>
            Bounty: {bountyLabel}
          </span>
          {p.min_bounty !== null && (
            <span className="badge info">
              min {Number(p.min_bounty).toLocaleString("vi-VN")} {p.currency ?? ""}
            </span>
          )}
          {p.max_bounty !== null && (
            <span className="badge info">
              max {Number(p.max_bounty).toLocaleString("vi-VN")} {p.currency ?? ""}
            </span>
          )}
          {p.open_scope !== null && (
            <span className="badge info">{p.open_scope ? "scope mở" : "scope đóng"}</span>
          )}
          {p.triage_active !== null && (
            <span className="badge info">{p.triage_active ? "đang triage" : "ngừng triage"}</span>
          )}
        </div>
      </div>

      {/* ── AI summary (lazy, cache) ── */}
      <section className="tile summary-tile">
        <h2>Tóm tắt AI</h2>
        {p.summary_status === "ready" && (
          <>
            <Markdown text={p.summary ?? ""} />
            <p className="meta">
              {p.summary_model && <>model: {p.summary_model} · </>}
              {p.summary_generated_at &&
                `sinh lúc ${new Date(p.summary_generated_at).toLocaleString("vi-VN")}`}
            </p>
          </>
        )}
        {p.summary_status === "generating" && (
          <p className="meta">
            Đang đọc policy + Scope và sinh tóm tắt qua Hermes Agent… trang vẫn dùng được,
            tóm tắt sẽ hiện khi xong.
          </p>
        )}
        {p.summary_status === "none" && <p className="meta">Chưa có summary.</p>}
        {p.summary_status === "error" && (
          <>
            <p className="alert">Chưa có summary — sinh lỗi: {p.summary_error}</p>
          </>
        )}
        <button
          className="btn"
          onClick={triggerSummary}
          disabled={triggering || p.summary_status === "generating"}
        >
          {p.summary_status === "ready" ? "Refresh summary" : "Sinh summary"}
        </button>
      </section>

      {/* ── Chạy Run ── */}
      <section className="tile">
        <h2>Chạy Run</h2>
        <p className="meta">
          Tạo Run cho Program này — Scope được chụp snapshot ngay lúc tạo. Rate limit
          và header định danh áp dụng cho mọi Tool Execution trong Run. Hiện mới có
          stub tool (sleep + echo) để chạy thử vòng lặp; tool thật ở ticket sau.
        </p>
        {runError && <p className="alert">Không tạo được Run: {runError}</p>}
        <div className="runform">
          <label>
            Rate limit (req/s)
            <input
              type="number"
              min="0.1"
              step="0.1"
              value={runRate}
              placeholder="1"
              onChange={(e) => setRunRate(e.target.value)}
            />
          </label>
          <label>
            Header định danh
            <input
              value={runHeaderName}
              placeholder="X-Bug-Bounty"
              onChange={(e) => setRunHeaderName(e.target.value)}
            />
          </label>
          <label>
            Giá trị header
            <input
              value={runHeaderValue}
              placeholder="để trống → mặc định HackerOne-&lt;username&gt; từ .env"
              onChange={(e) => setRunHeaderValue(e.target.value)}
            />
          </label>
          <label className="check" title="dev./staging./uat./qa./sandbox./test./preview. dưới wildcard là non-production — mặc định Scope Validator chặn không auto-test">
            <input
              type="checkbox"
              checked={allowNonProd}
              onChange={(e) => setAllowNonProd(e.target.checked)}
            />
            Cho phép non-production
          </label>
          <button className="btn primary" onClick={startRun} disabled={creatingRun}>
            {creatingRun ? "Đang tạo…" : "▶ Chạy Run"}
          </button>
        </div>
        <p className="meta">
          Rate limit để trống → mặc định 1 req/s (an toàn); header để trống → lấy
          mặc định từ <code>.env</code>.
        </p>
      </section>

      {/* ── Scope ── */}
      <section>
        <h2 className="section-title">Scope ({p.assets.length} Asset)</h2>
        {p.assets.length === 0 ? (
          <p className="meta">Chưa sync Scope cho program này — chạy Sync platform rồi xem lại.</p>
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Loại</th>
                <th>Bounty</th>
                <th>Submission</th>
                <th>Max severity</th>
                <th>Tier</th>
                <th>Ghi chú</th>
              </tr>
            </thead>
            <tbody>
              {p.assets.map((a) => (
                <tr key={a.id}>
                  <td><code>{a.asset_identifier}</code></td>
                  <td>{a.asset_type}</td>
                  <td>
                    <span className={`badge ${a.eligible_for_bounty ? "ok" : "down"}`}>
                      {a.eligible_for_bounty ? "có" : "không"}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${a.eligible_for_submission ? "ok" : "down"}`}>
                      {a.eligible_for_submission ? "có" : "không"}
                    </span>
                  </td>
                  <td>{a.max_severity ?? "—"}</td>
                  <td>{a.tier ?? "—"}</td>
                  <td className="note">{a.instruction ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* ── Policy ── */}
      <section>
        <h2 className="section-title">Chính sách (policy)</h2>
        {p.policy ? (
          <details open={!p.summary}>
            <summary>Xem toàn bộ policy text</summary>
            <pre className="policy">{p.policy}</pre>
          </details>
        ) : (
          <p className="meta">Platform không trả về policy text.</p>
        )}
      </section>
    </main>
  );
}
