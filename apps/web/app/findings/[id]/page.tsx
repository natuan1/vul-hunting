"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  candidateStatusBadgeClass,
  candidateStatusLabel,
  composeReportMarkdown,
  confidenceBadgeClass,
  confidenceText,
  fmtTime,
  oobBadgeClass,
  oobText,
  REPORT_PLATFORMS,
  REPORT_SECTION_LABEL,
  severityBadgeClass,
  type Candidate,
  type ReportSections,
} from "../../_lib/runui";

type Evidence = {
  path: string;
  truncated: boolean;
  content: string;
};

type VerifyResult = {
  verdict: string;
  score: number;
  threshold: number;
  reason: string;
  signals: string[];
  patterns: string[];
  payload: string;
  evidence_path: string | null;
  baseline_session_id: number | null;
  verify_session_id: number | null;
};

type OobCallback = {
  id: number;
  protocol: string;
  source: string;
  unique_id: string;
  full_id: string;
  occurred_at: string | null;
  received_at: string;
  raw_interaction: Record<string, unknown> | string | null;
};

type OobRegistration = {
  id: number;
  server_url: string;
  domain: string;
  correlation_id: string;
  status: string;
  expires_at: string;
};

type OobData = {
  registration: OobRegistration | null;
  callbacks: OobCallback[];
  count: number;
};

type OobVerifyResult = {
  verdict: string;
  score: number;
  threshold: number;
  reason: string;
  signals: string[];
  patterns: string[];
  payload: string;
  token: string;
  domain: string | null;
  callbacks: OobCallback[];
  evidence_path: string | null;
};

type TakeoverVerifyResult = {
  verdict: string;
  score: number;
  threshold: number;
  reason: string;
  signals: string[];
  patterns: string[];
  cname: string | null;
  service: string | null;
  claim_host: string | null;
  poc_url: string | null;
  token: string | null;
  username: string;
  deploy: { provider: string; url: string } | null;
  guidance: string | null;
  evidence_path: string | null;
  baseline_session_id: number | null;
  verify_session_id: number | null;
};

type HttpVerifyResult = {
  class: string;
  verdict: string;
  score: number;
  threshold: number;
  reason: string;
  signals: string[];
  patterns: string[];
  detail: { missing?: string[]; present?: string[]; markers?: string[] | { strong: string[]; weak: string[] } };
  reportable: boolean;
  payload: string;
  evidence_path: string | null;
  baseline_session_id: number | null;
  verify_session_id: number | null;
};

// Report draft theo mẫu platform (ticket #18)
type ReportDraft = {
  candidate_id: number;
  platform: string;
  program_platform: string | null;
  source: "generated" | "saved";
  sections: ReportSections;
  markdown: string;
  status: string;
  report_url: string | null;
  report_notes: string | null;
  reported_at: string | null;
};

// Batch A (ticket #15): 7 lớp HTTP-only dùng chung vòng verify-http
const HTTP_CLASSES = ["cors", "dirlist", "graphql", "crlf", "ssti", "headers", "disclosure"] as const;
const HTTP_CLASS_LABEL: Record<string, string> = {
  cors: "CORS misconfig",
  dirlist: "Directory listing",
  graphql: "GraphQL introspection",
  crlf: "CRLF injection",
  ssti: "SSTI",
  headers: "Missing security headers",
  disclosure: "Info disclosure / debug",
};

const TRANSITIONS = ["verifying", "verified", "rejected"] as const;
const OOB_POLL_MS = 5000;

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [candidate, setCandidate] = useState<Candidate | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [verifyEvidence, setVerifyEvidence] = useState<Evidence | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [oob, setOob] = useState<OobData | null>(null);
  const [oobEvidence, setOobEvidence] = useState<Evidence | null>(null);
  const [oobVerifying, setOobVerifying] = useState(false);
  const [oobResult, setOobResult] = useState<OobVerifyResult | null>(null);
  const [takeoverResult, setTakeoverResult] = useState<TakeoverVerifyResult | null>(null);
  const [takeoverVerifying, setTakeoverVerifying] = useState(false);
  const [httpResult, setHttpResult] = useState<HttpVerifyResult | null>(null);
  const [httpVerifying, setHttpVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Report draft theo mẫu platform (ticket #18)
  const [reportDraft, setReportDraft] = useState<ReportDraft | null>(null);
  const [reportPlatform, setReportPlatform] = useState<string>("");
  const [reportSections, setReportSections] = useState<ReportSections | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportSaving, setReportSaving] = useState(false);
  const [reportMsg, setReportMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [markUrl, setMarkUrl] = useState("");
  const [markNotes, setMarkNotes] = useState("");
  const [marking, setMarking] = useState(false);

  const load = useCallback(async () => {
    const res = await fetch(`/api/findings/${id}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? `HTTP ${res.status}`);
    }
    return (await res.json()) as Candidate;
  }, [id]);

  const loadEvidence = useCallback(async () => {
    const res = await fetch(`/api/findings/${id}/evidence`);
    if (!res.ok) return;
    setEvidence((await res.json()) as Evidence);
  }, [id]);

  const loadVerifyEvidence = useCallback(async () => {
    const res = await fetch(`/api/findings/${id}/verify-evidence`);
    if (!res.ok) return;
    setVerifyEvidence((await res.json()) as Evidence);
  }, [id]);

  const loadOob = useCallback(async () => {
    const res = await fetch(`/api/findings/${id}/oob`);
    if (!res.ok) return;
    setOob((await res.json()) as OobData);
  }, [id]);

  const loadOobEvidence = useCallback(async () => {
    const res = await fetch(`/api/findings/${id}/oob-evidence`);
    if (!res.ok) return;
    setOobEvidence((await res.json()) as Evidence);
  }, [id]);

  const runVerify = useCallback(async () => {
    setVerifying(true);
    setError(null);
    try {
      const res = await fetch(`/api/findings/${id}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.detail ?? `HTTP ${res.status}`);
      }
      setVerifyResult(body.verify as VerifyResult);
      setCandidate((body.candidate ?? null) as Candidate | null);
      loadVerifyEvidence().catch(() => {});
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setVerifying(false);
    }
  }, [id, loadVerifyEvidence]);

  const runOobVerify = useCallback(async () => {
    setOobVerifying(true);
    setError(null);
    try {
      const res = await fetch(`/api/findings/${id}/verify-oob`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.detail ?? `HTTP ${res.status}`);
      }
      setOobResult(body.verify as OobVerifyResult);
      setCandidate((body.candidate ?? null) as Candidate | null);
      loadOob().catch(() => {});
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setOobVerifying(false);
    }
  }, [id, loadOob]);

  const runTakeoverVerify = useCallback(async () => {
    setTakeoverVerifying(true);
    setError(null);
    try {
      const res = await fetch(`/api/findings/${id}/verify-takeover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.detail ?? `HTTP ${res.status}`);
      }
      setTakeoverResult(body.verify as TakeoverVerifyResult);
      setCandidate((body.candidate ?? null) as Candidate | null);
      loadVerifyEvidence().catch(() => {});
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setTakeoverVerifying(false);
    }
  }, [id, loadVerifyEvidence]);

  const runHttpVerify = useCallback(async () => {
    setHttpVerifying(true);
    setError(null);
    try {
      const res = await fetch(`/api/findings/${id}/verify-http`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.detail ?? `HTTP ${res.status}`);
      }
      setHttpResult(body.verify as HttpVerifyResult);
      setCandidate((body.candidate ?? null) as Candidate | null);
      loadVerifyEvidence().catch(() => {});
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setHttpVerifying(false);
    }
  }, [id, loadVerifyEvidence]);

  const loadReport = useCallback(
    async (platform: string, refresh: boolean = false) => {
      setReportLoading(true);
      try {
        const qs = new URLSearchParams();
        if (platform) qs.set("platform", platform);
        if (refresh) qs.set("refresh", "1");
        const res = await fetch(
          `/api/findings/${id}/report?${qs.toString()}`,
        );
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(body.detail ?? `HTTP ${res.status}`);
        }
        const draft = body as ReportDraft;
        setReportDraft(draft);
        setReportPlatform(draft.platform);
        setReportSections(draft.sections);
        setReportMsg(null);
      } catch (e) {
        setReportMsg(e instanceof Error ? e.message : String(e));
      } finally {
        setReportLoading(false);
      }
    },
    [id],
  );

  const editSection = useCallback((key: keyof ReportSections, value: string) => {
    setReportSections((s) => (s ? { ...s, [key]: value } : s));
  }, []);

  const copyText = useCallback(async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      setReportMsg("Không copy được — trình duyệt chặn clipboard.");
    }
  }, []);

  const saveDraft = useCallback(async () => {
    if (!reportSections) return;
    setReportSaving(true);
    try {
      const res = await fetch(`/api/findings/${id}/report`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          platform: reportPlatform,
          sections: reportSections,
          markdown: composeReportMarkdown(reportPlatform, reportSections),
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.detail ?? `HTTP ${res.status}`);
      }
      setReportMsg("Đã lưu nháp trong DB.");
      loadReport(reportPlatform).catch(() => {});
    } catch (e) {
      setReportMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setReportSaving(false);
    }
  }, [id, reportPlatform, reportSections, loadReport]);

  const submitReported = useCallback(async () => {
    setMarking(true);
    setError(null);
    try {
      const res = await fetch(`/api/findings/${id}/reported`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report_url: markUrl || null, report_notes: markNotes || null }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.detail ?? `HTTP ${res.status}`);
      }
      const updated = (body.candidate ?? null) as Candidate | null;
      if (updated) setCandidate(updated);
      setReportMsg("Đã đánh dấu 'reported'.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setMarking(false);
    }
  }, [id, markUrl, markNotes]);

  const transition = useCallback(
    async (status: string) => {
      setSaving(true);
      try {
        const res = await fetch(`/api/findings/${id}/status`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status }),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail ?? `HTTP ${res.status}`);
        }
        setCandidate((c) => (c ? { ...c, status } : c));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setSaving(false);
      }
    },
    [id],
  );

  useEffect(() => {
    (async () => {
      try {
        setCandidate(await load());
        loadEvidence().catch(() => {});
        loadVerifyEvidence().catch(() => {});
        loadOob().catch(() => {});
        loadOobEvidence().catch(() => {});
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [load, loadEvidence, loadVerifyEvidence, loadOob, loadOobEvidence]);

  // Candidate đang "đang xác minh" → poll nhẹ để thấy callback OOB về dần
  useEffect(() => {
    if (candidate?.status !== "verifying") return;
    const timer = setInterval(() => {
      load().then(setCandidate).catch(() => {});
      loadOob().catch(() => {});
    }, OOB_POLL_MS);
    return () => clearInterval(timer);
  }, [candidate?.status, load, loadOob]);

  // Report (ticket #18): Finding verified/reported → tải draft lần đầu +
  // prefill link/ghi chú đã nộp (nếu có)
  const reportable = candidate?.status === "verified" || candidate?.status === "reported";
  useEffect(() => {
    if (!reportable) return;
    if (!reportDraft) loadReport("").catch(() => {});
    if (candidate?.status === "reported") {
      if (candidate.report_url && !markUrl) setMarkUrl(candidate.report_url);
      if (candidate.report_notes && !markNotes) setMarkNotes(candidate.report_notes);
    }
  }, [reportable, candidate, reportDraft, loadReport, markUrl, markNotes]);

  if (error && !candidate) {
    return (
      <main className="page">
        <p className="alert">Không tải được Candidate: {error}</p>
        <a className="btn" href="/findings">← Về Findings</a>
      </main>
    );
  }
  if (!candidate) {
    return <main className="page"><p>Đang tải…</p></main>;
  }

  return (
    <main className="page wide">
      <p className="breadcrumb">
        <a href="/findings">← Findings</a>
      </p>

      <div className="pagehead">
        <div>
          <h1>
            <code>{candidate.template_id}</code>
          </h1>
          <p className="sub">
            {candidate.title ?? "—"} · Run{" "}
            <a href={`/runs/${candidate.run_id}`}>#{candidate.run_id}</a> · phát hiện{" "}
            {fmtTime(candidate.first_seen)}
          </p>
        </div>
        <div className="btnrow badges">
          <span className={severityBadgeClass(candidate.severity)}>
            {candidate.severity}
          </span>
          <span className={candidateStatusBadgeClass(candidate.status)}>
            {candidateStatusLabel(candidate.status)}
          </span>
          <span
            className={confidenceBadgeClass(candidate.status, candidate.confidence)}
          >
            confidence {confidenceText(candidate.confidence, candidate.confidence_threshold)}
          </span>
          <span className={oobBadgeClass(candidate.oob_callback_count)}>
            OOB {oobText(candidate.oob_callback_count)}
          </span>
        </div>
      </div>

      {error && <p className="alert">{error}</p>}

      <p className="badges">
        <span className="badge info">class: {candidate.class}</span>
        {candidate.param && <span className="badge">param: {candidate.param}</span>}
        {candidate.matcher_name && (
          <span className="badge">matcher: {candidate.matcher_name}</span>
        )}
      </p>

      <h2 className="section-title">Target</h2>
      <p>
        <a className="plink" href={candidate.target} target="_blank" rel="noreferrer">
          <code>{candidate.target}</code>
        </a>
      </p>

      {candidate.status === "rejected" && candidate.reject_reason && (
        <>
          <h2 className="section-title">Lý do loại bỏ</h2>
          <p className="alert">{candidate.reject_reason}</p>
        </>
      )}

      {candidate.class === "redirect" && (
        <>
          <h2 className="section-title">Xác minh open redirect</h2>
          <p className="meta">
            Baseline capture → PoC qua sandbox → response diff so baseline →
            confidence score. Payload KHÔNG bao giờ chạy ngoài sandbox.
          </p>
          <div className="btnrow">
            <button className="btn" disabled={verifying} onClick={runVerify}>
              {verifying ? "Đang xác minh trong sandbox…" : "▶ Chạy vòng xác minh"}
            </button>
          </div>
          {verifying && (
            <p className="meta">
              Đang chạy: Candidate chuyển sang “đang xác minh” cho tới khi có verdict.
            </p>
          )}
          {verifyResult && (
            <div>
              <p className="badges">
                <span
                  className={
                    verifyResult.verdict === "verified" ? "badge ok" : "badge down"
                  }
                >
                  {verifyResult.verdict === "verified" ? "Finding" : "false positive"} ·{" "}
                  score {verifyResult.score.toFixed(2)} / ngưỡng{" "}
                  {verifyResult.threshold.toFixed(2)}
                </span>
                {verifyResult.patterns.map((p) => (
                  <span key={p} className="badge info">pattern: {p}</span>
                ))}
              </p>
              <p className="meta">{verifyResult.reason}</p>
              {verifyResult.verify_session_id !== null && (
                <p className="meta">
                  Verify session: baseline{" "}
                  <a href={`/runs/${candidate.run_id}`}>#{verifyResult.baseline_session_id}</a>{" "}
                  · PoC #{verifyResult.verify_session_id}
                </p>
              )}
            </div>
          )}
        </>
      )}

      {(candidate.class === "ssrf" || (oob && (oob.count > 0 || oob.registration))) && (
        <>
          <h2 className="section-title">OOB qua interactsh (blind)</h2>
          <p className="meta">
            Registration interactsh <strong>riêng cho Run</strong> — domain payload
            xoay vòng theo Run, callback từ Internet được gắn về Candidate qua token
            trong subdomain.
          </p>
          {oob?.registration && (
            <p className="meta">
              Domain: <code>*.{oob.registration.domain}</code> · server{" "}
              <code>{oob.registration.server_url}</code> · hết hạn{" "}
              {fmtTime(oob.registration.expires_at)}
            </p>
          )}
          {candidate.class === "ssrf" && (
            <div className="btnrow">
              <button className="btn" disabled={oobVerifying} onClick={runOobVerify}>
                {oobVerifying
                  ? "Đang xác minh — chờ callback OOB…"
                  : "▶ Chạy vòng xác minh OOB (blind SSRF)"}
              </button>
            </div>
          )}
          {oobVerifying && (
            <p className="meta">
              Payload <code>http://&lt;token&gt;.&lt;domain&gt;</code> đã chạy qua
              sandbox — đang chờ target fetch ra Internet (callback có thể mất
              tới ~1 phút).
            </p>
          )}
          {oobResult && (
            <div>
              <p className="badges">
                <span
                  className={
                    oobResult.verdict === "verified" ? "badge ok" : "badge down"
                  }
                >
                  {oobResult.verdict === "verified" ? "Finding" : "false positive"} ·{" "}
                  score {oobResult.score.toFixed(2)} / ngưỡng{" "}
                  {oobResult.threshold.toFixed(2)}
                </span>
                <span className="badge info">{oobResult.callbacks.length} callback</span>
                {oobResult.patterns.map((p) => (
                  <span key={p} className="badge info">pattern: {p}</span>
                ))}
              </p>
              <p className="meta">
                {oobResult.reason}
                {oobResult.payload && (
                  <>
                    {" "}· payload: <code>{oobResult.payload}</code>
                  </>
                )}
              </p>
            </div>
          )}
          {oob && oob.count > 0 && (
            <table className="tbl">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Source</th>
                  <th>Timestamp</th>
                  <th>Full-id</th>
                </tr>
              </thead>
              <tbody>
                {oob.callbacks.map((cb) => (
                  <tr key={cb.id}>
                    <td><span className="badge info">{cb.protocol}</span></td>
                    <td><code>{cb.source}</code></td>
                    <td className="note">{fmtTime(cb.occurred_at)}</td>
                    <td className="note"><code>{cb.full_id}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {oob && oob.count > 0 && (
            <details>
              <summary className="meta">Raw interactions ({oob.count})</summary>
              <div className="logstream">
                <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                  {JSON.stringify(
                    oob.callbacks.map((cb) => cb.raw_interaction),
                    null,
                    2,
                  )}
                </pre>
              </div>
            </details>
          )}
        </>
      )}

      {HTTP_CLASSES.includes(candidate.class as (typeof HTTP_CLASSES)[number]) && (
        <>
          <h2 className="section-title">
            Xác minh batch A — {HTTP_CLASS_LABEL[candidate.class] ?? candidate.class}
          </h2>
          {candidate.class === "headers" ? (
            <p className="meta">
              Security headers CHỈ informational: chạy để thu thập evidence (danh sách
              headers thiếu) + ép severity thấp — KHÔNG tự tạo report, không đổi status.
            </p>
          ) : (
            <p className="meta">
              Baseline capture → PoC tuỳ lớp (Origin canary / `__schema` / `%0d%0a`
              header canary / `&#123;&#123;7*7&#125;&#125;` / path con / root host) qua
              sandbox → phân tích so baseline → confidence score. WAF block, payload bị
              escape hay marker có sẵn ở baseline đều bị loại.
            </p>
          )}
          <div className="btnrow">
            <button className="btn" disabled={httpVerifying} onClick={runHttpVerify}>
              {httpVerifying
                ? "Đang xác minh trong sandbox…"
                : candidate.class === "headers"
                  ? "▶ Thu thập evidence (informational)"
                  : "▶ Chạy vòng xác minh"}
            </button>
          </div>
          {httpResult && (
            <div>
              <p className="badges">
                <span
                  className={
                    httpResult.verdict === "verified"
                      ? "badge ok"
                      : httpResult.verdict === "informational"
                        ? "badge"
                        : "badge down"
                  }
                >
                  {httpResult.verdict === "verified"
                    ? "Finding"
                    : httpResult.verdict === "informational"
                      ? "informational — chỉ hiển thị, KHÔNG report"
                      : "false positive"}{" "}
                  · score {httpResult.score.toFixed(2)} / ngưỡng{" "}
                  {httpResult.threshold.toFixed(2)}
                </span>
                {httpResult.patterns.map((p) => (
                  <span key={p} className="badge info">pattern: {p}</span>
                ))}
              </p>
              <p className="meta">{httpResult.reason}</p>
              {httpResult.detail?.missing && httpResult.detail.missing.length > 0 && (
                <p className="badges">
                  {httpResult.detail.missing.map((h) => (
                    <span key={h} className="badge down">thiếu: {h}</span>
                  ))}
                </p>
              )}
              {httpResult.verify_session_id !== null && (
                <p className="meta">
                  Verify session: baseline{" "}
                  <a href={`/runs/${candidate.run_id}`}>#{httpResult.baseline_session_id}</a>{" "}
                  · PoC #{httpResult.verify_session_id}
                </p>
              )}
            </div>
          )}
        </>
      )}

      {candidate.class === "takeover" && (
        <>
          <h2 className="section-title">Xác minh subdomain takeover (PoC chứng minh kiểm soát)</h2>
          <p className="meta">
            Fingerprint match chưa đủ — policy của nhiều Program yêu cầu chứng minh
            KIỂM SOÁT: PoC page chứa username của bạn được deploy lên service bỏ hoang
            rồi xác nhận được phục vụ <strong>qua subdomain</strong>. Report takeover
            thiếu PoC hoạt động sẽ bị đóng N/A và ảnh hưởng reput.
          </p>
          <div className="btnrow">
            <button className="btn" disabled={takeoverVerifying} onClick={runTakeoverVerify}>
              {takeoverVerifying
                ? "Đang xác minh — probe + deploy + confirm…"
                : "▶ Chạy vòng xác minh takeover"}
            </button>
          </div>
          {takeoverVerifying && (
            <p className="meta">
              Fingerprint probe chạy trong sandbox; nếu có hosting cấu hình
              (TAKEOVER_HOSTING) worker sẽ deploy PoC page rồi confirm lại qua
              subdomain (propagation có thể mất tới vài phút).
            </p>
          )}
          {takeoverResult && (
            <div>
              <p className="badges">
                <span
                  className={
                    takeoverResult.verdict === "verified"
                      ? "badge ok"
                      : takeoverResult.verdict === "needs_manual"
                        ? "badge"
                        : "badge down"
                  }
                >
                  {takeoverResult.verdict === "verified"
                    ? "Finding — kiểm soát được chứng minh"
                    : takeoverResult.verdict === "needs_manual"
                      ? "cần xác minh tay"
                      : "false positive"}{" "}
                  · score {takeoverResult.score.toFixed(2)} / ngưỡng{" "}
                  {takeoverResult.threshold.toFixed(2)}
                </span>
                {takeoverResult.service && (
                  <span className="badge info">service: {takeoverResult.service}</span>
                )}
                {takeoverResult.patterns.map((p) => (
                  <span key={p} className="badge info">pattern: {p}</span>
                ))}
              </p>
              <p className="meta">
                {takeoverResult.cname && (
                  <>
                    CNAME: <code>{takeoverResult.cname}</code> ·{" "}
                  </>
                )}
                {takeoverResult.poc_url && (
                  <>
                    PoC: <code>{takeoverResult.poc_url}</code> ·{" "}
                  </>
                )}
                {takeoverResult.token && (
                  <>
                    token: <code>{takeoverResult.token}</code> ·{" "}
                  </>
                )}
                PoC page chứa username <code>{takeoverResult.username}</code>
              </p>
              <p className="meta">{takeoverResult.reason}</p>
              {takeoverResult.guidance && (
                <p className="alert">Hướng dẫn: {takeoverResult.guidance}</p>
              )}
            </div>
          )}
        </>
      )}

      <h2 className="section-title">Chuyển trạng thái</h2>
      <div className="btnrow">
        {TRANSITIONS.filter((s) => s !== candidate.status).map((s) => (
          <button
            key={s}
            className="btn"
            disabled={saving}
            onClick={() => transition(s)}
          >
            → {candidateStatusLabel(s)}
          </button>
        ))}
      </div>

      {reportable && (
        <>
          <h2 className="section-title">Report (nộp tay trên platform)</h2>
          <p className="meta">
            Draft sinh từ evidence theo mẫu platform — sửa từng phần, copy, tự
            nộp trên platform rồi đánh dấu bên dưới. Ứng dụng KHÔNG tự submit
            (auto-submit là v2).
          </p>
          <div className="btnrow badges">
            {REPORT_PLATFORMS.map((p) => (
              <button
                key={p}
                className={`btn${p === reportPlatform ? " active" : ""}`}
                disabled={reportLoading}
                onClick={() => loadReport(p)}
              >
                {p === "hackerone" ? "HackerOne" : "Intigriti"}
              </button>
            ))}
            {reportDraft && (
              <span className="badge">
                {reportDraft.source === "saved" ? "bản nháp đã lưu" : "sinh tự động từ evidence"}
              </span>
            )}
          </div>
          {reportMsg && <p className="meta">{reportMsg}</p>}
          {reportLoading && <p className="meta">Đang tải draft…</p>}
          {reportSections && (
            <>
              {(
                [
                  "title",
                  "severity",
                  "summary",
                  "steps_to_reproduce",
                  "impact",
                  "evidence",
                ] as const
              ).map((key) => (
                <div key={key} className="reportform">
                  <p className="badges">
                    <strong>{REPORT_SECTION_LABEL[key]}</strong>
                    <button
                      className="btn"
                      onClick={() => copyText(key, reportSections[key])}
                    >
                      {copied === key ? "✓ Đã copy" : "Copy"}
                    </button>
                  </p>
                  {key === "severity" ? (
                    <input
                      value={reportSections[key]}
                      onChange={(e) => editSection(key, e.target.value)}
                    />
                  ) : (
                    <textarea
                      rows={key === "title" ? 2 : 8}
                      value={reportSections[key]}
                      onChange={(e) => editSection(key, e.target.value)}
                    />
                  )}
                </div>
              ))}
              <div className="btnrow">
                <button
                  className="btn"
                  onClick={() =>
                    copyText(
                      "all",
                      composeReportMarkdown(reportPlatform, reportSections),
                    )
                  }
                >
                  {copied === "all" ? "✓ Đã copy" : "Copy toàn bộ markdown"}
                </button>
                <button className="btn" disabled={reportSaving} onClick={saveDraft}>
                  {reportSaving ? "Đang lưu…" : "Lưu nháp"}
                </button>
                <button
                  className="btn"
                  disabled={reportLoading}
                  onClick={() => loadReport(reportPlatform, true)}
                >
                  Khôi phục bản sinh tự động
                </button>
              </div>
              <details>
                <summary className="meta">Preview markdown trọn bản</summary>
                <div className="logstream">
                  <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                    {composeReportMarkdown(reportPlatform, reportSections)}
                  </pre>
                </div>
              </details>

              <h3 className="section-title">Đã nộp trên platform?</h3>
              {candidate.status === "reported" && (
                <p className="meta">
                  Đã nộp {fmtTime(candidate.reported_at)}
                  {candidate.report_url && (
                    <>
                      {" · "}
                      <a href={candidate.report_url} target="_blank" rel="noreferrer">
                        {candidate.report_url}
                      </a>
                    </>
                  )}
                </p>
              )}
              <div className="reportform">
                <input
                  style={{ width: "100%" }}
                  placeholder="Link report trên platform (vd https://hackerone.com/reports/…)"
                  value={markUrl}
                  onChange={(e) => setMarkUrl(e.target.value)}
                />
                <textarea
                  rows={2}
                  placeholder="Ghi chú tự do: ngày nộp, trạng thái triage, mức thưởng…"
                  value={markNotes}
                  onChange={(e) => setMarkNotes(e.target.value)}
                />
              </div>
              <div className="btnrow">
                <button className="btn" disabled={marking} onClick={submitReported}>
                  {marking
                    ? "Đang lưu…"
                    : candidate.status === "reported"
                      ? "Cập nhật link / ghi chú"
                      : "Đánh dấu đã nộp (reported)"}
                </button>
              </div>
            </>
          )}
        </>
      )}

      <h2 className="section-title">Evidence</h2>
      {candidate.evidence_path ? (
        evidence ? (
          <>
            <p className="meta">
              <code>{evidence.path}</code>
              {evidence.truncated && " (truncated — file đầy đủ trên volume)"}
            </p>
            <div className="logstream">
              <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                {evidence.content}
              </pre>
            </div>
          </>
        ) : (
          <p className="meta">Đang tải evidence…</p>
        )
      ) : (
        <p className="meta">Không có evidence file cho Candidate này.</p>
      )}

      {candidate.verify_evidence_path && (
        <>
          <h2 className="section-title">
            {candidate.class === "takeover"
              ? "Verify evidence (fingerprint probe + PoC page + deploy + confirm)"
              : "Verify evidence (baseline + PoC + diff)"}
          </h2>
          {verifyEvidence ? (
            <>
              <p className="meta">
                <code>{verifyEvidence.path}</code>
                {verifyEvidence.truncated && " (truncated — file đầy đủ trên volume)"}
              </p>
              <div className="logstream">
                <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                  {verifyEvidence.content}
                </pre>
              </div>
            </>
          ) : (
            <p className="meta">Đang tải verify evidence…</p>
          )}
        </>
      )}

      {candidate.oob_evidence_path && (
        <>
          <h2 className="section-title">OOB evidence (callbacks + phân tích)</h2>
          {oobEvidence ? (
            <>
              <p className="meta">
                <code>{oobEvidence.path}</code>
                {oobEvidence.truncated && " (truncated — file đầy đủ trên volume)"}
              </p>
              <div className="logstream">
                <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                  {oobEvidence.content}
                </pre>
              </div>
            </>
          ) : (
            <p className="meta">Đang tải OOB evidence…</p>
          )}
        </>
      )}
    </main>
  );
}
