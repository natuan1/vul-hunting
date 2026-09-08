"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  candidateStatusBadgeClass,
  candidateStatusLabel,
  confidenceBadgeClass,
  confidenceText,
  fmtTime,
  severityBadgeClass,
  type Candidate,
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

const TRANSITIONS = ["verifying", "verified", "rejected"] as const;

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [candidate, setCandidate] = useState<Candidate | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [verifyEvidence, setVerifyEvidence] = useState<Evidence | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

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
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [load, loadEvidence, loadVerifyEvidence]);

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
          <h2 className="section-title">Verify evidence (baseline + PoC + diff)</h2>
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
    </main>
  );
}
