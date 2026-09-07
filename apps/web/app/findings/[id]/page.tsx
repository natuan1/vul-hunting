"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  candidateStatusBadgeClass,
  candidateStatusLabel,
  fmtTime,
  severityBadgeClass,
  type Candidate,
} from "../../_lib/runui";

type Evidence = {
  path: string;
  truncated: boolean;
  content: string;
};

const TRANSITIONS = ["verifying", "verified", "rejected"] as const;

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [candidate, setCandidate] = useState<Candidate | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
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
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [load, loadEvidence]);

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
    </main>
  );
}
