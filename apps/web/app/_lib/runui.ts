// Helper dùng chung cho UI Run (badge trạng thái, format thời gian)
// Đặt trong _lib để App Router không nhầm là route

export function statusBadgeClass(status: string): string {
  if (status === "completed") return "badge ok";
  if (status === "failed") return "badge down";
  if (status === "halted") return "badge down"; // guardrail dừng (ticket #19) — đỏ
  return "badge info"; // pending | running
}

export function fmtTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString("vi-VN") : "—";
}

// Quyết định của Scope Validator → class badge (allowed xanh, non-prod xanh dương, ngoài Scope đỏ)
export function decisionBadgeClass(decision: string): string {
  if (decision === "allowed") return "badge ok";
  if (decision === "blocked_non_prod") return "badge info";
  return "badge down"; // blocked_out_of_scope
}

export function decisionLabel(decision: string): string {
  if (decision === "allowed") return "cho phép";
  if (decision === "blocked_non_prod") return "chặn (non-prod)";
  if (decision === "blocked_blacklist") return "chặn (blacklist)"; // ticket #19
  return "chặn (ngoài Scope)";
}

// ── Candidate / Findings (ticket #10) ──

export type Candidate = {
  id: number;
  run_id: number;
  target: string;
  class: string;
  param: string;
  template_id: string;
  title: string | null;
  severity: string;
  matcher_name: string | null;
  status: string;
  evidence_path: string | null;
  first_seen: string;
  // kết quả vòng xác minh (ticket #12)
  confidence: number | null;
  confidence_threshold: number | null;
  reject_reason: string | null;
  verify_evidence_path: string | null;
  // OOB callback (ticket #13)
  oob_callback_count: number;
  oob_evidence_path: string | null;
};

export function severityBadgeClass(severity: string): string {
  if (severity === "critical" || severity === "high") return "badge down";
  if (severity === "low") return "badge info";
  return "badge"; // medium / info
}

export function candidateStatusBadgeClass(status: string): string {
  if (status === "verified") return "badge ok";
  if (status === "rejected") return "badge down";
  if (status === "verifying") return "badge";
  if (status === "needs_manual") return "badge"; // #14: chờ xác minh tay
  return "badge info"; // new
}

export function candidateStatusLabel(status: string): string {
  if (status === "verifying") return "đang xác minh";
  if (status === "verified") return "đã xác minh";
  if (status === "rejected") return "loại bỏ";
  if (status === "needs_manual") return "cần xác minh tay";
  return "mới";
}

// Confidence score của vòng xác minh (0.0–1.0) — badge xanh khi đạt ngưỡng,
// đỏ khi bị loại, xám khi chưa verify
export function confidenceBadgeClass(status: string, score: number | null): string {
  if (score === null) return "badge";
  if (status === "verified") return "badge ok";
  if (status === "rejected") return "badge down";
  return "badge info"; // verifying / new nhưng đã có score cũ
}

export function confidenceText(score: number | null, threshold: number | null): string {
  if (score === null) return "—";
  const base = score.toFixed(2);
  return threshold !== null ? `${base} / ${threshold.toFixed(2)}` : base;
}

// ── OOB callback (ticket #13) ──

// Badge callback OOB: xanh khi có callback (bằng chứng blind), xám khi chưa có
export function oobBadgeClass(count: number): string {
  return count > 0 ? "badge ok" : "badge";
}

export function oobText(count: number): string {
  return count > 0 ? `${count} callback` : "—";
}
