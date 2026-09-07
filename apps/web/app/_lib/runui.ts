// Helper dùng chung cho UI Run (badge trạng thái, format thời gian)
// Đặt trong _lib để App Router không nhầm là route

export function statusBadgeClass(status: string): string {
  if (status === "completed") return "badge ok";
  if (status === "failed") return "badge down";
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
  return "badge info"; // new
}

export function candidateStatusLabel(status: string): string {
  if (status === "verifying") return "đang xác minh";
  if (status === "verified") return "đã xác minh";
  if (status === "rejected") return "loại bỏ";
  return "mới";
}
