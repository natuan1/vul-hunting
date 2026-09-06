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
