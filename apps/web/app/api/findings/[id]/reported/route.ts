// Đánh dấu Finding đã nộp TAY trên platform (ticket #18) — chỉ ghi nhận
// trạng thái + link + ghi chú, không có request nào gửi đi platform.
import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await fetch(`${WORKER_URL()}/candidates/${id}/reported`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(await req.json()),
  });
  return Response.json(await res.json(), { status: res.status });
}
