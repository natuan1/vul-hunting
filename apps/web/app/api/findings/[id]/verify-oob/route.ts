import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  // body tuỳ chọn: { wait_s?: number, poll_s?: number } — trống thì worker dùng mặc định
  const body = await req.json().catch(() => ({}));
  const res = await fetch(`${WORKER_URL()}/candidates/${id}/verify-oob`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return Response.json(await res.json(), { status: res.status });
}
