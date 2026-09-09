import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  // body tuỳ chọn: { payload?: string } — trống thì worker dùng canary mặc định
  const body = await req.json().catch(() => ({}));
  const res = await fetch(`${WORKER_URL()}/candidates/${id}/verify-http`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return Response.json(await res.json(), { status: res.status });
}
