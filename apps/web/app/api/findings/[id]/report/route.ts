// Report draft (ticket #18): GET sinh/đọc draft theo platform — CHỈ xem,
// không có đường submit lên platform (nộp là thao tác tay, auto-submit là v2).
import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

function query(req: Request): string {
  const url = new URL(req.url);
  const platform = url.searchParams.get("platform");
  const refresh = url.searchParams.get("refresh");
  const qs = new URLSearchParams();
  if (platform) qs.set("platform", platform);
  if (refresh) qs.set("refresh", "1");
  const s = qs.toString();
  return s ? `?${s}` : "";
}

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await fetch(
    `${WORKER_URL()}/candidates/${id}/report${query(req)}`,
    { cache: "no-store" },
  );
  return Response.json(await res.json(), { status: res.status });
}

export async function PUT(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await fetch(`${WORKER_URL()}/candidates/${id}/report`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(await req.json()),
  });
  return Response.json(await res.json(), { status: res.status });
}
