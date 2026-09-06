import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const body = await req.text();
  const res = await fetch(`${WORKER_URL()}/programs/${id}/runs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: body || "{}",
    cache: "no-store",
  });
  return Response.json(await res.json(), { status: res.status });
}
