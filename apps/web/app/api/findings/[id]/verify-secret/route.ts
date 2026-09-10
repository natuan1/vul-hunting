import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await fetch(`${WORKER_URL()}/candidates/${id}/verify-secret`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  return Response.json(await res.json(), { status: res.status });
}
