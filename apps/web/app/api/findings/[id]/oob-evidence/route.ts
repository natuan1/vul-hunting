import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await fetch(`${WORKER_URL()}/candidates/${id}/oob-evidence`, {
    cache: "no-store",
  });
  return Response.json(await res.json(), { status: res.status });
}
