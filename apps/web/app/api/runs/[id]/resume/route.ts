import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

// Guardrail HALT (ticket #19) chỉ người bấm tay mới thoát — proxy POST sang worker
export async function POST(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await fetch(`${WORKER_URL()}/runs/${id}/resume`, { method: "POST" });
  return Response.json(await res.json(), { status: res.status });
}
