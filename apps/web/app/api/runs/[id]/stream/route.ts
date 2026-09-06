import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

// SSE pass-through: stream log của Run từ worker về browser
export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const after = new URL(req.url).searchParams.get("after") ?? "0";
  const res = await fetch(`${WORKER_URL()}/runs/${id}/stream?after=${after}`, {
    headers: { accept: "text/event-stream" },
    cache: "no-store",
  });
  return new Response(res.body, {
    status: res.status,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    },
  });
}
