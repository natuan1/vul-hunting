import { WORKER_URL } from "../../../../_lib/worker";

export const dynamic = "force-dynamic";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const classed = new URL(req.url).searchParams.get("classed");
  const qs = classed === "1" ? "?classed=1" : "";
  const res = await fetch(`${WORKER_URL()}/runs/${id}/urls${qs}`, {
    cache: "no-store",
  });
  return Response.json(await res.json(), { status: res.status });
}
