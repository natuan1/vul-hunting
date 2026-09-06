import { WORKER_URL } from "../../_lib/worker";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const qs = new URL(req.url).search;
  const res = await fetch(`${WORKER_URL()}/audit${qs}`, { cache: "no-store" });
  return Response.json(await res.json(), { status: res.status });
}
