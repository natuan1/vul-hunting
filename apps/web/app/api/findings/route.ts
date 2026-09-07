import { WORKER_URL } from "../../_lib/worker";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const qs = new URL(req.url).searchParams.toString();
  const res = await fetch(`${WORKER_URL()}/candidates${qs ? `?${qs}` : ""}`, {
    cache: "no-store",
  });
  return Response.json(await res.json(), { status: res.status });
}
