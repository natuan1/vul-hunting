export const dynamic = "force-dynamic";

const WORKER_URL = () => process.env.WORKER_API_URL ?? "http://worker:8000";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const res = await fetch(`${WORKER_URL()}/programs/${id}`, { cache: "no-store" });
  return Response.json(await res.json(), { status: res.status });
}
