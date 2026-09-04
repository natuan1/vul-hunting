export const dynamic = "force-dynamic";

const WORKER_URL = () => process.env.WORKER_API_URL ?? "http://worker:8000";

export async function POST(
  _req: Request,
  { params }: { params: Promise<{ platform: string }> },
) {
  const { platform } = await params;
  const res = await fetch(`${WORKER_URL()}/sync/${platform}`, {
    method: "POST",
    cache: "no-store",
  });
  return Response.json(await res.json(), { status: res.status });
}

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ platform: string }> },
) {
  const { platform } = await params;
  const res = await fetch(`${WORKER_URL()}/sync/${platform}/status`, {
    cache: "no-store",
  });
  return Response.json(await res.json(), { status: res.status });
}
