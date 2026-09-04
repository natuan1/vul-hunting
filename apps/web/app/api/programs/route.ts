export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const workerUrl = process.env.WORKER_API_URL ?? "http://worker:8000";
  const { searchParams } = new URL(req.url);
  const res = await fetch(`${workerUrl}/programs?${searchParams.toString()}`, {
    cache: "no-store",
  });
  return Response.json(await res.json(), { status: res.status });
}
