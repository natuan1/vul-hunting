export const dynamic = "force-dynamic";

export async function GET() {
  const workerUrl = process.env.WORKER_API_URL ?? "http://worker:8000";
  try {
    const res = await fetch(`${workerUrl}/healthz`, { cache: "no-store" });
    const worker = await res.json();
    return Response.json({ web: { status: "ok" }, worker });
  } catch (error) {
    return Response.json({
      web: { status: "ok" },
      worker: {
        status: "unreachable",
        postgres: { connected: false, error: String(error) },
      },
    });
  }
}
