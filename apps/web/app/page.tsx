"use client";

import { useCallback, useEffect, useState } from "react";

type PostgresStatus = {
  connected: boolean;
  latency_ms?: number;
  version?: string | null;
  error?: string;
};

type Health = {
  web: { status: string };
  worker: { status: string; postgres?: PostgresStatus; error?: string };
};

function Badge({ ok }: { ok: boolean }) {
  return (
    <span className={`badge ${ok ? "ok" : "down"}`}>{ok ? "OK" : "DOWN"}</span>
  );
}

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);

  const load = useCallback(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  const postgres = health?.worker?.postgres;

  return (
    <main className="page">
      <h1>vul-hunting</h1>
      <p className="sub">Bug bounty hunting assistant — trạng thái hệ thống</p>
      <div className="tiles">
        <div className="tile">
          <h2>Web (Next.js)</h2>
          <Badge ok={!!health} />
          <p className="meta">
            {health ? "Đang phục vụ requests" : "Đang tải..."}
          </p>
        </div>
        <div className="tile">
          <h2>Worker (FastAPI)</h2>
          <Badge ok={health?.worker?.status === "ok"} />
          <p className="meta">{health?.worker?.status ?? "—"}</p>
        </div>
        <div className="tile">
          <h2>Postgres</h2>
          <Badge ok={!!postgres?.connected} />
          <p className="meta">
            {postgres?.connected
              ? `latency ${postgres.latency_ms} ms · PostgreSQL ${postgres.version}`
              : (postgres?.error ?? "—")}
          </p>
        </div>
      </div>
      <p className="updated">Tự động làm mới mỗi 5 giây</p>
    </main>
  );
}
