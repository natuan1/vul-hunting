"use client";

import { useCallback, useEffect, useRef, useState } from "react";

type Program = {
  id: number;
  handle: string;
  name: string;
  currency: string | null;
  submission_state: string | null;
  offers_bounties: boolean;
  min_bounty: number | null;
  max_bounty: number | null;
  open_scope: boolean | null;
  triage_active: boolean | null;
  platform: string;
  asset_count: number;
};

type SyncState = {
  status: string;
  programs_total?: number | null;
  programs_done?: number | null;
  scopes_done?: number | null;
  error?: string | null;
};

const PLATFORMS = ["hackerone", "intigriti"] as const;
type Platform = (typeof PLATFORMS)[number];

const ASSET_TYPES = ["URL", "WILDCARD", "APPLE_OS_APP", "GOOGLE_PLAY_APP", "OTHER"];

export default function ProgramsPage() {
  const [items, setItems] = useState<Program[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [loading, setLoading] = useState(true);
  const [platform, setPlatform] = useState("hackerone");
  const [bounty, setBounty] = useState("any");
  const [bountyMin, setBountyMin] = useState("");
  const [bountyMinInput, setBountyMinInput] = useState("");
  const [assetType, setAssetType] = useState("all");
  const [q, setQ] = useState("");
  const [qInput, setQInput] = useState("");
  const [syncStates, setSyncStates] = useState<Record<string, SyncState | null>>({});
  const [syncing, setSyncing] = useState<Record<string, boolean>>({});
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({
      platform,
      bounty,
      asset_type: assetType,
      page: String(page),
      page_size: String(pageSize),
    });
    if (q) params.set("q", q);
    if (bountyMin) params.set("bounty_min", bountyMin);
    try {
      const res = await fetch(`/api/programs?${params}`);
      const data = await res.json();
      setItems(data.items ?? []);
      setTotal(data.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [platform, bounty, assetType, bountyMin, q, page, pageSize]);

  useEffect(() => {
    load();
  }, [load]);

  // debounce ô tìm kiếm + ô bounty tối thiểu
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput);
      setPage(1);
    }, 400);
    return () => clearTimeout(t);
  }, [qInput]);

  useEffect(() => {
    const t = setTimeout(() => {
      setBountyMin(bountyMinInput);
      setPage(1);
    }, 400);
    return () => clearTimeout(t);
  }, [bountyMinInput]);

  const refreshStatuses = useCallback(async (): Promise<boolean> => {
    const entries = await Promise.all(
      PLATFORMS.map(async (p) => {
        const res = await fetch(`/api/sync/${p}`);
        return [p, (await res.json()) as SyncState] as const;
      }),
    );
    const next: Record<string, SyncState | null> = {};
    let anyRunning = false;
    for (const [p, st] of entries) {
      next[p] = st;
      if (st?.status === "running") anyRunning = true;
    }
    setSyncStates(next);
    setSyncing(Object.fromEntries(PLATFORMS.map((p) => [p, next[p]?.status === "running"])));
    return anyRunning;
  }, []);

  const startSync = async (p: Platform) => {
    setSyncing((s) => ({ ...s, [p]: true }));
    await fetch(`/api/sync/${p}`, { method: "POST" });
    const running = await refreshStatuses();
    if (running && !pollRef.current) {
      pollRef.current = setInterval(async () => {
        const any = await refreshStatuses();
        if (!any) {
          if (pollRef.current) clearInterval(pollRef.current);
          pollRef.current = null;
          load();
        }
      }, 3000);
    }
  };

  useEffect(() => {
    // nếu đang có sync chạy (F5 giữa chừng) thì tiếp tục poll
    (async () => {
      const any = await refreshStatuses();
      if (any) {
        pollRef.current = setInterval(async () => {
          const still = await refreshStatuses();
          if (!still) {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
            load();
          }
        }, 3000);
      }
    })();
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pages = Math.max(1, Math.ceil(total / pageSize));
  const anyRunning = PLATFORMS.some((p) => syncing[p]);

  return (
    <main className="page wide">
      <div className="pagehead">
        <div>
          <h1>Programs</h1>
          <p className="sub">
            Bug bounty programs từ HackerOne &amp; Intigriti — chọn target rồi mới chạy recon.
          </p>
        </div>
        <div className="btnrow">
          {PLATFORMS.map((p) => (
            <button
              key={p}
              className="btn primary"
              onClick={() => startSync(p)}
              disabled={syncing[p] || anyRunning}
            >
              {syncing[p] ? `Đang sync ${p}…` : `Sync ${p}`}
            </button>
          ))}
        </div>
      </div>

      {PLATFORMS.map((p) => {
        const st = syncStates[p];
        if (!st || st.status === "never_synced") return null;
        if (st.status === "running")
          return (
            <div key={p} className="progress">
              [{p}] Đang sync: {st.programs_done ?? 0}/{st.programs_total ?? "?"} program ·{" "}
              {st.scopes_done ?? 0} scope — chậm vì tôn trọng rate limit của platform
            </div>
          );
        if (st.status === "error")
          return (
            <div key={p} className="alert">
              [{p}] Sync lỗi: {st.error} — bấm Sync {p} để resume từ điểm dừng.
            </div>
          );
        if (st.status === "done")
          return (
            <div key={p} className="done-note">
              [{p}] Sync xong: {st.programs_done ?? 0} program · {st.scopes_done ?? 0} scope.
            </div>
          );
        return null;
      })}

      <div className="toolbar">
        <select value={platform} onChange={(e) => { setPlatform(e.target.value); setPage(1); }}>
          <option value="all">Tất cả platform</option>
          <option value="hackerone">HackerOne</option>
          <option value="intigriti">Intigriti</option>
        </select>
        <select value={bounty} onChange={(e) => { setBounty(e.target.value); setPage(1); }}>
          <option value="any">Bounty: tất cả</option>
          <option value="yes">Có bounty</option>
          <option value="no">Không bounty</option>
        </select>
        <select value={assetType} onChange={(e) => { setAssetType(e.target.value); setPage(1); }}>
          <option value="all">Loại asset: tất cả</option>
          {ASSET_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input
          type="number"
          min="0"
          placeholder="Payout tối đa ≥ (EUR/USD)"
          title="Chỉ hiện program trả tối đa ít nhất số này (lọc theo maxBounty của Intigriti; H1 chỉ có cờ có/không bounty)"
          value={bountyMinInput}
          onChange={(e) => setBountyMinInput(e.target.value)}
          style={{ maxWidth: 190 }}
        />
        <input
          placeholder="Từ khoá tên / handle / scope…"
          value={qInput}
          onChange={(e) => setQInput(e.target.value)}
        />
      </div>

      <table className="tbl">
        <thead>
          <tr>
            <th>Program</th>
            <th>Platform</th>
            <th>Bounty</th>
            <th>Scope</th>
            <th>Assets</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr><td colSpan={6}>Đang tải…</td></tr>
          )}
          {!loading && items.length === 0 && (
            <tr><td colSpan={6}>Chưa có program nào — bấm nút Sync ở trên.</td></tr>
          )}
          {items.map((p) => (
            <tr key={p.id}>
              <td>
                <span className="pname">{p.name}</span>
                <span className="phandle">{p.handle}</span>
              </td>
              <td>{p.platform}</td>
              <td>
                <span className={`badge ${p.offers_bounties ? "ok" : "down"}`}>
                  {p.offers_bounties
                    ? p.max_bounty
                      ? `tới ${p.max_bounty.toLocaleString("vi-VN")} ${p.currency ?? ""}`
                      : "có"
                    : "không"}
                </span>
              </td>
              <td>{p.open_scope === null ? "—" : p.open_scope ? "open" : "closed"}</td>
              <td>{p.asset_count}</td>
              <td>{p.submission_state ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="pager">
        <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>← Trước</button>
        <span>Trang {page} / {pages} · {total} program</span>
        <button className="btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>Sau →</button>
      </div>
    </main>
  );
}
