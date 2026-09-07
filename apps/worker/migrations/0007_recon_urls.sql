-- 0007: Recon Phase 2 (ticket #9) — katana crawl + gau/waymore URL lịch sử
-- + gf slicing → bảng URLs + params gắn nhãn class (nguồn cho Detection Phase)

-- 1 row / URL (đã chuẩn hoá) trong Run. Chìa khoá dedupe crawled ↔ lịch sử là
-- (run_id, url): cùng 1 URL từ katana và gau/waymore GỘP sources/classes vào
-- 1 row duy nhất (upsert merge mảng, cùng kiểu với recon_assets.sources).
-- classes là nhãn từ gf patterns (xss, sqli, ssrf, redirect, ssti, ...) —
-- Detection Phase truy URL theo class qua index GIN.
CREATE TABLE IF NOT EXISTS recon_urls (
    id          BIGSERIAL PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,                 -- URL đã chuẩn hoá (lowercase host, bỏ fragment/port mặc định)
    host        TEXT NOT NULL,                 -- host của URL (join được với recon_assets.host)
    params      TEXT[] NOT NULL DEFAULT '{}',  -- tên param trong query string
    sources     TEXT[] NOT NULL DEFAULT '{}',  -- nguồn: katana, gau, waymore
    classes     TEXT[] NOT NULL DEFAULT '{}',  -- nhãn class từ gf patterns
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, url)
);

CREATE INDEX IF NOT EXISTS idx_recon_urls_run_host ON recon_urls(run_id, host);
CREATE INDEX IF NOT EXISTS idx_recon_urls_classes ON recon_urls USING GIN (classes);
