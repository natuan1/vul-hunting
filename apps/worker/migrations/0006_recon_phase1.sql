-- 0006: Recon Phase 1 (ticket #8) — chuỗi subfinder → amass → dnsx → naabu → httpx

-- Tool Execution ghi đủ stderr + đường dẫn artifact JSONL trên docker volume
ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS stderr TEXT;
ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS artifact_path TEXT;

-- Kết quả recon theo Run: 1 row / host. Subdomain xuất hiện ngay sau bước
-- discovery (UI đếm tăng dần), DNS/HTTP bổ sung qua từng bước sau.
-- CNAME lưu cột riêng để nuôi lớp subdomain takeover (ticket #14).
CREATE TABLE IF NOT EXISTS recon_assets (
    id          BIGSERIAL PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host        TEXT NOT NULL,                 -- host đã chuẩn hoá (thấp, không scheme/port)
    sources     TEXT[] NOT NULL DEFAULT '{}',  -- tool phát hiện: subfinder, amass, ...
    cname       TEXT,                          -- chuỗi CNAME (nếu có) — nuôi lớp takeover
    ip          TEXT[],                        -- A record (dnsx)
    ports       INTEGER[],                     -- cổng mở (naabu)
    is_live     BOOLEAN NOT NULL DEFAULT FALSE,-- httpx xác nhận HTTP sống
    http_url    TEXT,
    http_status INTEGER,
    http_title  TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, host)
);

CREATE INDEX IF NOT EXISTS idx_recon_assets_run ON recon_assets(run_id, host);
CREATE INDEX IF NOT EXISTS idx_recon_assets_live ON recon_assets(run_id, is_live);
