-- 0003: AI summary + đánh giá khả năng tự động hoá của Program (cache)
-- ticket #5 — Program Detail: scope, policy, AI summary lazy

CREATE TABLE IF NOT EXISTS program_summaries (
    program_id   INTEGER PRIMARY KEY REFERENCES programs(id) ON DELETE CASCADE,
    summary      TEXT,                            -- markdown: tóm tắt + đánh giá tự động hoá
    model        TEXT,                            -- model đã dùng để sinh
    status       TEXT NOT NULL DEFAULT 'none',    -- none | generating | ready | error
    error        TEXT,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
