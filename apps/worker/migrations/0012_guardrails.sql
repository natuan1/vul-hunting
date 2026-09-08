-- Guardrails (ticket #19): blacklist asset do scope violation.
-- Target bị Scope Validator chặn vì NGOÀI Scope → lưu lại để các Run sau
-- chặn NGAY từ validate (không đợi lookup Scope), kèm lý do gốc.
-- Gỡ blacklist là thao tác tay (SQL) — scope mở rộng hợp lệ là quyết định
-- của người dùng, không phải của tool.

CREATE TABLE IF NOT EXISTS asset_blacklist (
    id BIGSERIAL PRIMARY KEY,
    program_id BIGINT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (program_id, host)
);
