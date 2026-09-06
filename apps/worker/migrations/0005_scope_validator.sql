-- 0005: Scope Validator (ticket #7) — chặn cứng target ngoài Scope + audit log

-- #7 mở rộng từ vựng tool_executions.status: thêm 'blocked' (validator chặn
-- target, tool không chạy) cạnh 'running | ok | failed' do 0004 định nghĩa —
-- 0004 đã áp dụng nên ghi nhận tại đây thay vì sửa file cũ

-- Config per-Run: cho phép subdomain non-production (mặc định KHÔNG)
ALTER TABLE runs ADD COLUMN IF NOT EXISTS allow_non_prod BOOLEAN NOT NULL DEFAULT FALSE;

-- Audit MỌI target của Tool Execution (cả allowed lẫn blocked):
-- thời gian, target, tool, Run — truy được theo Run / theo asset
CREATE TABLE IF NOT EXISTS scope_audit_log (
    id       BIGSERIAL PRIMARY KEY,
    run_id   INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tool     TEXT NOT NULL,
    target   TEXT NOT NULL,                 -- host đã chuẩn hoá (thấp, không scheme/port)
    decision TEXT NOT NULL,                 -- allowed | blocked_out_of_scope | blocked_non_prod
    reason   TEXT,                          -- giải thích tiếng Việt cho người xem
    ts       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scope_audit_run ON scope_audit_log(run_id, id);
CREATE INDEX IF NOT EXISTS idx_scope_audit_target ON scope_audit_log(target);
