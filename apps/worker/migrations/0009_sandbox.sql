-- 0009: Sandbox bridge (ticket #11, ADR-0003) — verify session + egress log

-- Verify session: MỘT lần gọi run_in_sandbox = MỘT container --rm mới tinh.
-- Status lifecycle: running → ok | timeout | blocked (chặn tại bridge, không có
-- container nào được quay) | error (lỗi môi trường docker).
-- Script gốc lưu lại để đối chiếu evidence khi viết report (bằng chứng "PoC
-- đã làm gì"). run_id SET NULL khi Run bị xoá — session vẫn còn để audit.
CREATE TABLE IF NOT EXISTS sandbox_sessions (
    id             BIGSERIAL PRIMARY KEY,
    run_id         INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    target         TEXT NOT NULL,                 -- host đã chuẩn hoá (validator đối chiếu)
    script         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'running',
    exit_code      INTEGER,
    stdout         TEXT,                          -- cap DB, giống tool_executions
    stderr         TEXT,
    reason         TEXT,                          -- giải thích cho status blocked/error
    container_name TEXT,                          -- docker ps truy được theo session
    network_name   TEXT,                          -- network --internal riêng của session
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at    TIMESTAMPTZ,
    CHECK (status IN ('running', 'ok', 'timeout', 'blocked', 'error'))
);

CREATE INDEX IF NOT EXISTS idx_sandbox_sessions_run ON sandbox_sessions(run_id, id);
CREATE INDEX IF NOT EXISTS idx_sandbox_sessions_status ON sandbox_sessions(status);

-- Egress log: MỌI destination mà sandbox định chạm tới, do egress proxy ghi
-- (đúng 1 dòng/connection) — truy được theo verify session. Request nhắm ngoài
-- Scope bị proxy TỪ CHỐI forward → vẫn có dòng decision 'blocked*' nhưng
-- KHÔNG có packet nào đi ra ngoài.
CREATE TABLE IF NOT EXISTS sandbox_egress (
    id          BIGSERIAL PRIMARY KEY,
    session_id  BIGINT NOT NULL REFERENCES sandbox_sessions(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,                    -- host:port của lần kết nối
    scheme      TEXT NOT NULL DEFAULT 'tcp',      -- http | https | tcp
    decision    TEXT NOT NULL,                    -- allowed | blocked_out_of_scope | blocked_non_prod | rejected
    reason      TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sandbox_egress_session ON sandbox_egress(session_id, id);
