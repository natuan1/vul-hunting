-- 0004: Run + job queue (ADR-0001) + log stream + Tool Execution
-- ticket #6 — Run core

-- Run: một lần quét một Program (Recon Phase + Detection Phase ở ticket sau;
-- ticket này chỉ có stub tool sleep+echo để chứng minh vòng lặp)
CREATE TABLE IF NOT EXISTS runs (
    id                 SERIAL PRIMARY KEY,
    program_id         INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    status             TEXT NOT NULL DEFAULT 'pending', -- pending | running | completed | failed
    rate_limit_rps     REAL,                            -- req/s tối đa cho mọi request trong Run; NULL = không giới hạn
    ident_header_name  TEXT,                            -- header định danh, vd 'X-Bug-Bounty'
    ident_header_value TEXT,                            -- vd 'HackerOne-<username>'
    scope_snapshot     JSONB NOT NULL,                  -- Scope chụp lúc TẠO Run (không đọc assets trực tiếp sau đó)
    error              TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at         TIMESTAMPTZ,
    finished_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_runs_program ON runs(program_id);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);

-- Hàng đợi việc theo ADR-0001: Postgres thuần, FOR UPDATE SKIP LOCKED.
-- Tự lo retry (run_after + backoff), visibility timeout (locked_at quá hạn
-- không report → coi worker chết, job được claim lại) và dead-letter (status 'dead').
CREATE TABLE IF NOT EXISTS jobs (
    id           SERIAL PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    type         TEXT NOT NULL DEFAULT 'run',
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | running | done | dead
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    run_after    TIMESTAMPTZ NOT NULL DEFAULT now(), -- job available sau thời điểm này (retry có backoff)
    locked_at    TIMESTAMPTZ,                        -- mốc tính visibility timeout khi 'running'
    locked_by    TEXT,                               -- định danh consumer đang giữ job
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_jobs_claim ON jobs(status, run_after);

-- Log/stdout của từng Tool Execution trong Run — UI stream qua SSE
CREATE TABLE IF NOT EXISTS run_logs (
    id      BIGSERIAL PRIMARY KEY,
    run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    level   TEXT NOT NULL DEFAULT 'info',             -- info | error
    message TEXT NOT NULL,
    ts      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_run_logs_run ON run_logs(run_id, id);

-- Tool Execution: một lần chạy một công cụ CLI bên trong một Run
-- (giữ exit code, stdout, thời gian — stdout cũng đổ vào run_logs để stream)
CREATE TABLE IF NOT EXISTS tool_executions (
    id          BIGSERIAL PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    args        TEXT,
    status      TEXT NOT NULL DEFAULT 'running',      -- running | ok | failed
    exit_code   INTEGER,
    stdout      TEXT,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tool_executions_run ON tool_executions(run_id, seq);
