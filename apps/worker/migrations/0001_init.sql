-- 0001: Platform / Program / Asset (scope) + sync_state
-- ticket #3 — Sync HackerOne → Programs

CREATE TABLE IF NOT EXISTS platforms (
    id   SERIAL PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,          -- 'hackerone' | 'intigriti'
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS programs (
    id                   SERIAL PRIMARY KEY,
    platform_id          INTEGER NOT NULL REFERENCES platforms(id),
    handle               TEXT NOT NULL,             -- slug trên platform
    name                 TEXT NOT NULL,
    currency             TEXT,
    policy               TEXT,
    submission_state     TEXT,                      -- open | closed | ...
    state                TEXT,
    offers_bounties      BOOLEAN NOT NULL DEFAULT FALSE,
    open_scope           BOOLEAN,
    triage_active        BOOLEAN,
    started_accepting_at TIMESTAMPTZ,
    synced_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (platform_id, handle)
);

CREATE TABLE IF NOT EXISTS assets (
    id                      SERIAL PRIMARY KEY,
    program_id              INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    asset_identifier        TEXT NOT NULL,          -- ví dụ 'example.com' hoặc '*.example.com'
    asset_type              TEXT NOT NULL,          -- URL | WILDCARD | APPLE_OS_APP | GOOGLE_PLAY_APP | OTHER | ...
    eligible_for_bounty     BOOLEAN NOT NULL DEFAULT FALSE,
    eligible_for_submission BOOLEAN NOT NULL DEFAULT FALSE,
    max_severity            TEXT,
    instruction             TEXT,
    UNIQUE (program_id, asset_identifier, asset_type)
);

CREATE INDEX IF NOT EXISTS idx_programs_name ON programs(name);
CREATE INDEX IF NOT EXISTS idx_programs_bounty ON programs(offers_bounties);
CREATE INDEX IF NOT EXISTS idx_assets_identifier ON assets(asset_identifier);
CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_id);

-- Trạng thái sync từng platform (1 row đang chạy mỗi platform; claim hết hạn sau 15 phút)
CREATE TABLE IF NOT EXISTS sync_state (
    id             SERIAL PRIMARY KEY,
    platform_slug  TEXT NOT NULL,
    status         TEXT NOT NULL,                   -- running | done | error
    programs_total INTEGER,
    programs_done  INTEGER NOT NULL DEFAULT 0,
    scopes_done    INTEGER NOT NULL DEFAULT 0,
    last_handle    TEXT,                            -- resume point khi error
    error          TEXT,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sync_state_platform ON sync_state(platform_slug, status);
