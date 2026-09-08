-- 0011: Interactsh OOB client (ticket #13) — register per-Run → payload domains
-- → poll callback → gắn Evidence (OOB callback) cho Candidate đang chờ verify.

-- Mỗi Run có đăng ký riêng với interactsh (public server mặc định): domain
-- payload xoay vòng THEO RUN, không tái sử dụng chéo. private_key (PEM PKCS8)
-- phải persist để poll về sau vẫn giải mã được callback (server trả dữ liệu
-- mã hoá bằng public key đã register) — key dùng một lần cho domain dùng một
-- lần, không phải secret dài hạn.
CREATE TABLE IF NOT EXISTS oob_registrations (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    server_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    correlation_id TEXT NOT NULL UNIQUE,
    secret_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'expired', 'closed')),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_oob_registrations_run
    ON oob_registrations(run_id, status);

-- Callback từ Internet về (DNS/HTTP/SMTP...): nguồn gốc Evidence OOB.
-- `source` = remote-address của interaction, `raw_interaction` = JSON gốc
-- giải mã từ poll response. candidate_id nhận khi token payload trong
-- full-id khớp một Candidate CÙNG Run (callback trôi nổi không gắn đâu).
CREATE TABLE IF NOT EXISTS oob_callbacks (
    id BIGSERIAL PRIMARY KEY,
    registration_id BIGINT NOT NULL REFERENCES oob_registrations(id) ON DELETE CASCADE,
    run_id BIGINT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    candidate_id BIGINT REFERENCES candidates(id) ON DELETE SET NULL,
    protocol TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    unique_id TEXT NOT NULL DEFAULT '',
    full_id TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw_interaction JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oob_callbacks_candidate
    ON oob_callbacks(candidate_id);
CREATE INDEX IF NOT EXISTS idx_oob_callbacks_received
    ON oob_callbacks(received_at);

-- UI hiển thị callback count + chi tiết trên Candidate; evidence OOB
-- (source, protocol, timestamp, raw interaction) lưu file, path ở đây
-- (tách khỏi evidence_path của Detection và verify_evidence_path của #12).
ALTER TABLE candidates
    ADD COLUMN IF NOT EXISTS oob_callback_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS oob_evidence_path TEXT;
