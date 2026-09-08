-- 0010: Vòng xác minh (ticket #12) — kết quả verify open redirect trên Candidate

-- Confidence score 0.0–1.0 chấm khi verify (kèm ngưỡng đúng lúc chấm —
-- ngưỡng cấu hình được qua VERIFY_CONFIDENCE_THRESHOLD nên phải ghi lại
-- theo từng lần để đối chiếu về sau).
-- Verify session: baseline (request vô hại) + PoC (quyết định) — 2 container
-- ephemeral riêng, truy được egress log theo session id (ticket #11).
-- Reject reason + verify evidence (baseline + PoC + diff + pattern log) lưu
-- file JSON trên volume, path trong verify_evidence_path (tách khỏi
-- evidence_path của Detection Phase — mỗi phase một bằng chứng).
ALTER TABLE candidates
    ADD COLUMN IF NOT EXISTS confidence REAL,
    ADD COLUMN IF NOT EXISTS confidence_threshold REAL,
    ADD COLUMN IF NOT EXISTS reject_reason TEXT,
    ADD COLUMN IF NOT EXISTS verify_evidence_path TEXT,
    ADD COLUMN IF NOT EXISTS verify_session_id BIGINT REFERENCES sandbox_sessions(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS baseline_session_id BIGINT REFERENCES sandbox_sessions(id) ON DELETE SET NULL;

-- score luôn nằm trong đoạn 0.0–1.0 (do pipeline chấm, không nhận giá trị ngoài)
ALTER TABLE candidates
    DROP CONSTRAINT IF EXISTS chk_candidates_confidence_range;
ALTER TABLE candidates
    ADD CONSTRAINT chk_candidates_confidence_range
    CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1));
