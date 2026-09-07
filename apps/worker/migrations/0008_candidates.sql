-- 0008: Detection core (ticket #10) — nuclei → Candidate + Evidence

-- Candidate: nghi vấn lỗ hổng do nuclei phát hiện trong Detection Phase.
-- Dedupe theo đề bài: CÙNG asset + class + param → 1 row duy nhất trong Run
-- (UNIQUE run_id + target + class + param; finding trùng bị bỏ qua).
-- Evidence (raw request/response, template id, matcher) lưu file JSON trên
-- docker volume, đường dẫn ghi ở evidence_path (tách khỏi artifacts_dir vì
-- artifacts bị xoá mỗi attempt còn evidence phải sống qua retry).
-- Status lifecycle: new → verifying → verified/rejected (ticket #12+ điều phối).
CREATE TABLE IF NOT EXISTS candidates (
    id            BIGSERIAL PRIMARY KEY,
    run_id        INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    target        TEXT NOT NULL,                  -- asset bị detect (URL/host)
    class         TEXT NOT NULL DEFAULT 'misc',   -- lớp lỗ hổng (tags nuclei ∩ vocab)
    param         TEXT NOT NULL DEFAULT '',       -- tên param của target (dedupe)
    template_id   TEXT NOT NULL,                  -- nuclei template id
    title         TEXT,                           -- info.name của template
    severity      TEXT NOT NULL DEFAULT 'info',   -- info/low/medium/high/critical
    matcher_name  TEXT,                           -- matcher khớp từ nuclei
    status        TEXT NOT NULL DEFAULT 'new',
    evidence_path TEXT,                           -- file JSON evidence trên volume
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, target, class, param),
    CHECK (status IN ('new', 'verifying', 'verified', 'rejected')),
    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_candidates_run_status ON candidates(run_id, status);
CREATE INDEX IF NOT EXISTS idx_candidates_class_sev ON candidates(class, severity);
