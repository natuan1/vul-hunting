-- 0013: Report theo mẫu platform + Preview + đánh dấu reported (ticket #18).

-- Draft report user sửa trên Preview lưu NGAY TRONG DB (lưu trễ) — map theo
-- platform {"hackerone": {...}, "intigriti": {...}} để 2 mẫu không đè nhau:
-- mỗi bản gồm {platform, sections, markdown, saved_at}. KHÔNG có submit API:
-- nộp là hành động tay của user trên platform, auto-submit là v2.
ALTER TABLE candidates
    ADD COLUMN IF NOT EXISTS report_drafts JSONB,
    ADD COLUMN IF NOT EXISTS report_url TEXT,   -- link report trên platform sau khi nộp tay
    ADD COLUMN IF NOT EXISTS report_notes TEXT, -- ghi chú tự do (ngày nộp, kết quả...)
    ADD COLUMN IF NOT EXISTS reported_at TIMESTAMPTZ;

-- lifecycle thêm `reported`: Finding đã nộp tay lên platform (bước cuối,
-- quyết định của người dùng — KHÔNG bao giờ do worker tự chuyển).
ALTER TABLE candidates
    DROP CONSTRAINT IF EXISTS candidates_status_check;
ALTER TABLE candidates
    ADD CONSTRAINT candidates_status_check
    CHECK (status IN ('new', 'verifying', 'verified', 'rejected', 'needs_manual', 'reported'));
