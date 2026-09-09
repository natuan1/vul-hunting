-- 0012: Subdomain takeover (ticket #14) — status lifecycle mới `needs_manual`.

-- Policy của nhiều Program (vd Goldman Sachs): takeover xác nhận bằng fingerprint
-- mà KHÔNG chứng minh được kiểm soát (PoC page hoạt động) sẽ bị đóng N/A và
-- ảnh hưởng reput. Khi chưa cấu hình hosting chứng minh kiểm soát
-- (TAKEOVER_HOSTING rỗng), vòng verify dừng ở "fingerprint match — cần xác minh
-- tay": Candidate giữ trạng thái riêng `needs_manual` (KHÔNG phải verdict
-- verified/rejected) để UI lộ rõ việc người dùng phải làm tiếp.
ALTER TABLE candidates
    DROP CONSTRAINT IF EXISTS candidates_status_check;
ALTER TABLE candidates
    ADD CONSTRAINT candidates_status_check
    CHECK (status IN ('new', 'verifying', 'verified', 'rejected', 'needs_manual'));
