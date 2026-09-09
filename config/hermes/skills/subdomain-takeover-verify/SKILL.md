---
name: subdomain-takeover-verify
description: Xác minh agentic Candidate class "takeover" (subdomain takeover)
  của vul-hunting — fingerprint probe + PoC page chứng minh kiểm soát (chứa
  username) + confirm qua subdomain. Dùng khi cần xác minh một Candidate
  subdomain takeover trước khi report.
---

# Subdomain takeover verify (vòng xác minh ticket #14)

Mục tiêu: biến **Candidate** class `takeover` thành **Finding** (status
`verified`) CHỈ khi chứng minh được **kiểm soát subdomain** bằng PoC page hoạt
động, hoặc kết luận **rejected** khi không kiểm soát được, hoặc dừng ở
**needs_manual** khi chưa có hosting tự động. Fingerprint match THÔI thì
KHÔNG được report — nhiều Program (vd Goldman Sachs) đóng N/A report takeover
thiếu PoC và reput bị ảnh hưởng. Mọi request chạm target chạy TRONG sandbox
qua MCP tool; agent không bao giờ fetch target trực tiếp.

## Khi nào dùng

- Người dùng/nghiệp vụ yêu cầu "xác minh Candidate takeover #N".
- Sau Detection Phase, có Candidate `class: takeover` status `new` cần xác minh.

## Quy trình

1. **Nhận Candidate**: cần `candidate_id`.
2. **Gọi tool MCP `mcp_sandbox_verify_subdomain_takeover`** với
   `{"candidate_id": <id>}`. Tool đi trọn vòng:
   - **Fingerprint probe** (sandbox): service tương ứng CNAME (GitHub Pages,
     S3, Heroku…) còn ở trạng thái bỏ hoang không? Mất fingerprint →
     `rejected` (`fingerprint_gone`);
   - **Soạn PoC page**: chứa USERNAME ĐỊNH DANH của user (HACKERONE_USERNAME/
     INTIGRITI_USERNAME) + token one-shot — không có username → `needs_manual`
     (`missing_username`);
   - **Deploy** qua hosting khả dụng (`TAKEOVER_HOSTING` = github-pages/s3):
     claim đúng hostname mà CNAME trỏ tới. Deploy/claim lỗi → `rejected`
     (`claim_failed` — fingerprint match nhưng không kiểm soát được);
   - **Confirm probe** (sandbox): PoC page được PHỤC VỤ QUA SUBDOMAIN →
     kiểm soát được chứng minh → `verified` (score 0.95). Deploy xong mà
     subdomain không phục vụ PoC → `rejected` (`no_control`).
   - **Chưa cấu hình hosting** → `needs_manual`
     (`manual_verification_required`) kèm hướng dẫn claim + nội dung PoC page
     — KHÔNG phải rejected: đó là việc người dùng phải làm tay.
3. **Đọc kết quả JSON** và diễn giải ĐÚNG:
   - `verdict: "verified"` → Finding thật, đã có PoC hoạt động (`poc_url`,
     `token`, `username` là bằng chứng; evidence gồm fingerprint probe +
     deploy + confirm probe);
   - `verdict: "rejected"` → KHÔNG được báo thật. Đọc `patterns`:
     - `fingerprint_gone` — service đã gắn lại;
     - `claim_failed` — không claim/kiểm soát được qua hosting khả dụng;
     - `no_control` — subdomain không phục vụ PoC sau deploy;
     - `probe_error` / `no_cname` — không xác minh được (không phải verdict
       kỹ thuật).
   - `verdict: "needs_manual"` → dừng và BÁO NGƯỜI DÙNG hướng dẫn trong
     `guidance` (claim gì trên service nào, PoC page phải chứa username +
     token nào) — người dùng làm tay rồi verify lại, hoặc tự chuyển trạng
     thái Candidate qua UI.
4. **Báo cáo**: nêu verdict, service + CNAME + claim host, reason, pattern
   log, evidence path + verify session ids. Khi tư vấn report, NHẮC: đính kèm
   PoC page hoạt động (URL + nội dung chứa username) — takeover xác nhận
   thiếu PoC sẽ bị đóng N/A và ảnh hưởng reput.

## Rào cấm

- KHÔNG chạy curl/python/payload trực tiếp trong terminal — mọi request tới
  target phải qua tool sandbox. Target ngoài Scope bị chặn tại bridge.
- KHÔNG tự đổi `verdict` của tool; KHÔNG gợi ý report khi verdict khác
  `verified` — kể cả fingerprint còn match (diff analysis/confirm đã loại các
  trường hợp không kiểm soát được).
- KHÔNG dùng tool này cho Candidate class khác `takeover` (tool tự từ chối).
- KHÔNG deploy PoC page ngoài luồng tool (deploy chạy phía worker qua hosting
  đã cấu hình — agent không tự phát request tới GitHub/S3).

## Kiểm chứng

- evidence file (`evidence_path`) chứa fingerprint probe + PoC page (page,
  username, token) + deploy detail + confirm profile — đọc được qua
  `GET /candidates/{id}/verify-evidence`.
- `status` của Candidate trong DB là `verified`/`rejected`/`needs_manual`
  tương ứng; `needs_manual` giữ Candidate ngoài hai verdict để UI lộ rõ việc
  còn chờ người dùng.
