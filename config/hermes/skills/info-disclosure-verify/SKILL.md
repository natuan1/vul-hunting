---
name: info-disclosure-verify
description: Xác minh agentic Candidate class "disclosure" (info disclosure/
  debug endpoints) của vul-hunting — probe endpoint qua sandbox, marker nhạy
  cảm phải MỚI xuất hiện so với root host. Dùng khi cần xác minh một Candidate
  info disclosure trước khi report.
---

# Info disclosure / debug endpoints verify (batch A — ticket #15)

Mục tiêu: xác nhận endpoint lộ nội dung nhạy cảm MỚI so với root host
(baseline diff) — secret/private key/phpinfo/actuator. Stack trace đơn thuần
không đủ. Mọi request chạy TRONG sandbox.

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate info disclosure/debug #N".
- Có Candidate `class: disclosure` status `new` (vd /.env, /debug,
  /actuator/env, /.git/config…).

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_http_class`** với `{"candidate_id": <id>}`.
   Tool đi trọn vòng:
   - **Baseline**: GET root host (`https://host/`) — nội dung nền;
   - **PoC**: GET URL candidate;
   - **Phân tích**: marker STRONG (password/secret key/AKIA/private key/
     phpinfo/actuator `_links`/git index…) mới xuất hiện so với baseline →
     0.90 → verified.
2. **Diễn giải kết quả**:
   - `verified` — disclosure thật, kèm markers trúng trong `detail`;
   - `rejected`, đọc `patterns`:
     - `weak_disclosure_only` — chỉ stack trace/debug message → xem tay;
     - `endpoint_missing` — 403/404, endpoint đã đóng hoặc tool output cũ;
     - `no_sensitive_content` — response không có marker nhạy cảm;
     - `no_diff` / `waf_block` / `probe_error` — không phải verdict kỹ thuật.
3. **Báo cáo**: verdict, evidence path, markers trúng. CẢNH BÁO payload thật
   (key/token) — che bớt khi report.

## Rào cấm

- KHÔNG chạy request trực tiếp — mọi probe qua tool sandbox.
- KHÔNG report khi chỉ có `weak_disclosure_only` — cần người dùng quyết.
- KHÔNG dùng tool cho class khác 7 lớp HTTP-only (tool tự từ chối).

## Kiểm chứng

- evidence chứa baseline (root) + PoC (endpoint) + markers + pattern log.
- `status` Candidate đổi thành `verified`/`rejected` tương ứng.
