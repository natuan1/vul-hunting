---
name: dirlist-verify
description: Xác minh agentic Candidate class "dirlist" (directory listing) của
  vul-hunting — probe lại URL + baseline path con qua sandbox + confidence
  score. Dùng khi cần xác minh một Candidate directory listing trước khi report.
---

# Directory listing verify (batch A — ticket #15)

Mục tiêu: xác nhận chỉ mục thư mục là hành vi THẬT của URL candidate — không
phải server trả listing cho mọi path hay tool output đã cũ. Mọi request chạy
TRONG sandbox.

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate directory listing #N".
- Có Candidate `class: dirlist` status `new`.

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_http_class`** với `{"candidate_id": <id>}`.
   Tool đi trọn vòng:
   - **Baseline**: GET path con không tồn tại (`.vulhunt-baseline`) trong cùng
     thư mục — phải KHÔNG listing;
   - **PoC**: GET URL candidate — phải 2xx + marker listing ("Index of /",
     "Directory listing for", "[To Parent Directory]"…);
   - **Confidence**: listing thật → 0.90 → verified (ngưỡng 0.85).
2. **Diễn giải kết quả**:
   - `verified` — listing xác nhận, kèm evidence (markers trúng);
   - `rejected`, đọc `patterns`:
     - `baseline_also_listing` — mọi path đều listing → không phải listing riêng;
     - `not_a_listing` — response không có marker chỉ mục;
     - `endpoint_missing` — 403/404, listing đã đóng hoặc tool output cũ;
     - `waf_block` / `probe_error` — không phải verdict kỹ thuật.
3. **Báo cáo**: verdict, evidence path, markers trúng.

## Rào cấm

- KHÔNG chạy request trực tiếp — mọi probe qua tool sandbox.
- KHÔNG report khi `baseline_also_listing` — đó là hành vi server, không phải
  thư mục cụ thể.
- KHÔNG dùng tool cho class khác 7 lớp HTTP-only (tool tự từ chối).

## Kiểm chứng

- evidence chứa baseline (path con) + PoC + markers + pattern log.
- `status` Candidate đổi thành `verified`/`rejected` tương ứng.
