---
name: crlf-verify
description: Xác minh agentic Candidate class "crlf" (CRLF injection) của
  vul-hunting — chèn header canary qua %0d%0a vào param, probe qua sandbox, soi
  response headers. Dùng khi cần xác minh một Candidate CRLF trước khi report.
---

# CRLF injection verify (batch A — ticket #15)

Mục tiêu: chứng minh server PARSE CRLF do người dùng kiểm soát — header canary
phải XUẤT HIỆN trong response headers, không chỉ bị echo trong body. Mọi
payload chạy TRONG sandbox.

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate CRLF #N".
- Có Candidate `class: crlf` status `new` (từ crlfuzz hoặc nuclei).

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_http_class`** với `{"candidate_id": <id>}`
   (tuỳ chọn `"payload": "X-Canary-Custom: 1"`). Tool đi trọn vòng:
   - **Baseline**: param = giá trị benign;
   - **PoC**: param = `%0d%0aX-Vulhunt-Injection: 1` (encode chuẩn URL);
   - **Phân tích**: header canary trong response headers → 0.95 → verified.
2. **Diễn giải kết quả**:
   - `verified` — CRLF thật, kèm evidence diff;
   - `rejected`, đọc `patterns`:
     - `payload_escaped` — payload chỉ bị echo ở dạng encode/escape trong body;
     - `header_not_injected` — header canary không xuất hiện;
     - `no_diff` — param không phản ứng;
     - `waf_block` / `probe_error` / `no_param` — không phải verdict kỹ thuật.
3. **Báo cáo**: verdict, evidence path, header canary trúng.

## Rào cấm

- KHÔNG chạy request trực tiếp — mọi payload qua tool sandbox.
- KHÔNG report khi payload chỉ bị reflect trong body — đó là `payload_escaped`.
- KHÔNG dùng tool cho class khác 7 lớp HTTP-only (tool tự từ chối).

## Kiểm chứng

- evidence chứa baseline + PoC URL (%0D%0A) + response headers + pattern log.
- `status` Candidate đổi thành `verified`/`rejected` tương ứng.
