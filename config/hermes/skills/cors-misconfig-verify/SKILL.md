---
name: cors-misconfig-verify
description: Xác minh agentic Candidate class "cors" (CORS misconfig) của
  vul-hunting — probe Origin canary qua sandbox + baseline diff + confidence
  score. Dùng khi cần xác minh một Candidate CORS trước khi report.
---

# CORS misconfig verify (batch A — ticket #15)

Mục tiêu: biến Candidate class `cors` thành **Finding** (`verified`) khi server
ECHO origin canary VÀ cho credentials, hoặc **rejected** khi false positive.
Mọi request chạy TRONG sandbox qua MCP tool.

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate CORS #N".
- Có Candidate `class: cors` status `new` sau Detection Phase.

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_http_class`** với
   `{"candidate_id": <id>}` (tuỳ chọn `"payload": "<origin canary của bạn>"`).
   Tool đi trọn vòng:
   - **Baseline**: GET target không kèm Origin;
   - **PoC**: GET target với `Origin: <canary>`;
   - **Phân tích so baseline**: chỉ verified khi `access-control-allow-origin`
     ECHO đúng origin canary + `access-control-allow-credentials: true`
     (score 0.95); echo nhưng không credentials → 0.60 (dưới ngưỡng 0.85).
2. **Diễn giải kết quả**:
   - `verified` — Finding thật, kèm evidence + session ids;
   - `rejected`, đọc `patterns`:
     - `wildcard_only` — ACAO `*`: trình duyệt chặn credentials, vô hại;
     - `origin_not_reflected` — server không echo origin canary;
     - `no_diff` — response giống hệt baseline;
     - `waf_block` / `probe_error` — không phải verdict kỹ thuật.
3. **Báo cáo**: verdict, score/ngưỡng, reason, evidence path.

## Rào cấm

- KHÔNG chạy curl/request trực tiếp — mọi probe qua tool sandbox.
- KHÔNG report CORS chỉ vì ACAO `*` — đó là `wildcard_only`, rejected.
- KHÔNG dùng tool cho class khác 7 lớp HTTP-only (tool tự từ chối).

## Kiểm chứng

- evidence (`evidence_path`) chứa baseline + PoC + diff (ACAO/ACAC) + pattern.
- `status` Candidate đổi thành `verified`/`rejected` tương ứng.
