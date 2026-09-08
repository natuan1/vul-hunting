---
name: open-redirect-verify
description: Xác minh agentic Candidate class "redirect" (open redirect) của
  vul-hunting — baseline + PoC qua sandbox + response diff + confidence score.
  Dùng khi cần xác minh/nhận xét một Candidate open redirect trước khi report.
---

# Open redirect verify (vòng xác minh ticket #12)

Mục tiêu: biến **Candidate** class `redirect` thành **Finding** (status
`verified`) khi thật, hoặc **rejected** kèm lý do khi false positive — KHÔNG
bao giờ report sai. Mọi payload chạy TRONG sandbox qua MCP tool, agent không
bao giờ thực thi request trực tiếp.

## Khi nào dùng

- Người dùng/nghiệp vụ yêu cầu "xác minh Candidate open redirect #N".
- Sau Detection Phase, có Candidate `class: redirect` status `new` cần xác minh.

## Quy trình

1. **Nhận Candidate**: cần `candidate_id` (và nếu người dùng cho URL canary
   riêng thì dùng, không thì để tool tự dùng canary mặc định).
2. **Gọi tool MCP `mcp_sandbox_verify_open_redirect`** với
   `{"candidate_id": <id>}` (tuỳ chọn `"payload": "<url canary>"`). Tool đi
   trọn vòng:
   - **Baseline capture**: request vô hại tới target (param = giá trị benign),
     ghi lại status + headers + content-type + body-length;
   - **Soạn PoC**: chèn payload canary vào param của Candidate;
   - **Chạy trong sandbox**: baseline và PoC mỗi cái 1 container ephemeral
     (scope + egress log + rate limit như mọi Tool Execution);
   - **Response diff so baseline**: so sánh PoC với baseline theo HƯỚNG KHAI
     THÁC ĐƯỢC — không phải "payload có xuất hiện trong response?";
   - **Confidence score** 0.0–1.0; ≥ ngưỡng (mặc định 0.85) → `verified`,
     dưới ngưỡng → `rejected`.
3. **Đọc kết quả JSON** và diễn giải ĐÚNG:
   - `verdict: "verified"` → Candidate đã thành Finding. Kèm `score`,
     `signals` (vd `location_redirect`, `meta_refresh`, `js_redirect`),
     `evidence_path` (file JSON chứa baseline + PoC + diff) và session ids.
   - `verdict: "rejected"` → FALSE POSITIVE, KHÔNG được báo thật. Đọc
     `patterns` (pattern log) + `reason`:
     - `waf_block` — response PoC là trang chặn WAF;
     - `payload_escaped` — payload chỉ xuất hiện ở dạng đã encode/escape;
     - `payload_in_error` — payload chỉ nằm trong error log/stack trace;
     - `no_diff` — response giống hệt baseline (target không phản ứng);
     - `body_reflection` — payload chỉ bị reflect thuần, không có cơ chế
       redirect → chưa đủ làm bằng chứng;
     - `probe_error` / `no_param` — không xác minh được (không phải verdict
       kỹ thuật).
4. **Báo cáo**: nêu verdict, score/ngưỡng, reason, pattern log, đường dẫn
   evidence + verify session ids (egress log truy được theo session).

## Rào cấm

- KHÔNG chạy curl/python/payload trực tiếp trong terminal — TOÀN BỘ payload
  phải qua tool sandbox. Target ngoài Scope bị chặn tại bridge.
- KHÔNG tự đổi `verdict` của tool: tool trả `rejected` thì kết luận là false
  positive, kể cả khi bản thân thấy payload xuất hiện trong response (đó là
  điểm mà diff analysis đã loại — WAF page/escape/error log cũng "có payload").
- KHÔNG dùng tool này cho Candidate class khác `redirect` (tool tự từ chối).

## Kiểm chứng

- evidence file (`evidence_path`) chứa đủ baseline + PoC + diff + pattern log
  — đọc được qua `GET /candidates/{id}/verify-evidence`.
- score nằm trong đoạn 0.0–1.0; ngưỡng đang hiệu lực nằm trong `threshold`.
- `status` của Candidate trong DB đã đổi thành `verified`/`rejected` tương ứng.
