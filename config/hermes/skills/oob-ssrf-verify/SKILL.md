---
name: oob-ssrf-verify
description: Xác minh agentic Candidate blind class "ssrf" của vul-hunting bằng
  OOB callback qua interactsh — payload per-Run + chờ callback + evidence.
  Dùng khi cần xác minh một Candidate SSRF/blind trước khi report.
---

# OOB verify — blind SSRF (ticket #13)

Mục tiêu: biến **Candidate** class `ssrf` thành **Finding** (status
`verified`) khi target thật sự fetch payload ra Internet, hoặc **rejected**
kèm lý do khi không có bằng chứng — KHÔNG bao giờ report sai. Blind class
không tự báo bằng response: bằng chứng quyết định là **OOB callback** về
interactsh. Mọi request tới target chạy TRONG sandbox qua MCP tool, agent
không bao giờ thực thi trực tiếp.

## Khi nào dùng

- Người dùng/nghiệp vụ yêu cầu "xác minh Candidate SSRF #N".
- Sau Detection Phase, có Candidate `class: ssrf` status `new` cần xác minh.

## Quy trình

1. **Nhận Candidate**: cần `candidate_id`.
2. **Gọi tool MCP `mcp_sandbox_verify_oob_ssrf`** với `{"candidate_id": <id>}`.
   Tool đi trọn vòng:
   - **Register per-Run**: đảm bảo Run có registration interactsh riêng —
     domain payload xoay vòng THEO RUN, không tái sử dụng chéo giữa các Run;
   - **Soạn payload**: `http://<token>.<domain>` với token nhúng candidate id,
     chèn vào param của Candidate;
   - **Chạy trong sandbox**: baseline (request vô hại) và PoC mỗi cái 1
     container ephemeral (scope + egress log + rate limit như mọi Tool
     Execution) — target có thể fetch payload bằng server-side;
   - **Chờ + poll callback** trong cửa sổ chờ (mặc định ~60s): callback từ
     Internet về interactsh được map về Candidate qua token;
   - **Verdict**: có callback → `verified` (score 0.95); hết cửa sổ không
     callback → `rejected` (`no_oob_callback`).
3. **Đọc kết quả JSON** và diễn giải ĐÚNG:
   - `verdict: "verified"` → Candidate đã thành Finding. Kèm `callbacks`
     (source, protocol, timestamp, raw interaction), `payload`, `token`,
     `domain` (của Run) và `evidence_path`.
   - `verdict: "rejected"` → KHÔNG đủ bằng chứng, KHÔNG được báo thật. Đọc
     `patterns` + `reason`:
     - `no_oob_callback` — target không fetch payload trong cửa sổ chờ (có
       thể vẫn blind thật nhưng không xác nhận được → không report);
     - `probe_error` — không đọc được profile response từ sandbox (không phải
       verdict kỹ thuật);
     - `no_param` — Candidate không có param để chèn payload.
4. **Báo cáo**: nêu verdict, score/ngưỡng, reason, số callback + nguồn
   (source IP/protocol), đường dẫn evidence và domain payload của Run.

## Rào cấm

- KHÔNG chạy curl/python/payload trực tiếp trong terminal — TOÀN BỘ payload
  phải qua tool sandbox. Target ngoài Scope bị chặn tại bridge.
- KHÔNG tự đổi `verdict` của tool: tool trả `rejected` thì kết luận là
  KHÔNG đủ bằng chứng, kể cả khi response trông đáng ngờ — blind chỉ được
  xác nhận bằng callback.
- KHÔNG dùng tool này cho Candidate class khác `ssrf` (tool tự từ chối).
- KHÔNG tái sử dụng domain payload của Run khác — mỗi Run có registration
  riêng, tool tự đảm bảo điều này.

## Kiểm chứng

- evidence file (`evidence_path`) chứa callbacks (source, protocol,
  timestamp, raw interaction) + baseline/PoC + phân tích — đọc được qua
  `GET /candidates/{id}/oob-evidence`.
- callback count + chi tiết xem được qua `GET /candidates/{id}/oob` và trên
  UI Findings (Candidate detail).
- `status` của Candidate trong DB đã đổi thành `verified`/`rejected`.
