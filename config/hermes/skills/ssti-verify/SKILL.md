---
name: ssti-verify
description: Xác minh agentic Candidate class "ssti" của vul-hunting — chèn
  {{7*7}} vào param qua sandbox, đòi kết quả `49` VÀ vắng mặt ở baseline. Dùng
  khi cần xác minh một Candidate SSTI trước khi report.
---

# SSTI verify (batch A — ticket #15)

Mục tiêu: chứng minh template engine EVALUATE payload — kết quả phép tính (`49`)
phải xuất hiện trong PoC và KHÔNG có sẵn ở baseline (chống FP "số ở đâu đó").
Mọi payload chạy TRONG sandbox.

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate SSTI #N".
- Có Candidate `class: ssti` status `new` (từ SSTImap hoặc nuclei).

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_http_class`** với `{"candidate_id": <id>}`.
   Tool đi trọn vòng:
   - **Baseline**: param = giá trị benign;
   - **PoC**: param = `{{7*7}}`;
   - **Phân tích**: `49` trong PoC + vắng ở baseline → 0.90 → verified.
2. **Diễn giải kết quả**:
   - `verified` — SSTI thật, kèm evidence diff;
   - `rejected`, đọc `patterns`:
     - `ambiguous_baseline` — `49` có sẵn ở baseline, không phải kết quả payload;
     - `payload_escaped` — payload chỉ bị reflect nguyên văn;
     - `no_diff` / `waf_block` / `probe_error` / `no_param` — không phải
       verdict kỹ thuật.
3. **Báo cáo**: verdict, evidence path.

## Rào cấm

- KHÔNG chạy payload trực tiếp — mọi thứ qua tool sandbox.
- KHÔNG dùng payload destructive (rce thật) ở bước verify — `{{7*7}}` đủ chứng
  minh; escalate chỉ khi người dùng yêu cầu rõ ràng.
- KHÔNG dùng tool cho class khác 7 lớp HTTP-only (tool tự từ chối).

## Kiểm chứng

- evidence chứa baseline + PoC + pattern log; `49` phải vắng ở baseline.
- `status` Candidate đổi thành `verified`/`rejected` tương ứng.
