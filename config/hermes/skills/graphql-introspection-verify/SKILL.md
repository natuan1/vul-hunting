---
name: graphql-introspection-verify
description: Xác minh agentic Candidate class "graphql" (introspection) của
  vul-hunting — confirm endpoint là GraphQL qua query vô hại rồi probe __schema
  qua sandbox. Dùng khi cần xác minh một Candidate GraphQL introspection.
---

# GraphQL introspection verify (batch A — ticket #15)

Mục tiêu: xác nhận endpoint THẬT SỰ là GraphQL (baseline `__typename`) VÀ
introspection mở (PoC `__schema` trả data). Chống FP của tool output
(graphql-cop/nuclei) bằng baseline diff. Mọi request chạy TRONG sandbox.

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate GraphQL introspection #N".
- Có Candidate `class: graphql` status `new` (từ graphql-cop hoặc nuclei).

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_http_class`** với `{"candidate_id": <id>}`.
   Tool đi trọn vòng:
   - **Baseline**: POST `{"query":"{ __typename }"}` — phải trả `data` (confirm
     endpoint là GraphQL);
   - **PoC**: POST `{"query":"{ __schema { types { name } } }"}` — phải trả
     `data.__schema` (introspection mở, score 0.95).
2. **Diễn giải kết quả**:
   - `verified` — introspection mở thật, kèm số types trong `detail`;
   - `rejected`, đọc `patterns`:
     - `introspection_disabled` — server trả errors nói rõ introspection tắt;
     - `endpoint_not_graphql` — baseline `__typename` không trả data;
     - `not_graphql` — PoC response không phải JSON;
     - `no_schema` — baseline là GraphQL nhưng `__schema` không trả data;
     - `waf_block` / `probe_error` — không phải verdict kỹ thuật.
3. **Báo cáo**: verdict, evidence path, số types lộ ra.

## Rào cấm

- KHÔNG chạy query trực tiếp — mọi probe qua tool sandbox.
- KHÔNG report introspection khi baseline không xác nhận được endpoint là
  GraphQL (`endpoint_not_graphql`).
- KHÔNG dùng tool cho class khác 7 lớp HTTP-only (tool tự từ chối).

## Kiểm chứng

- evidence chứa cả 2 response JSON + analysis (baseline_graphql/introspection).
- `status` Candidate đổi thành `verified`/`rejected` tương ứng.
