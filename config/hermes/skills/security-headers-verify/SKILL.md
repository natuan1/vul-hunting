---
name: security-headers-verify
description: Thu thập evidence thiếu security headers cho Candidate class
  "headers" của vul-hunting — CHỈ informational: không verdict, không report,
  chỉ hiển thị. Dùng khi cần danh sách headers thiếu của một Candidate.
---

# Security headers — informational (batch A — ticket #15)

Đặc biệt: class `headers` **KHÔNG bao giờ thành Finding/report** — thiếu
security headers chỉ là informational. Verify chỉ thu thập evidence (danh sách
headers thiếu) + ép severity trần `low`; status Candidate GIỮ NGUYÊN. Chỉ hiển
thị cho người dùng tự cân nhắc.

## Khi nào dùng

- Người dùng yêu cầu "xem Candidate thiếu security headers #N thiếu gì".
- Có Candidate `class: headers` status bất kỳ.

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_http_class`** với `{"candidate_id": <id>}`.
   Tool:
   - GET target qua sandbox (baseline = PoC — không có payload);
   - So 6 headers: `content-security-policy`, `strict-transport-security`,
     `x-frame-options`, `x-content-type-options`, `referrer-policy`,
     `permissions-policy`;
   - Ghi evidence (danh sách thiếu/có) + ép severity ≤ `low`.
2. **Diễn giải kết quả**:
   - `verdict: "informational"` — LUÔN vậy, kể cả thiếu hết. `reportable` luôn
     `false`; `detail.missing` là danh sách headers thiếu.
   - KHÔNG có `verified`/`rejected` — status không đổi.
3. **Báo cáo**: chỉ trình bày danh sách headers thiếu + khuyến nghị cấu hình;
   KHÔNG tạo report bug bounty cho class này.

## Rào cấm

- KHÔNG report "missing security header" lên platform — hầu hết chương trình
  coi đây là N/A/informational.
- KHÔNG tự đổi status Candidate class `headers` thành `verified`.
- KHÔNG dùng tool cho class khác 7 lớp HTTP-only (tool tự từ chối).

## Kiểm chứng

- evidence chứa `detail.missing`/`detail.present` + severity đã ép trần `low`.
- `status` Candidate GIỮ NGUYÊN sau khi chạy (không verified/rejected).
