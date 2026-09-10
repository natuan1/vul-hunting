---
name: exposed-secrets-verify
description: Xác minh agentic Candidate class "secret" của vul-hunting (batch
  B, ticket #16) — sandbox quét lại URL với trufflehog, đối chiếu detector +
  prefix với detection. Evidence KHÔNG bao giờ chứa key đầy đủ. Dùng khi cần
  xác minh một Candidate exposed secrets trước khi report.
---

# Exposed secrets verify (batch B — ticket #16)

Mục tiêu: xác nhận secret đã phát hiện (verify-key PASSED ở Detection Phase với
`trufflehog --only-verified`) **VẪN còn được phục vụ** tại URL hiện nay —
URL lịch sử từ Wayback/Common Crawl có thể đã chết. Vẫn còn → Finding; đã bị
xoá/đổi → rejected. **Evidence chỉ chứa prefix của key (4 ký tự đầu + "…"),
KHÔNG bao giờ chứa key đầy đủ.**

## Profile an toàn

- Detection: tool `trufflehog-urls` (tooling image) quét nội dung URL nhạy cảm
  (.env, bucket, JS bundle, backup files) với `--results=verified` — CHỈ secret
  verify-key với provider thành công mới thành Candidate (severity `high`);
  fetch pacing ≥ 1 req/s theo rate limit của Run + header định danh.
- Verify: rescan trong sandbox với `--no-verification` (egress proxy của
  sandbox chỉ cho target trong Scope — provider API là host ngoài Scope);
  kết quả được MASK (prefix only) + fingerprint sha256 trước khi rời container.

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate secret #N".
- Có Candidate `class: secret` status `new` (từ trufflehog-urls).

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_secret`** với `{"candidate_id": <id>}`.
   Tool đi trọn vòng:
   - **Baseline**: fetch URL, chỉ ghi status/headers/body-length — KHÔNG thu
     body (tránh đưa secret vào evidence);
   - **Rescan**: fetch URL trong sandbox + trufflehog quét nội dung;
   - **Đối chiếu**: detector + fingerprint khớp detection →
     `secret_still_exposed` (score 0.95) → verified.
2. **Diễn giải kết quả**:
   - `verified` — secret vẫn còn expose, kèm evidence (đã mask);
   - `rejected`, đọc `patterns`:
     - `no_longer_exposed` — URL chết hoặc secret đã bị xoá → KHÔNG report
       (report secret đã vá bị đóng N/A và ảnh hưởng reput);
     - `secret_changed` — URL còn serve secret NHƯNG khác secret đã detect
       (detector/fingerprint lệch — key có thể đã rotate) → không báo trên
       secret cũ (có thể tạo Candidate mới từ evidence nếu cần);
     - `waf_block` / `probe_error` / `no_detection_reference` — không phải
       verdict kỹ thuật.
3. **Báo cáo**: verdict, detector + prefix (KHÔNG key đầy đủ), URL, evidence
   path. Nêu rõ "key đã được che trong evidence" — người dùng cần key đầy đủ
   thì tự xem tại nguồn (URL) với quyền của mình.

## Rào cấm

- KHÔNG chạy curl/trufflehog trực tiếp — mọi thứ qua tool sandbox.
- KHÔNG dán key nguyên bản vào report/chat/log — chỉ dùng prefix đã che.
- KHÔNG tự thử key bằng cách gọi API provider trong terminal — verify-key đã
  làm ở Detection Phase; sandbox cũng không cho phép (egress proxy).
- KHÔNG dùng tool cho class khác `secret` (tool tự từ chối).

## Kiểm chứng

- evidence (`evidence_path`) chứa baseline (không body) + rescan (đã mask) +
  đối chiếu detector/prefix; `grep` key đầy đủ trong file phải rỗng.
- `status` Candidate đổi thành `verified`/`rejected` tương ứng.
