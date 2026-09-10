---
name: sqli-verify
description: Xác minh agentic Candidate class "sqli" của vul-hunting (batch B,
  ticket #16) — sqlmap CHỈ chạy trong sandbox với profile an toàn mức thấp
  (error/boolean, level 1 risk 1, delay ≥ 1 req/s), KHÔNG dump dữ liệu, KHÔNG
  đọc file. Dùng khi cần xác minh một Candidate SQLi trước khi report.
---

# SQLi verify (batch B — ticket #16)

Mục tiêu: chứng minh **injection được** — sqlmap xác nhận injection point với
kỹ thuật error-based/boolean. PoC = injection point + payload, KHÔNG phải dữ
liệu chiếm được. Mọi request của sqlmap chạy TRONG sandbox bridge (egress proxy
chặn theo Scope + rate limit của Run).

## Profile an toàn (bắt buộc — tool tự áp, KHÔNG được đổi)

| Tham số | Giá trị | Lý do |
|---|---|---|
| `--technique` | `BE` | error-based + boolean blind DUY NHẤT — không time-based nặng, không UNION/stacked |
| `--level` | `1` | mức khuếch tán thấp nhất |
| `--risk` | `1` | risk thấp nhất (không OR/heavy payload) |
| `--threads` | `1` | tuần tự — không dồn dập target |
| `--delay` | ≥ `1` (giây) | rate limit nghiêm ngặt: không nhanh hơn 1 req/s; Run chậm hơn thì delay = 1/rps |
| `--batch` | có | không tương tác |
| `--flush-session` | có | session sạch mỗi lần chạy |

TUYỆT ĐỐI KHÔNG: `--dump`/`--dump-all` (dump dữ liệu), `--file-read`/
`--file-write` (đọc/ghi file hệ thống), `--os-shell`/`--os-pwn`, time-based.
Vi phạm "minimum testing necessary" + rules chống pivot/PII của các Program.

## Stop-condition

Output sqlmap có dấu hiệu dump/đọc file/kỹ thuật ngoài profile (`fetching
entries`, `--dump`, `reading file`, `Type: time-based blind`, …) → guardrails
**HALT Run** + cảnh báo, KHÔNG tiếp tục — Candidate trả lifecycle về cũ, người
dùng bấm Resume sau khi xem xét. Dương tính giả hướng AN TOÀN (halt nhầm chỉ
là phiền, lọt là pivot/PII thật).

## Khi nào dùng

- Người dùng yêu cầu "xác minh Candidate SQLi #N".
- Có Candidate `class: sqli` status `new` (từ nuclei tags/gf classed URLs).

## Quy trình

1. **Gọi tool MCP `mcp_sandbox_verify_sqli`** với `{"candidate_id": <id>}`.
   Tool đi trọn vòng:
   - **Baseline**: GET target — WAF chặn (403/406/CAPTCHA…) → rejected ngay,
     sqlmap KHÔNG chạy (không lãng phí request);
   - **sqlmap trong sandbox**: profile an toàn ở trên, test đúng param của
     Candidate;
   - **Stop-condition**: scan output — có dấu hiệu dump/đọc file → HALT;
   - **Verdict**: injection point xác nhận → `verified` (score 0.95);
     "all tested parameters do not appear to be injectable" → `rejected`.
2. **Diễn giải kết quả**:
   - `verified` — SQLi thật, kèm injection point + payload + DBMS (KHÔNG dữ
     liệu); severity report theo impact khai thác được, KHÔNG claim dump/RCE;
   - `rejected`, đọc `patterns`:
     - `not_injectable` — không injectable với profile an toàn → KHÔNG report;
     - `waf_block` / `probe_error` / `no_param` / `no_confirmation` — không
       phải verdict kỹ thuật.
   - Status `error` kèm `GUARDRAIL HALT` — stop-condition đã kích hoạt, KHÔNG
     chạy lại tool; báo người dùng.
3. **Báo cáo**: verdict, parameter + technique, evidence path. KHÔNG dán dữ
   liệu DB (không có trong evidence vì profile cấm dump).

## Rào cấm

- KHÔNG chạy sqlmap trực tiếp trong terminal hay ngoài sandbox — tool là lối
  duy nhất, profile an toàn được áp cứng.
- KHÔNG thêm flag dump/đọc file/os-shell dù target trông "an toàn" — quyết
  định escalate là của người dùng.
- KHÔNG dùng tool cho class khác `sqli` (tool tự từ chối).

## Kiểm chứng

- evidence chứa baseline + injection point + profile an toàn + `violations: []`
  (trống = stop-condition sạch).
- `status` Candidate đổi thành `verified`/`rejected`; nếu HALT thì Run ở
  trạng thái `halted` chờ Resume.
