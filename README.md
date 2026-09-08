# vul-hunting

Ứng dụng cá nhân hỗ trợ bug bounty hunting: thu thập Program từ HackerOne/Intigriti,
recon & kiểm thử tự động, xác minh lỗ hổng bằng Hermes Agent, và sinh report để gửi platform.

## Chạy nhanh

```bash
cp .env.example .env   # tuỳ chọn — compose có giá trị mặc định
docker compose up -d --build
```

Mở **http://localhost:3001** — trang status hiển thị trạng thái thật của Web / Worker / Postgres / Hermes.

Key API (OpenRouter, HackerOne, Intigriti) đặt trong `.env` — xem `.env.example`.

## Cấu trúc

| Thành phần | Vai trò |
|---|---|
| `apps/web` | Next.js UI (port mặc định 3001) |
| `apps/worker` | FastAPI worker — REST API, sync platforms, job queue consumer |
| `postgres` | Dữ liệu + job queue (ADR-0001) |
| `hermes` | hermes-agent gateway — AI core (ADR-0002), API server nội bộ :8642 |
| `docker/tooling` | Image CLI recon: subfinder/amass/dnsx/naabu/httpx (pin version, có checksum) |
| `config/hermes/` | config.yaml + skills của hermes (mount vào container) |

## Tính năng hiện có

- **Programs** (`/programs`) — sync danh sách program từ HackerOne & Intigriti, filter theo
  platform / bounty / payout tối đa / loại asset / từ khoá (tên, handle, scope), pagination.
  Sync chạy nền, tôn trọng rate limit từng platform, lỗi thì resume từ điểm dừng.
- **Runs** (`/runs`) — recon thật trên program: chuỗi `subfinder → amass → dnsx → naabu →
  httpx` chạy trong container ephemeral từ image `docker/tooling` (worker gọi docker qua
  socket — sibling container). Mọi target đi qua Scope Validator + rate limit + header định
  danh; subdomain/live host/CNAME lưu DB (`recon_assets`) với bộ đếm tăng dần trên UI;
  stdout JSONL của từng tool lưu artifact trên volume (`recon_data:/data/artifacts/<run_id>/`),
  stdout/stderr/exit code/thời gian lưu bảng `tool_executions`.
- **Detection** — nuclei quét bề mặt từ Recon → Candidate kèm evidence JSON
  (`/candidates`, Findings screen trên UI).
- **Verification loop: open redirect** (ticket #12) — xác minh agentic Candidate
  class `redirect`: skill hermes `open-redirect-verify` (mount tại
  `config/hermes/skills/`) hướng dẫn agent gọi MCP tool
  `verify_open_redirect(candidate_id, payload?)` trên worker; tool đi trọn vòng
  **baseline capture** (request vô hại, ghi status/headers/content-type/
  body-length) → **soạn PoC** từ param của Candidate → **chạy cả hai trong
  sandbox** (container ephemeral, scope + egress + rate limit như mọi Tool
  Execution) → **response diff so baseline** theo hướng khai thác được (WAF
  block page / payload bị encode-escape / payload nằm trong error log đều kết
  luận false positive) → **confidence score** 0.0–1.0. Score ≥ ngưỡng
  (`VERIFY_CONFIDENCE_THRESHOLD`, mặc định 0.85) → Candidate thành Finding
  (status `verified`) kèm verify evidence (baseline + PoC + diff + pattern log,
  xem qua `GET /candidates/{id}/verify-evidence`); dưới ngưỡng → `rejected`
  kèm lý do + pattern log. UI Findings hiển thị confidence/lý do loại và nút
  chạy vòng xác minh cho class `redirect`. Payload KHÔNG bao giờ được agent
  thực thi trực tiếp.
- **OOB client: interactsh** (ticket #13, ADR-0004) — client interactsh chạy
  TRONG worker (server public mặc định `oast.*`, không cần key): mỗi Run có
  **registration riêng** — domain payload xoay vòng theo Run, không tái sử
  dụng chéo; registration + key persist trong DB nên worker restart vẫn poll
  tiếp được. Poller nền gắn **OOB callback** (source, protocol, timestamp,
  raw interaction) về đúng Candidate qua token trong subdomain; callback cache
  giữ theo TTL (`OOB_CALLBACK_RETENTION_H`) rồi xoá sạch, registration hết hạn
  (`OOB_REGISTRATION_TTL_H`) được deregister. Vòng xác minh OOB cho Candidate
  blind class `ssrf` (skill hermes `oob-ssrf-verify` + MCP tool
  `verify_oob_ssrf` + nút trên Findings): payload
  `http://<token>.<domain>` chèn vào param chạy qua sandbox → chờ callback
  → callback về = verified kèm evidence OOB, hết cửa sổ chờ = rejected.
  Template nuclei OOB cũng được bật lại (bỏ `-ni`) — nuclei tự register
  riêng từng lần chạy và nhúng interaction vào finding JSON. UI Findings
  hiển thị callback count + chi tiết trên Candidate.

  Giới hạn đã ghi nhận (môi trường): nếu mạng đang dùng có thiết bị can thiệp
  TLS (FortiGate/corporate proxy) ký lại chứng chỉ của `oast.*` bằng CA riêng
  thì worker không verify được HTTPS tới interactsh — register sẽ fail trên
  mọi server. Cách khắc phục: xuất root CA của thiết bị (Fortinet) thành file
  PEM, mount vào container worker và trỏ `SSL_CERT_FILE` (httpx tự dùng) —
  xem `.env.example` phần ticket #13.
- **Sandbox bridge** (ticket #11, ADR-0003) — Hermes Agent gọi MCP tool
  `run_in_sandbox(script, target, timeout)` qua toolset `mcp_servers.sandbox`
  trong `config/hermes/config.yaml`: mỗi lần gọi worker quay một container
  `docker run --rm` MỚI TINH từ tooling image, chạy trong docker network
  `--internal` riêng (không có route ra ngoài). Luật ra ngoài DUY NHẤT là
  egress proxy trong worker: đối chiếu từng destination với Scope (payload
  nhắm ngoài scope bị chặn TẠI BRIDGE — không có request đi ra), tự chèn
  header định danh, giữ nhịp rate limit của Run, và ghi egress log vào DB.
  Timeout được enforce (quá hạn → `docker rm -f`). Verify session + egress
  log truy được qua `/sandbox/sessions`.

  Giới hạn đã ghi nhận: HTTPS đi qua CONNECT tunnel nên egress log ghi **mỗi
  connection** (không đọc được từng request bên trong TLS), header định danh
  do proxy chèn chỉ áp dụng cho HTTP thường — script HTTPS tự thêm qua env
  `IDENT_HEADER_NAME`/`IDENT_HEADER_VALUE`; DNS lookup đi qua resolver của
  host (docker embedded DNS) nên không nằm trong egress log.

## Bảo mật — docker.sock trên worker

Worker mount `/var/run/docker.sock`, tức **worker có quyền Docker = quyền
root trên host**. Rủi ro này được CHẤP NHẬN có chủ đích cho mô hình
local-first (worker cần quay container tooling/sandbox sibling — ADR-0003):
KHÔNG expose worker ra ngoài mạng nội bộ/máy cá nhân, KHÔNG chạy compose này
trên host đa người dùng hoặc có workload quan trọng khác.

## Tài liệu

- [`CONTEXT.md`](./CONTEXT.md) — thuật ngữ domain (glossary)
- [`docs/adr/`](./docs/adr) — các quyết định kiến trúc
- [`docs/agents/`](./docs/agents) — cấu hình cho agent skills (issue tracker, triage labels)
