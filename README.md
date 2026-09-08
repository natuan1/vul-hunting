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
