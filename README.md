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
| `config/hermes/` | config.yaml + skills của hermes (mount vào container) |

## Tính năng hiện có

- **Programs** (`/programs`) — sync danh sách program từ HackerOne & Intigriti, filter theo
  platform / bounty / payout tối đa / loại asset / từ khoá (tên, handle, scope), pagination.
  Sync chạy nền, tôn trọng rate limit từng platform, lỗi thì resume từ điểm dừng.

## Tài liệu

- [`CONTEXT.md`](./CONTEXT.md) — thuật ngữ domain (glossary)
- [`docs/adr/`](./docs/adr) — các quyết định kiến trúc
- [`docs/agents/`](./docs/agents) — cấu hình cho agent skills (issue tracker, triage labels)
