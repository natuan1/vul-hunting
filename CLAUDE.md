# vul-hunting

Ứng dụng cá nhân hỗ trợ bug bounty hunting: thu thập chương trình từ HackerOne/Intigriti,
recon & kiểm thử tự động, xác thực lỗ hổng bằng AI agent, và gửi report.

## Agent skills

### Issue tracker

Issues được track trên GitHub Issues của repo `natuan1/vul-hunting`, thao tác qua `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Bộ nhãn triage tiếng Việt, ánh xạ 5 vai trò chuẩn (kèm nhãn phụ `Bug`, `Hotfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` ở repo root. See `docs/agents/domain.md`.
