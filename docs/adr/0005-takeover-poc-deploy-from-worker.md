# PoC page của takeover deploy từ worker, chỉ confirm chạm target qua sandbox

Ticket #14 viết "deploy qua hosting khả dụng **trong sandbox**". Diễn giải theo chữ —
chạy deploy từ trong container sandbox — sẽ phá mô hình an toàn đã dựng: container
sandbox chỉ được nói chuyện với target (egress proxy chặn mọi destination ngoài Scope
snapshot, ADR-0003), mà GitHub API/S3 endpoint lại chính xác là destination NGOÀI
Scope. Mở ngoại lệ egress cho provider hosting đồng nghĩa mở luồng ra Internet không đối
chiếu Scope từ chính payload container — đắt hơn lợi ích mang lại.

## Considered options

- **Deploy trong sandbox + mở ngoại lệ egress cho provider hosting** — đúng chữ ticket nhưng
  phá luật ra ngoài duy nhất của ADR-0003; token GitHub/AWS phải truyền vào payload
  container (mở rộng bề mặt lộ secret), egress log đổ lẫn giữa "chạm target" và "hạ
  tầng của mình".
- **Client deploy trong worker (chọn)** — giống đúng mô hình interactsh client ở
  ADR-0004: deploy PoC page là tương tác với HẠ TẦNG CỦA MÌNH (GitHub Pages/S3), không
  phải với target; token giữ trong worker env, không bao giờ vào container payload.
  Bằng chứng quyết định vẫn phải qua sandbox: fingerprint probe và confirm probe đều
  chạy `run_in_sandbox` — "PoC page được phục vụ QUA SUBDOMAIN" chỉ tin được khi nhìn
  từ container sandbox qua egress proxy có audit.
- **Service compose riêng cho hosting** — thêm bộ phận chuyển động chỉ để giữ token;
  deploy là thao tác ít, không cần process thường trực.

## Consequences

- `configure_hosting`/deployer nằm ở worker (`app/takeover.py`): GitHub Pages REST API
  (tạo repo user-site + `index.html`/`CNAME` + bật Pages) và S3 PutObject SigV4 tự viết
  bằng stdlib (không thêm boto3); test bằng httpx MockTransport, không chạm mạng thật.
- Token (GITHUB_TOKEN / AWS keys) chỉ sống trong worker env; evidence chỉ ghi provider +
  URL + detail, không bao giờ ghi token.
- Account hosting PHẢI trùng nhãn đầu của CNAME (`<label>.github.io`, bucket tên =
  host nạn nhân) — lệch là không kiểm soát được → `rejected claim_failed` (đúng tiêu
  chí "fingerprint match nhưng không kiểm soát được → rejected").
- Chưa cấu hình `TAKEOVER_HOSTING` → vòng verify dừng ở `needs_manual` kèm hướng dẫn
  claim + nội dung PoC page (username + token) — đây là trạng thái lifecycle thứ 5
  (migration 0012), không phải verdict.
