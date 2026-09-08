# Interactsh OOB client chạy trong worker, không phải service compose riêng

Ticket #13 mô tả "interactsh-client như service trong compose", nhưng một service compose tĩnh chỉ register MỘT lần — trong khi đề bài (và acceptance criteria) yêu cầu **domain xoay vòng per-Run, không tái sử dụng chéo**. Vì vậy worker tự nói giao thức interactsh (register/poll/deregister) trực tiếp với server public mặc định (`oast.*`) bằng Python (httpx + cryptography), giữ state trong Postgres.

## Considered options

- **Service compose tĩnh (`projectdiscovery/interactsh-client`)** — đúng chữ ticket nhưng không register được per-Run: một process client = một registration = một domain; xoay vòng theo Run phải restart service, mất callback đang chờ và không map được callback về đúng Run.
- **Container interactsh-client per-Run qua docker.sock** — giữ đúng "dùng binary chính thức" nhưng thêm nhiều bộ phận chuyển động: vòng đời container (orphan cleanup khi worker chết), transport callback qua file JSONL trên volume, parsing log để lấy domain. Toàn bộ chỉ để thay ~150 dòng protocol code đã ổn định (v1) và có spec rõ.
- **Python client trong worker (chọn)** — register/poll/deregister per-Run trực tiếp; correlation-id + secret + private key persist trong DB nên worker restart vẫn poll tiếp được (callback cache không mất giữa chừng verify dài); hết hạn TTL → deregister + sweep; test thuần với fake client.

## Consequences

- Thêm dependency `cryptography` cho worker và phần protocol code phải theo kịp server (đã đối chiếu trực tiếp mã nguồn Go: register/poll/deregister JSON, RSA-OAEP-SHA256 cho AES key, AES-CTR với IV 16 byte ở đầu, payload `{correlation-id}{nonce}.{host}` 20+13 ký tự).
- Private key RSA dùng một lần (một domain, một TTL) lưu DB — không phải secret dài hạn; server public cũng không có dữ liệu gì ngoài callback của chính domain đó.
- Self-host interactsh (VPS + domain riêng) là v2: chỉ cần đổi `INTERACTSH_SERVER` — khi đó HỎI user về VPS/domain.
