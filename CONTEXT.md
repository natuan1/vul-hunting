# Vul Hunting

Ứng dụng cá nhân hỗ trợ bug bounty hunting: thu thập Program từ các platform, chạy recon
& kiểm thử tự động, xác minh lỗ hổng bằng Hermes Agent, và sinh report để gửi platform.

## Language

### Sourcing

**Platform**:
Nền tảng bug bounty là nguồn dữ liệu Program — hiện là HackerOne hoặc Intigriti.
_Avoid_: marketplace, site, source

**Program**:
Một chương trình bug bounty công khai trên một Platform, gồm Scope, chính sách và bảng thưởng.
_Avoid_: project, target, bug bounty

**Asset**:
Tài nguyên cụ thể nằm trong Scope của một Program — domain, wildcard domain, API host, hay ứng dụng web.
_Avoid_: scope item, endpoint, host

**Scope**:
Tập hợp Asset mà Program cho phép kiểm thử, kèm giới hạn loại và điều kiện.
_Avoid_: whitelist, targets list

### Safety

**Scope Validator**:
Thành phần chặn cứng (hard block) mọi hành động kiểm thử nhắm vào Asset không thuộc Scope của Program đang chạy.
_Avoid_: safety check, guard, filter

**Guardrails**:
Lớp phân loại lỗi TRƯỚC rồi phản ứng SAU cho mọi Tool Execution (module `app/guardrails.py`): rate limit → backoff luỹ thừa x2 trần 1 giờ; ban signal (CAPTCHA, chuỗi 401/403 liên tiếp) → HALT Run; auth error → retry tối đa 3; timeout → kéo dài timeout + giảm parallelism; asset ngoài Scope → blacklist. Cũng là tên cap đồng thời (`GUARDRAIL_MAX_CONCURRENT`, mặc định 4) chặn tổng Tool Execution + Verify Session đang chạy.
_Avoid_: retry logic, error handler, guard (đè nhầm Scope Validator)

**HALT**:
Trạng thái `halted` của Run khi Guardrails thấy tín hiệu bị cấm — Run dừng TOÀN BỘ, UI cảnh báo đỏ, KHÔNG auto-resume (job không retry, job reclaim cũng không tự chạy lại).
_Avoid_: paused, stopped, cancel

**Resume**:
Hành động bấm tay DUY NHẤT đưa Run khỏi HALT về `pending` và xếp hàng lại (`POST /runs/{id}/resume`).
_Avoid_: restart, retry, continue

**Asset Blacklist**:
Danh sách asset bị cấm vĩnh viễn theo Program (`asset_blacklist`) — target bị Scope Validator chặn vì NGOÀI Scope được đưa vào đây để các Run sau chặn NGAY từ validate. Gỡ là thao tác tay của người dùng (scope mở rộng là quyết định con người).
_Avoid_: denylist, ban list

### Hunting

**Run**:
Một lần quét một Program, gồm Recon Phase (pipeline cứng) và Detection Phase (agentic).
_Avoid_: scan, job, session

**Recon Phase**:
Phần đầu của một Run, chạy chuỗi công cụ cố định để thu thập bề mặt tấn công của Program.
_Avoid_: discovery, enumeration

**Detection Phase**:
Phần sau của một Run, nơi Hermes Agent chủ động phân tích artifact của Recon Phase và sinh Candidate.
_Avoid_: testing, exploitation

**Tool Execution**:
Một lần chạy một công cụ CLI bên trong một Run, giữ lại stdout/stderr JSONL, exit code và thời gian.
_Avoid_: task, step

**Candidate**:
Nghi vấn lỗ hổng do tool hoặc Hermes Agent đánh dấu, chưa qua xác minh.
_Avoid_: mẫu thử, sample, finding (khi chưa verified)

**Finding**:
Candidate đã được xác minh trong sandbox và kết luận là lỗ hổng thật.
_Avoid_: issue, bug, vuln (khi mơ hồ)

**Evidence**:
Bằng chứng gắn với một Candidate hoặc Finding — request/response, screenshot, OOB callback, log thực thi.
_Avoid_: proof, sample, artifact (dùng chung chung)

**Verify Session**:
Một lần gọi `run_in_sandbox` — ứng với một container ephemeral, một egress log và một dòng
trong `sandbox_sessions`; đơn vị truy vấn bằng chứng verify (theo `session_id`).
_Avoid_: session (đơn thuần), sandbox run

**Confidence Score**:
Điểm 0.0–1.0 do vòng xác minh chấm dựa trên response diff của PoC so với baseline; đạt
ngưỡng (mặc định 0.85, cấu hình qua `VERIFY_CONFIDENCE_THRESHOLD`) thì Candidate thành
Finding, dưới ngưỡng thì rejected kèm lý do và pattern log.
_Avoid_: điểm tin cậy (dài), probability

**Verify Evidence**:
File JSON của một vòng xác minh — baseline (request vô hại) + PoC + diff so baseline +
pattern log; đường dẫn nằm trong `candidates.verify_evidence_path`, xem qua
`GET /candidates/{id}/verify-evidence`.
_Avoid_: proof (dùng chung chung), log verify

**OOB Callback**:
Tương tác từ Internet (DNS/HTTP/SMTP...) về interactsh — bằng chứng quyết định của các
lỗ hổng blind; gồm source, protocol, timestamp và raw interaction, gắn vào Candidate
qua token nhúng trong subdomain payload, xem qua `GET /candidates/{id}/oob`.
_Avoid_: pingback, callback (đơn thuần), hit

**OOB Registration**:
Đăng ký interactsh RIÊNG cho một Run — domain payload xoay vòng theo Run, không tái sử
dụng chéo; có TTL (hết hạn → deregister sạch sẽ), persist trong DB để poll tiếp qua
worker restart.
_Avoid_: collaborator session, interactsh session

**Subdomain Takeover**:
Lớp lỗ hổng phát hiện từ CNAME treo (dnsx ở Recon 1) — subdomain trỏ tới service bỏ
hoang claim được (GitHub Pages, S3, Heroku…). Verify PHẢI chứng minh kiểm soát: PoC
page chứa username định danh được phục vụ qua subdomain; fingerprint match thiếu PoC
hoạt động bị platform đóng N/A.
_Avoid_: cname hijack, dangling dns

**PoC Page**:
Trang tĩnh do worker soạn — chứa username định danh của user + token one-shot, deploy
lên hosting khả dụng (TAKEOVER_HOSTING: GitHub Pages/S3) để chứng minh kiểm soát
subdomain; là bằng chứng bắt buộc của Finding takeover.
_Avoid_: proof page, canary page

**Needs Manual**:
Trạng thái lifecycle của Candidate (cùng `new/verifying/verified/rejected`) — vòng
verify dừng chờ người dùng xác minh tay (vd takeover match fingerprint nhưng chưa cấu
hình hosting deploy PoC), kèm hướng dẫn trong evidence; không phải verdict.
_Avoid_: pending, skipped, unverified

**Informational**:
Thuộc tính của một số lớp Candidate (hiện là `headers` — missing security headers) chỉ
hiển thị để tham khảo: verify chỉ thu thập Evidence (headers thiếu) + ép severity trần
`low`, KHÔNG bao giờ đổi status/verdict — không bao giờ tự thành Finding hay report.
_Avoid_: false positive (khác — rejected là verdict), noise

**HTTP-only Classes**:
Bảy lớp lỗ hổng của catalog batch A — `cors` (CORS misconfig), `dirlist` (directory
listing), `graphql` (introspection), `crlf` (CRLF injection), `ssti`, `headers`
(missing security headers), `disclosure` (info disclosure/debug endpoints); mỗi lớp có
detection (nuclei templates + graphql-cop/graphw00f/crlfuzz/SSTImap cho 3 lớp chuyên
dụng) và một verify skill riêng xác minh bằng confirm tool output + baseline diff.
_Avoid_: catalog classes (dài), web classes

### AI

**Hermes Agent**:
Thành phần AI của ứng dụng, chạy trên framework hermes-agent của Nous Research — điều phối công cụ CLI và phân tích kết quả.
_Avoid_: AI (đơn thuần), bot, assistant
