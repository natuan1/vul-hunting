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

### AI

**Hermes Agent**:
Thành phần AI của ứng dụng, chạy trên framework hermes-agent của Nous Research — điều phối công cụ CLI và phân tích kết quả.
_Avoid_: AI (đơn thuần), bot, assistant
