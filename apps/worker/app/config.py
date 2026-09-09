import os


class Settings:
    database_url: str = os.environ["DATABASE_URL"]

    # username platform để dựng header định danh mặc định cho Run (ticket #6) —
    # không phải secret nhưng vẫn để env, không hardcode
    hackerone_username: str = os.environ.get("HACKERONE_USERNAME", "")
    intigriti_username: str = os.environ.get("INTIGRITI_USERNAME", "")

    # tooling image + thực thi tool (ticket #8): worker gọi docker CLI qua
    # docker.sock mount để chạy container ephemeral từ image này
    tooling_image: str = os.environ.get("TOOLING_IMAGE", "vulhunt-tooling:latest")
    docker_bin: str = os.environ.get("DOCKER_BIN", "docker")
    tool_timeout_s: float = float(os.environ.get("TOOL_TIMEOUT_S", "900"))

    # artifact JSONL lưu filesystem (docker volume recon_data mount tại /data)
    artifacts_dir: str = os.environ.get("ARTIFACTS_DIR", "/data/artifacts")

    # tên volume chứa artifacts nhìn từ phía docker daemon — để amass v5 ghi
    # output file vào đúng nơi worker đọc lại (sibling container mount theo tên).
    # Rỗng = không mount, amass chỉ harvest từ stdout.
    recon_volume: str = os.environ.get("RECON_VOLUME", "")

    # (ticket #9, tuỳ chọn) AlienVault OTX — truyền vào container waymore khi có.
    # Không có key vẫn chạy được: gau/waymore lấy được URL lịch sử từ
    # Common Crawl + Wayback (OTX endpoint công khai dùng keyless).
    otx_api_key: str = os.environ.get("OTX_API_KEY", "")

    # evidence file JSON của Candidate (ticket #10) — TÁCH KHỎI artifacts_dir vì
    # artifacts bị xoá mỗi attempt còn evidence phải sống qua retry
    evidence_dir: str = os.environ.get("EVIDENCE_DIR", "/data/evidence")

    # nuclei (ticket #10): templates baked sẵn trong tooling image (không tải
    # lúc chạy); cap số target mỗi Run để giữ nhịp "điều độ"
    nuclei_templates_dir: str = os.environ.get(
        "NUCLEI_TEMPLATES_DIR", "/home/tooler/nuclei-templates"
    )
    detection_max_targets: int = int(os.environ.get("DETECTION_MAX_TARGETS", "300"))

    # ── sandbox bridge (ticket #11, ADR-0003) ──
    # key bearer của MCP endpoint /mcp — hermes gửi theo config mcp_servers.
    # Rỗng = fail-closed (endpoint từ chối mọi call).
    sandbox_mcp_key: str = os.environ.get("SANDBOX_MCP_KEY", "")
    # địa chỉ egress proxy NHÌN TỪ container sandbox (alias của worker trên
    # network --internal của từng session) + port proxy lắng nghe trong worker
    sandbox_proxy_host: str = os.environ.get("SANDBOX_PROXY_HOST", "sbx-proxy")
    sandbox_proxy_port: int = int(os.environ.get("SANDBOX_PROXY_PORT", "8765"))
    # timeout script: mặc định + cap tuyệt đối (container không sống quá hạn này)
    sandbox_default_timeout_s: float = float(os.environ.get("SANDBOX_DEFAULT_TIMEOUT_S", "120"))
    sandbox_max_timeout_s: float = float(os.environ.get("SANDBOX_MAX_TIMEOUT_S", "600"))
    # tên container worker (compose container_name) — để `docker network connect`
    # gắn worker vào network internal của session, egress proxy với tới được
    worker_container_name: str = os.environ.get("WORKER_CONTAINER_NAME", "vulhunt-worker")

    # ── vòng xác minh (ticket #12) ──
    # ngưỡng confidence: score ≥ ngưỡng → Candidate thành Finding (verified);
    # dưới ngưỡng → rejected kèm lý do + pattern log
    verify_confidence_threshold: float = float(
        os.environ.get("VERIFY_CONFIDENCE_THRESHOLD", "0.85")
    )
    # URL canary mặc định làm payload PoC open redirect (khi không chỉ định)
    verify_canary_url: str = os.environ.get(
        "VERIFY_CANARY_URL", "https://canary.example/vulhunt-poc"
    )
    # Origin "kẻ tấn công" cho verify CORS misconfig (batch A #15) — origin
    # canary của bạn, target KHÔNG được phép reflect + cho credentials
    verify_cors_origin: str = os.environ.get(
        "VERIFY_CORS_ORIGIN", "https://canary-vulhunt.example"
    )

    # ── interactsh OOB (ticket #13, ADR-0004) ──
    # server public mặc định của interactsh (phân tách phẩy, worker chọn ngẫu
    # nhiên 1 cái lúc register; https lỗi thì fallback http) — self-host là v2
    interactsh_server: str = os.environ.get(
        "INTERACTSH_SERVER",
        "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
    )
    # nhịp poll nền của worker (poller gắn callback vào Candidate chờ verify)
    oob_poll_interval_s: float = float(os.environ.get("OOB_POLL_INTERVAL_S", "5"))
    # registration sống bao lâu (giờ) — đủ dài cho verify class blind kéo dài;
    # hết hạn → deregister khỏi server + status 'expired' (sạch sẽ)
    oob_registration_ttl_h: float = float(os.environ.get("OOB_REGISTRATION_TTL_H", "24"))
    # callback cache giữ bao lâu (giờ) trước khi xoá khỏi DB
    oob_callback_retention_h: float = float(
        os.environ.get("OOB_CALLBACK_RETENTION_H", "168")
    )
    # cửa sổ chờ callback trong vòng xác minh OOB (blind) + nhịp poll từng lượt
    oob_verify_wait_s: float = float(os.environ.get("OOB_VERIFY_WAIT_S", "60"))
    oob_verify_poll_s: float = float(os.environ.get("OOB_VERIFY_POLL_S", "5"))

    # ── subdomain takeover (ticket #14) ──
    # hosting chứng minh kiểm soát cho PoC page: '' (không — verify dừng ở
    # "fingerprint match, cần xác minh tay") | 'github-pages' | 's3'
    takeover_hosting: str = os.environ.get("TAKEOVER_HOSTING", "")
    # GitHub Pages: token + account PHẢI trùng nhãn đầu của CNAME (*.github.io)
    github_token: str = os.environ.get("GITHUB_TOKEN", "")
    github_username: str = os.environ.get("GITHUB_USERNAME", "")
    # S3: bucket claim tạo qua PutObject SigV4 (region mặc định us-east-1)
    aws_access_key_id: str = os.environ.get("AWS_ACCESS_KEY_ID", "")
    aws_secret_access_key: str = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    aws_region: str = os.environ.get("AWS_REGION", "us-east-1")
    # cửa sổ chờ PoC page được phục vụ qua subdomain sau deploy (propagation)
    # + nhịp confirm probe từng lượt
    takeover_verify_wait_s: float = float(os.environ.get("TAKEOVER_VERIFY_WAIT_S", "120"))
    takeover_verify_poll_s: float = float(os.environ.get("TAKEOVER_VERIFY_POLL_S", "10"))

    # ── guardrails (ticket #19): phân loại lỗi TRƯỚC, phản ứng SAU ──
    # cap Tool Execution đồng thời (chống WAF ban) — cũng là số consumer queue
    # song song (mỗi consumer 1 Run; cap bên trong vẫn giữ nếu consumer nhiều hơn)
    guardrail_max_concurrent: int = int(os.environ.get("GUARDRAIL_MAX_CONCURRENT", "4"))
    # rate limit: backoff luỹ thừa x2 — mốc đầu + trần 1 giờ
    guardrail_backoff_base_s: float = float(os.environ.get("GUARDRAIL_BACKOFF_BASE_S", "30"))
    guardrail_backoff_cap_s: float = float(os.environ.get("GUARDRAIL_BACKOFF_CAP_S", "3600"))
    # sau N lần backoff không hết rate limit thì thôi (ghi nhận, Run vẫn chạy tiếp)
    guardrail_rate_limit_max_retries: int = int(
        os.environ.get("GUARDRAIL_RATE_LIMIT_MAX_RETRIES", "5")
    )
    # auth error: retry tối đa 3 (nhắc refresh credential/header định danh)
    guardrail_auth_max_retries: int = int(os.environ.get("GUARDRAIL_AUTH_MAX_RETRIES", "3"))
    # chuỗi 401/403 liên tiếp đủ dài → coi là tín hiệu bị cấm, HALT Run
    guardrail_ban_consecutive: int = int(os.environ.get("GUARDRAIL_BAN_CONSECUTIVE", "5"))
    # timeout: kéo dài timeout x2 (trần) + giảm parallelism, tối đa N lần retry
    guardrail_timeout_max_s: float = float(os.environ.get("GUARDRAIL_TIMEOUT_MAX_S", "3600"))
    guardrail_timeout_max_retries: int = int(
        os.environ.get("GUARDRAIL_TIMEOUT_MAX_RETRIES", "2")
    )
    # pool Postgres — consumer song song đòi nhiều connection hơn trước (5)
    db_pool_max: int = int(os.environ.get("DB_POOL_MAX", "10"))


settings = Settings()
