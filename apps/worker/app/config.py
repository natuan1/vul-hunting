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


settings = Settings()
