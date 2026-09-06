import os


class Settings:
    database_url: str = os.environ["DATABASE_URL"]

    # username platform để dựng header định danh mặc định cho Run (ticket #6) —
    # không phải secret nhưng vẫn để env, không hardcode
    hackerone_username: str = os.environ.get("HACKERONE_USERNAME", "")
    intigriti_username: str = os.environ.get("INTIGRITI_USERNAME", "")


settings = Settings()
