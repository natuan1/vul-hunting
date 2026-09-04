import os


class Settings:
    database_url: str = os.environ["DATABASE_URL"]


settings = Settings()
