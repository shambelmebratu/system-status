from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Northstar Operations"
    environment: str = "production"
    database_url: str = "postgresql+psycopg://northstar:northstar@postgres:5432/northstar"
    jwt_secret: str = "change-this-secret-before-production"
    admin_email: str = "admin@example.com"
    admin_password: str = "change-me-now"
    check_interval_seconds: int = 60
    cors_origins: str = "http://localhost:3000"
    cpu_threshold: float = 85
    memory_threshold: float = 90
    disk_threshold: float = 85
    load_threshold: float = 10
    swap_threshold: float = 80
    process_threshold: float = 80
    company_name: str = "Northstar Operations"
    brand_primary_color: str = "#c9f36b"
    brand_accent_color: str = "#68d5e8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
