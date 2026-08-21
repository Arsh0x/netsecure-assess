from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NetSecure Assess"
    environment: str = "development"
    secret_key: str = "development-only-change-me-please"
    database_url: str = "sqlite:///./netsecure.db"
    access_token_minutes: int = 30
    refresh_token_days: int = 7
    cors_origins: str = "http://localhost:5173"
    demo_mode: bool = True
    enable_live_capture: bool = False
    max_cidr_hosts: int = 64
    max_ports: int = 256
    scan_concurrency: int = 16
    scan_timeout_seconds: int = 300

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

