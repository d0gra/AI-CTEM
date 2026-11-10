"""Runtime configuration. Every operational value is read from the environment."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SECRET = "dev-only-secret-change-me-dev-only-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="CTEM_", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    demo_mode: bool = False
    allow_registration: bool = True

    # Database: the API and workers connect as a non-owner role that is subject to RLS.
    database_url: str = "postgresql+psycopg://ctem_app:ctem_app_dev@127.0.0.1:54329/ctem"
    migration_database_url: str = "postgresql+psycopg://ctem_owner:ctem_owner_dev@127.0.0.1:54329/ctem"
    db_pool_size: int = 10
    redis_url: str | None = None

    # Secrets
    secret_key: str = _DEV_SECRET
    # One or more urlsafe-base64 32-byte Fernet keys, comma separated. First key encrypts.
    encryption_keys: str = ""

    # Sessions
    session_ttl_minutes: int = 12 * 60
    session_idle_minutes: int = 60
    cookie_secure: bool = True
    cookie_name: str = "ctem_session"
    max_failed_logins: int = 8
    lockout_minutes: int = 15

    cors_origins: list[str] = Field(default_factory=list)
    public_base_url: str = "http://localhost:3000"

    # Rate limiting (requests per minute)
    rate_limit_auth: int = 10
    rate_limit_api: int = 600

    # Evidence / report storage
    storage_backend: Literal["local", "s3"] = "local"
    storage_local_path: str = "./var/storage"
    s3_bucket: str = ""
    s3_endpoint_url: str | None = None
    s3_region: str = "us-east-1"
    max_upload_bytes: int = 25 * 1024 * 1024

    # Outbound network policy
    # Assessments may only reach private/loopback addresses when this is enabled AND the
    # target is in the organization's authorized scope. Webhooks never reach private ranges
    # unless allow_private_webhooks is set (intended for development only).
    allow_private_targets: bool = False
    allow_private_webhooks: bool = False
    outbound_timeout_seconds: float = 15.0
    outbound_user_agent: str = "ctem-platform/0.1 (+authorized security assessment)"

    # Scanner execution
    scanner_timeout_seconds: int = 900
    repo_scan_root: str = ""  # directory under which local repositories may be analysed

    # Email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "ctem@localhost"
    smtp_starttls: bool = True

    # Threat intel
    nvd_api_key: str = ""

    # Workers
    worker_concurrency: int = 4
    worker_poll_seconds: float = 2.0
    job_max_attempts: int = 3
    job_stale_after_seconds: int = 300
    max_running_jobs_per_org: int = 4

    # Observability
    log_level: str = "INFO"
    log_json: bool = True
    otel_exporter_otlp_endpoint: str = ""
    sentry_dsn: str = ""

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @model_validator(mode="after")
    def _validate_production(self) -> "Settings":
        if self.env == "production":
            problems = []
            if self.secret_key == _DEV_SECRET or len(self.secret_key) < 32:
                problems.append("CTEM_SECRET_KEY must be set to a random value of at least 32 characters")
            if not self.encryption_keys:
                problems.append("CTEM_ENCRYPTION_KEYS must be set")
            if not self.cookie_secure:
                problems.append("CTEM_COOKIE_SECURE must be true")
            if self.demo_mode:
                problems.append("CTEM_DEMO_MODE must not be enabled")
            if self.allow_private_webhooks:
                problems.append("CTEM_ALLOW_PRIVATE_WEBHOOKS must not be enabled")
            if problems:
                raise ValueError("Unsafe production configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
