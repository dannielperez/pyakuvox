"""Application configuration loaded from environment variables.

Uses pydantic-settings to validate and type-check all config values.
Secrets (passwords, tokens) are loaded from env vars — never hardcoded.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LocalAuthType(StrEnum):
    """Authentication methods supported by Akuvox local HTTP API.

    Verified via pylocal-akuvox:
      - NONE / ALLOWLIST: no credentials needed (device uses IP allowlist)
      - BASIC: HTTP Basic auth
      - DIGEST: HTTP Digest auth
    """

    NONE = "none"
    ALLOWLIST = "allowlist"
    BASIC = "basic"
    DIGEST = "digest"


class CloudSubdomain(StrEnum):
    """Known Akuvox SmartPlus regional subdomains.

    Source: ezhevita/AkuvoxAPI + nimroddolev/akuvox const.py.
    These are reverse-engineered — Akuvox may change them at any time.
    """

    ECLOUD = "ecloud"  # EMEA
    UCLOUD = "ucloud"  # Americas
    SCLOUD = "scloud"  # APAC
    JCLOUD = "jcloud"  # APAC2 (JP/KR/MN)
    CCLOUD = "ccloud"  # China
    RUCLOUD = "rucloud"  # Russia/Belarus
    AUCLOUD = "aucloud"  # Australia (unconfirmed, seen in some sources)


class LocalSettings(BaseSettings):
    """Connection settings for the local Akuvox HTTP API."""

    model_config = SettingsConfigDict(env_prefix="AKUVOX_LOCAL_")

    host: str = "192.168.1.100"
    port: int = 80
    username: str = "admin"
    password: SecretStr = SecretStr("admin")
    auth_type: LocalAuthType = LocalAuthType.BASIC
    use_ssl: bool = False
    verify_ssl: bool = False
    timeout: int = 10

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_ssl else "http"
        return f"{scheme}://{self.host}:{self.port}"


class CloudSettings(BaseSettings):
    """Connection settings for the Akuvox SmartPlus cloud API.

    WARNING: All cloud integration is EXPERIMENTAL and based on
    reverse-engineered, undocumented endpoints. These settings and
    the cloud module may break without notice.
    """

    model_config = SettingsConfigDict(env_prefix="AKUVOX_CLOUD_")

    phone_number: str = ""
    country_code: str = ""
    auth_token: SecretStr = SecretStr("")
    token: SecretStr = SecretStr("")
    subdomain: CloudSubdomain = CloudSubdomain.ECLOUD

    @property
    def is_configured(self) -> bool:
        return bool(self.token.get_secret_value())


class Settings(BaseSettings):
    """Root configuration aggregating all sub-settings."""

    model_config = SettingsConfigDict(
        env_prefix="AKUVOX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    debug: bool = False
    log_level: str = "INFO"
    log_http_bodies: bool = False

    local: LocalSettings = LocalSettings()
    cloud: CloudSettings = CloudSettings()

    @model_validator(mode="after")
    def _debug_implies_verbose_logging(self) -> Self:
        if self.debug and self.log_level == "INFO":
            self.log_level = "DEBUG"
        return self


def get_settings() -> Settings:
    """Factory that loads settings from env / .env file.

    Call this once at application startup; pass the resulting
    object via dependency injection rather than importing a global.
    """
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        return Settings(_env_file=str(env_path))  # type: ignore[call-arg]
    return Settings()
