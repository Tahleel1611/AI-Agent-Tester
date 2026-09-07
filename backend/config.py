from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    api_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    llm_provider: Literal["openai", "anthropic", "oci", "mock"] = "mock"
    llm_api_key: str | None = Field(default=None, repr=False)
    llm_model: str = "cohere.command-r-plus"
    oci_auth_type: Literal["API_KEY", "INSTANCE_PRINCIPAL", "RESOURCE_PRINCIPAL"] = "API_KEY"
    oci_profile: str | None = "DEFAULT"
    oci_compartment_id: str | None = None
    oci_service_endpoint: str | None = None
    allowed_cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost", "http://127.0.0.1"]
    )
    allowed_cors_origin_regex: str = r"chrome-extension://.*"

    @field_validator("allowed_cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
