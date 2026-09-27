"""Layered configuration: defaults -> YAML file -> environment -> runtime override.

Every value is schema-checked at load and unknown keys are *rejected*, not ignored
(blueprint §9.3(9)). Environment variables use the ``NEURAWALL_`` prefix and ``__``
as the nesting delimiter, e.g. ``NEURAWALL_LLM__MODEL=claude-sonnet-5``.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from neurawall.core.errors import ValidationFailure


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InferenceSettings(_Section):
    #: Tier 1 score at which a flow is escalated to Tier 2 (blueprint §5.4).
    t2_escalation_threshold: float = Field(0.6, ge=0, le=1)
    #: Tier 2 confidence band considered ambiguous -> escalate to Tier 3.
    t3_ambiguous_low: float = Field(0.4, ge=0, le=1)
    t3_ambiguous_high: float = Field(0.7, ge=0, le=1)
    #: Max Tier 2 invocations per node per second.
    t2_rate_per_second: float = Field(500.0, gt=0)
    #: Baseline warm-up (flows per entity) before Tier 1 scores are trusted.
    baseline_warmup_flows: int = Field(200, ge=10)
    isolation_forest_trees: int = Field(100, ge=10, le=1000)


class LlmSettings(_Section):
    provider: Literal["anthropic", "offline"] = "anthropic"
    model: str = "claude-opus-5"
    api_key: SecretStr | None = None
    max_tokens: int = Field(16000, ge=256, le=64000)
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    #: Server-side refusal fallbacks (beta ``server-side-fallback-2026-07-01``).
    server_side_fallbacks: bool = True
    #: Hard budget on Tier 3 invocations per hour, per cluster (blueprint §5.4).
    max_calls_per_hour: int = Field(120, ge=0)
    timeout_seconds: float = Field(60.0, gt=0)


class PolicySettings(_Section):
    #: Drafts affecting more than this fraction of historical traffic are flagged.
    blast_radius_threshold: float = Field(0.01, ge=0, le=1)
    #: Replay window (seconds) used for rule simulation.
    simulation_window_seconds: int = Field(7 * 24 * 3600, ge=60)
    #: Nodes warn when running a bundle older than this (blueprint §3.3).
    bundle_ttl_warning_seconds: int = Field(24 * 3600, ge=60)
    #: Four-eyes: the approver of a rule change must differ from its author.
    require_four_eyes: bool = False
    #: Minimum dwell time per canary stage before auto-advance (5% -> 25% -> 100%).
    rollout_stage_seconds: int = Field(300, ge=0)
    #: Auto-rollback if canary nodes block this much more traffic than the rest.
    rollback_block_rate_increase: float = Field(0.02, ge=0, le=1)
    #: Seed a starter rule pack on first boot.
    starter_rules: bool = True


class AuthSettings(_Section):
    secret_key: SecretStr | None = None
    access_token_ttl_seconds: int = Field(8 * 3600, ge=60)
    bootstrap_admin_email: str = "admin@neurawall.local"
    bootstrap_admin_password: SecretStr | None = None
    login_rate_per_minute: int = Field(10, ge=1)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NEURAWALL_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    environment: Literal["development", "production", "test"] = "development"
    data_dir: Path = Path("./data")
    database_url: str | None = None
    host: str = "0.0.0.0"  # noqa: S104 - server binds all interfaces inside containers
    port: int = Field(8080, ge=1, le=65535)
    public_url: str = "http://localhost:8080"
    cors_origins: list[str] = []
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True
    #: Generate synthetic traffic from a built-in demo sensor (for evaluation / sales demos).
    demo_mode: bool = False
    #: Flow records retained for simulation / investigation.
    flow_retention_seconds: int = Field(7 * 24 * 3600, ge=3600)

    inference: InferenceSettings = InferenceSettings()
    llm: LlmSettings = LlmSettings()
    policy: PolicySettings = PolicySettings()
    auth: AuthSettings = AuthSettings()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence (highest first): runtime override > env > YAML file > defaults.
        return (init_settings, env_settings, _YamlSource(settings_cls), file_secret_settings)

    @model_validator(mode="after")
    def _production_guards(self) -> Settings:
        if self.inference.t3_ambiguous_low > self.inference.t3_ambiguous_high:
            raise ValueError("inference.t3_ambiguous_low must be <= t3_ambiguous_high")
        if self.environment == "production" and self.auth.secret_key is None:
            raise ValueError(
                "auth.secret_key (NEURAWALL_AUTH__SECRET_KEY) is required in production"
            )
        return self

    @property
    def resolved_database_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'neurawall.db').resolve()}"

    @property
    def jwt_secret(self) -> str:
        if self.auth.secret_key is not None:
            return self.auth.secret_key.get_secret_value()
        # Development only: a per-install secret persisted in the data dir.
        path = self.data_dir / ".jwt-secret"
        if not path.exists():
            self.data_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(secrets.token_urlsafe(48))
            path.chmod(0o600)
        return path.read_text().strip()

    @property
    def anthropic_api_key(self) -> str | None:
        if self.llm.api_key is not None:
            return self.llm.api_key.get_secret_value()
        return os.environ.get("ANTHROPIC_API_KEY")


class _YamlSource(PydanticBaseSettingsSource):
    """Reads the file named by ``NEURAWALL_CONFIG`` (if any)."""

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        path = os.environ.get("NEURAWALL_CONFIG")
        if not path:
            return {}
        p = Path(path)
        if not p.is_file():
            raise ValidationFailure(f"config file not found: {path}")
        data = yaml.safe_load(p.read_text()) or {}
        if not isinstance(data, dict):
            raise ValidationFailure("config file must contain a mapping at the top level")
        return data


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def load_settings(**overrides: Any) -> Settings:
    """Build settings with runtime overrides (highest precedence). Not cached."""
    return Settings(**overrides)
