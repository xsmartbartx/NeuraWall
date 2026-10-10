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
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from neurawall.core.errors import ValidationFailure


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InferenceSettings(_Section):
    #: Tier 1 score at which a flow is escalated to Tier 2 (blueprint §5.4).
    t2_escalation_threshold: float = Field(0.6, ge=0, le=1)
    #: Tier 2 confidence band considered ambiguous -> escalate to Tier 3.
    t3_ambiguous_low: float = Field(0.4, ge=0, le=1)
    #: Upper bound of the ambiguous band (above it, Tier 2 is confident enough on its own).
    t3_ambiguous_high: float = Field(0.7, ge=0, le=1)
    #: Max Tier 2 invocations per node per second.
    t2_rate_per_second: float = Field(500.0, gt=0)
    #: Baseline warm-up (flows per entity) before Tier 1 scores are trusted.
    baseline_warmup_flows: int = Field(200, ge=10)
    #: Isolation Forest size (accuracy vs CPU).
    isolation_forest_trees: int = Field(100, ge=10, le=1000)


class LlmSettings(_Section):
    #: `offline` always uses the deterministic heuristic advisor (no data leaves the host).
    provider: Literal["anthropic", "offline"] = "anthropic"
    #: Claude model used for triage, rule drafting and narration.
    model: str = "claude-opus-5"
    #: Anthropic API key; falls back to `ANTHROPIC_API_KEY`. Without one, Tier 3 runs offline.
    api_key: SecretStr | None = None
    #: Output token ceiling per Tier 3 call.
    max_tokens: int = Field(16000, ge=256, le=64000)
    #: Reasoning effort for Tier 3 calls (cost vs thoroughness).
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    #: Server-side refusal fallbacks (beta ``server-side-fallback-2026-07-01``).
    server_side_fallbacks: bool = True
    #: Anthropic workspace id, required when the API key is not scoped to a workspace
    #: (sent as the `anthropic-workspace-id` header). Falls back to `ANTHROPIC_WORKSPACE_ID`.
    workspace_id: str | None = None
    #: Hard budget on Tier 3 invocations per hour, per cluster (blueprint §5.4).
    max_calls_per_hour: int = Field(120, ge=0)
    #: Per-request timeout for Tier 3 calls; on timeout the heuristic advisor answers.
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


class BillingSettings(_Section):
    #: Plan for installs not billed through Stripe (self-hosted licences, Enterprise
    #: Dedicated). An active Stripe subscription takes precedence.
    plan: Literal["community", "pro", "business", "enterprise", "enterprise_dedicated"] = (
        "community"
    )
    #: Stripe secret key (`sk_live_…`). Empty = self-serve billing disabled.
    stripe_secret_key: SecretStr | None = None
    #: Signing secret of the webhook endpoint `<public_url>/api/v1/billing/webhook`.
    stripe_webhook_secret: SecretStr | None = None
    #: Stripe Customer Portal configuration id (optional; Stripe default otherwise).
    stripe_portal_configuration_id: str | None = None
    #: Stripe Price ids per plan and interval.
    price_pro_month: str | None = None
    price_pro_year: str | None = None
    price_business_month: str | None = None
    price_business_year: str | None = None
    price_enterprise_month: str | None = None
    price_enterprise_year: str | None = None
    #: Claude calls per UTC month included with Business. Over it, the offline advisor answers
    #: until the month ends. Placeholder until the plan limits are decided.
    llm_calls_business: int = Field(3000, ge=0)
    #: Claude calls per UTC month included with Enterprise.
    llm_calls_enterprise: int = Field(15000, ge=0)

    @field_validator("*", mode="before")
    @classmethod
    def _empty_is_unset(cls, v: Any) -> Any:
        # Compose passes unset variables as "", which must mean "not configured".
        return None if isinstance(v, str) and not v.strip() else v

    @property
    def self_serve_enabled(self) -> bool:
        return self.stripe_secret_key is not None and self.stripe_webhook_secret is not None

    def llm_monthly_calls(self, plan: str) -> int | None:
        """The call budget of an `included` plan; None = no budget to enforce."""
        return {"business": self.llm_calls_business, "enterprise": self.llm_calls_enterprise}.get(
            plan
        )

    def price_id(self, plan: str, interval: str) -> str | None:
        value = getattr(self, f"price_{plan}_{interval}", None)
        return value or None

    def plan_by_price(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for plan in ("pro", "business", "enterprise"):
            for interval in ("month", "year"):
                pid = self.price_id(plan, interval)
                if pid:
                    out[pid] = plan
        return out


class AuthSettings(_Section):
    #: HMAC key for console sessions. Required in production (`openssl rand -base64 48`).
    secret_key: SecretStr | None = None
    #: Console session lifetime.
    access_token_ttl_seconds: int = Field(8 * 3600, ge=60)
    #: Email of the admin account created on first start.
    bootstrap_admin_email: str = "admin@neurawall.local"
    #: Initial admin password. If unset, one is generated into `data_dir/initial-admin-password.txt`.
    bootstrap_admin_password: SecretStr | None = None
    #: Login attempts allowed per minute per client IP and per account.
    login_rate_per_minute: int = Field(10, ge=1)
    #: Clerk JWKS URL (e.g. `https://clerk.example.com/.well-known/jwks.json`). Setting it
    #: enables `POST /api/v1/auth/sso`, which signs an *existing* user in from a verified
    #: Clerk session token. Unset (the default) = SSO is off and the endpoint returns 404.
    sso_jwks_url: str | None = None
    #: If set, the token's `iss` claim must equal this (the Clerk frontend API URL).
    sso_issuer: str | None = None
    #: If set, the token's `aud` claim must equal this (the Clerk JWT template should set it),
    #: so a Clerk token minted for another service cannot be replayed here.
    sso_audience: str | None = None
    #: Where the console sends the browser to obtain a token (the NEXORA account app's
    #: handoff URL). Setting it shows "Sign in with NEXORA" on the console login page.
    sso_login_url: str | None = None
    #: If set, the token must carry this Clerk organisation id (`org_id`), so only members
    #: of one organisation can use SSO.
    sso_required_org_id: str | None = None
    #: Create a `viewer` on the first SSO sign-in of a verified member of `sso_required_org_id`
    #: (the token must carry `email_verified: true`). Off by default: SSO then only signs in
    #: existing users. A role is never taken from the identity provider; admins promote users.
    sso_jit: bool = False
    #: Lifetime of an SSO session. Unset = `access_token_ttl_seconds`, or one hour when `sso_jit`
    #: is on (removing someone from the organisation then takes effect within the hour).
    sso_session_ttl_seconds: int | None = Field(None, ge=60)
    #: `enabled` = anyone with a password may use it. `admin_only` = password sign-in is kept
    #: for admins (break-glass); everyone else uses SSO.
    local_login: Literal["enabled", "admin_only"] = "enabled"
    #: Public "Try the demo" sign-in as a read-only viewer, for a *separate demo instance* with
    #: synthetic traffic. Refused at startup unless `demo_mode` is on, and on any instance that
    #: is linked to NEXORA, has Stripe keys or a Claude API key.
    demo_public_login: bool = False

    @model_validator(mode="after")
    def _jit_needs_an_organisation(self) -> AuthSettings:
        if self.sso_jit and not (self.sso_jwks_url and self.sso_required_org_id):
            raise ValueError(
                "auth.sso_jit needs auth.sso_jwks_url and auth.sso_required_org_id: "
                "without an organisation any identity-provider user would get an account"
            )
        return self

    @property
    def sso_ttl_seconds(self) -> int:
        if self.sso_session_ttl_seconds is not None:
            return self.sso_session_ttl_seconds
        return 3600 if self.sso_jit else self.access_token_ttl_seconds


class NexoraSettings(_Section):
    """Linked mode: this installation belongs to one NEXORA organisation. Off unless an API
    key is set. The plan then comes from NEXORA instead of a licence or a local Stripe
    subscription, and usage events flow back."""

    #: NEXORA API base URL. Must be https (http only for localhost, in tests).
    api_url: str = "https://api.onenexora.com"
    #: An organisation API key (`nx_live_…`) allowed to read this organisation's NeuraWall
    #: entitlement and write usage events. Empty = standalone installation.
    api_key: SecretStr | None = None
    #: Where "manage your plan" sends people (the NEXORA console).
    console_url: str = "https://console.onenexora.com"
    #: How often the plan is re-read.
    sync_interval_seconds: int = Field(3600, ge=60)
    #: Send usage events (counts only: no addresses, no emails, no flow data).
    events_enabled: bool = True

    @field_validator("*", mode="before")
    @classmethod
    def _empty_is_unset(cls, v: Any, info: ValidationInfo) -> Any:
        # Compose passes unset variables as "", which must mean "use the default".
        if isinstance(v, str) and not v.strip():
            return cls.model_fields[info.field_name or ""].get_default()
        return v

    @field_validator("api_url", "console_url")
    @classmethod
    def _https(cls, v: str) -> str:
        host = v.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if not (v.startswith("https://") or (v.startswith("http://") and host == "localhost")):
            raise ValueError("must be an https:// URL")
        return v.rstrip("/")

    @property
    def linked(self) -> bool:
        return self.api_key is not None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NEURAWALL_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    #: `production` enforces a configured secret key and marks the console accordingly.
    environment: Literal["development", "production", "test"] = "development"
    #: Holds the SQLite database (if used), bundle-signing key and bootstrap secret. Mode 0700.
    data_dir: Path = Path("./data")
    #: SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host/neurawall`. Empty = SQLite in data_dir.
    database_url: str | None = None
    #: Listen address.
    host: str = "0.0.0.0"  # noqa: S104 - server binds all interfaces inside containers
    #: Listen port.
    port: int = Field(8080, ge=1, le=65535)
    #: Externally reachable URL (shown in enrollment instructions; `https://` enables HSTS).
    public_url: str = "http://localhost:8080"
    #: Allowed browser origins if the console is served from another origin (normally empty).
    cors_origins: list[str] = []
    #: Log verbosity.
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    #: Structured JSON logs (recommended in production) instead of human-readable text.
    log_json: bool = True
    #: Generate synthetic traffic from a built-in demo sensor (for evaluation / sales demos).
    demo_mode: bool = False
    #: Override flow retention. Unset = the active plan's retention (7/30/90 days).
    flow_retention_seconds: int | None = Field(None, ge=3600)

    inference: InferenceSettings = InferenceSettings()
    llm: LlmSettings = LlmSettings()
    policy: PolicySettings = PolicySettings()
    auth: AuthSettings = AuthSettings()
    billing: BillingSettings = BillingSettings()
    nexora: NexoraSettings = NexoraSettings()

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
        if self.auth.demo_public_login:
            if not self.demo_mode:
                raise ValueError("auth.demo_public_login needs demo_mode (synthetic traffic only)")
            if self.nexora.linked or self.billing.stripe_secret_key is not None:
                raise ValueError(
                    "auth.demo_public_login must not run on an installation that is linked to "
                    "NEXORA or has billing keys: use a separate demo instance"
                )
            if self.anthropic_api_key:
                raise ValueError("auth.demo_public_login must run with the offline advisor")
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
    def anthropic_workspace_id(self) -> str | None:
        return self.llm.workspace_id or os.environ.get("ANTHROPIC_WORKSPACE_ID") or None

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
