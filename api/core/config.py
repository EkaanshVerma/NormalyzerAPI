"""
Centralised application configuration loaded from environment variables.

Uses pydantic-settings so that every config value is validated at startup.
Missing required vars cause an immediate, descriptive startup failure rather
than a silent runtime error.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings sourced from environment variables.

    Attributes:
        APP_NAME:             Human-readable service name.
        APP_VERSION:          Semantic version string exposed via /health.
        DEBUG:                Enables verbose logging when True.
        SUPABASE_URL:         Supabase project URL (e.g., https://xyz.supabase.co).
        SUPABASE_SERVICE_KEY: Supabase service_role key (full DB access, server-side only).
        STRIPE_API_KEY:       Stripe secret key for customer creation + metered billing.
        STRIPE_METER_EVENT:   The Stripe Meter event name configured in the dashboard.
        GEMINI_API_KEY:       Google Gemini API key for LLM fallback categorization.
        GEMINI_MODEL:         Gemini model to use for fallback.
        MASTER_ADMIN_TOKEN:   Admin token for key listing and revocation endpoints.
    """

    APP_NAME: str = "Normalyze"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Supabase — replaces SQLite for serverless compatibility on Vercel.
    # The service_role key bypasses RLS and is used server-side only.
    SUPABASE_URL: str = ""
    SUPABASE_SERVICE_KEY: str = ""

    # Stripe — used for customer creation, metered billing, and webhooks.
    STRIPE_API_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""  # whsec_... from Stripe Dashboard → Webhooks
    STRIPE_METERED_PRICE_ID: str = ""  # price_... for the metered subscription plan

    # Gemini fallback for unmatched transactions.
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"

    # Admin token — for key listing/revocation only.
    # Self-serve key generation does NOT require this.
    MASTER_ADMIN_TOKEN: str = "admin-bootstrap-token"

    # Free tier — maximum total transactions a key can process before
    # requiring a paid Stripe subscription. Set via env to adjust without deploy.
    FREE_TIER_CALLS: int = 10000

    # Brevo — transactional email for OTP verification and contact form.
    BREVO_API_KEY: str = ""
    CONTACT_EMAIL: str = "ekaansh.vermagroup@gmail.com"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    Using lru_cache ensures the .env file is read only once per process
    lifecycle, which is critical for serverless cold-start performance.
    """
    return Settings()
