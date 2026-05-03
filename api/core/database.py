"""
Supabase database layer for API key storage and usage event logging.

Uses the Supabase Python client (REST over HTTP) — fully compatible with
Vercel's read-only serverless filesystem. No local files, no SQLite.

The service_role key is used server-side to bypass Row Level Security (RLS).
Never expose this key to the client.

Required Supabase tables (create via SQL editor or migrations):

    CREATE TABLE api_keys (
        id                  BIGSERIAL PRIMARY KEY,
        key_prefix          TEXT        NOT NULL,
        key_hash            TEXT        NOT NULL UNIQUE,
        label               TEXT        NOT NULL DEFAULT '',
        email               TEXT        NOT NULL DEFAULT '',
        stripe_customer_id  TEXT        NOT NULL DEFAULT '',
        is_active           BOOLEAN     NOT NULL DEFAULT TRUE,
        is_paid             BOOLEAN     NOT NULL DEFAULT FALSE,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_used_at        TIMESTAMPTZ
    );

    CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
    CREATE INDEX idx_api_keys_hash   ON api_keys(key_hash);
    CREATE INDEX idx_api_keys_email  ON api_keys(email);

    CREATE TABLE usage_events (
        id                  BIGSERIAL PRIMARY KEY,
        api_key_id          BIGINT      NOT NULL REFERENCES api_keys(id),
        endpoint            TEXT        NOT NULL,
        transaction_count   INTEGER     NOT NULL DEFAULT 0,
        matched_count       INTEGER     NOT NULL DEFAULT 0,
        fallback_count      INTEGER     NOT NULL DEFAULT 0,
        unmatched_count     INTEGER     NOT NULL DEFAULT 0,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
    );
"""

import logging
from functools import lru_cache
from typing import Optional

from supabase import Client, create_client

from api.core.config import get_settings

logger = logging.getLogger(__name__)


@lru_cache()
def get_supabase() -> Client:
    """
    Return a cached Supabase client instance.

    Cached so the client is reused across requests within the same
    serverless invocation (or across requests in long-running mode).
    """
    settings = get_settings()

    if not settings.SUPABASE_URL or not settings.SUPABASE_SERVICE_KEY:
        raise RuntimeError(
            "SUPABASE_URL and SUPABASE_SERVICE_KEY must be set. "
            "See .env.example for details."
        )

    return create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)


# ──────────────────────────────────────────────
# API Key Operations
# ──────────────────────────────────────────────

def insert_api_key(
    key_prefix: str,
    key_hash: str,
    label: str,
    email: str,
    stripe_customer_id: str,
) -> dict:
    """Insert a new API key row and return the created record."""
    client = get_supabase()
    result = (
        client.table("api_keys")
        .insert({
            "key_prefix": key_prefix,
            "key_hash": key_hash,
            "label": label,
            "email": email,
            "stripe_customer_id": stripe_customer_id,
        })
        .execute()
    )
    return result.data[0] if result.data else {}


def find_active_key_by_hash(key_hash: str) -> Optional[dict]:
    """Look up an active API key by its SHA-256 hash."""
    client = get_supabase()
    result = (
        client.table("api_keys")
        .select("*")
        .eq("key_hash", key_hash)
        .eq("is_active", True)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def touch_key_last_used(key_id: int) -> None:
    """Update last_used_at to now(). Fire-and-forget."""
    try:
        client = get_supabase()
        client.table("api_keys").update(
            {"last_used_at": "now()"}
        ).eq("id", key_id).execute()
    except Exception:
        pass  # Non-critical — don't break the request.


def find_key_by_email(email: str) -> Optional[dict]:
    """Look up an existing active key for a given email."""
    client = get_supabase()
    result = (
        client.table("api_keys")
        .select("*")
        .eq("email", email)
        .eq("is_active", True)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def list_all_keys() -> list:
    """Return all API key records (for admin listing)."""
    client = get_supabase()
    result = (
        client.table("api_keys")
        .select("id, key_prefix, label, email, stripe_customer_id, is_active, is_paid, created_at, last_used_at")
        .order("id", desc=True)
        .execute()
    )
    return result.data or []


def revoke_key_by_prefix(key_prefix: str) -> int:
    """
    Soft-revoke all active keys matching the prefix.

    Returns the number of rows affected.
    """
    client = get_supabase()
    result = (
        client.table("api_keys")
        .update({"is_active": False})
        .eq("key_prefix", key_prefix)
        .eq("is_active", True)
        .execute()
    )
    return len(result.data) if result.data else 0


# ──────────────────────────────────────────────
# Usage Event Operations
# ──────────────────────────────────────────────

def insert_usage_event(
    api_key_id: int,
    endpoint: str,
    transaction_count: int,
    matched_count: int,
    fallback_count: int,
    unmatched_count: int,
) -> None:
    """Insert a usage event row. Fire-and-forget — never raises."""
    try:
        client = get_supabase()
        client.table("usage_events").insert({
            "api_key_id": api_key_id,
            "endpoint": endpoint,
            "transaction_count": transaction_count,
            "matched_count": matched_count,
            "fallback_count": fallback_count,
            "unmatched_count": unmatched_count,
        }).execute()
    except Exception as exc:
        logger.error("Failed to insert usage event: %s", exc)


def get_total_usage_for_key(api_key_id: int) -> int:
    """
    Return the total transaction count consumed by a given API key.

    Used by the auth layer to enforce FREE_TIER_CALLS.
    Returns 0 if the query fails (fail-open to avoid blocking paid users
    on a transient DB error).
    """
    try:
        client = get_supabase()
        result = (
            client.table("usage_events")
            .select("transaction_count")
            .eq("api_key_id", api_key_id)
            .execute()
        )
        if result.data:
            return sum(row["transaction_count"] for row in result.data)
        return 0
    except Exception as exc:
        logger.error("Failed to query usage for key %d: %s", api_key_id, exc)
        return 0


# ──────────────────────────────────────────────
# Payment Status Operations
# ──────────────────────────────────────────────

def mark_paid_by_customer_id(stripe_customer_id: str) -> int:
    """
    Set is_paid = True on all active keys linked to the given Stripe customer.

    Called by the Stripe webhook handler after checkout.session.completed
    or invoice.paid is verified.

    Returns the number of rows updated.
    """
    try:
        client = get_supabase()
        result = (
            client.table("api_keys")
            .update({"is_paid": True})
            .eq("stripe_customer_id", stripe_customer_id)
            .eq("is_active", True)
            .execute()
        )
        return len(result.data) if result.data else 0
    except Exception as exc:
        logger.error(
            "Failed to mark paid for customer %s: %s",
            stripe_customer_id, exc,
        )
        return 0
