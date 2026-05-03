"""
Authentication dependency — database-backed API key system.

Key format:  ``nyz_live_<32-char-hex>``  (total 41 chars)
Storage:     Only the SHA-256 hash is persisted; the raw key is shown once at creation.
Lookup:      Hash the incoming key, query Supabase by hash + is_active.

This replaces the naive "Bearer token = Stripe Customer ID" approach.
"""

import hashlib
import logging
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.core.config import Settings, get_settings
from api.core.database import find_active_key_by_hash, get_total_usage_for_key, touch_key_last_used

logger = logging.getLogger(__name__)

# ── Constants ──
KEY_PREFIX = "nyz_live_"
KEY_RANDOM_BYTES = 16  # 32 hex chars → total key length = 41


# Reusable HTTP Bearer scheme for OpenAPI docs.
_bearer_scheme = HTTPBearer(
    scheme_name="BearerAuth",
    description="Provide your API key (format: nyz_live_<hex>) as a Bearer token.",
)


def generate_api_key() -> str:
    """Generate a new raw API key string."""
    return KEY_PREFIX + secrets.token_hex(KEY_RANDOM_BYTES)


def hash_key(raw_key: str) -> str:
    """SHA-256 hash of the raw API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def verify_api_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> dict:
    """
    FastAPI dependency that extracts and validates the Bearer API key.

    Also enforces the free-tier usage cap (FREE_TIER_CALLS).
    Keys with a linked Stripe customer ID are assumed to be on a paid
    plan and bypass the cap.

    Returns:
        A dict with the full api_keys row (id, stripe_customer_id, email, etc.).

    Raises:
        HTTPException 401: If the key is missing, malformed, or not in the database.
        HTTPException 429: If the free-tier call limit has been exceeded.
    """
    raw_key = credentials.credentials

    # Quick format check before hitting the DB.
    if not raw_key.startswith(KEY_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format. Keys must start with 'nyz_live_'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    key_hash_val = hash_key(raw_key)
    key_record = find_active_key_by_hash(key_hash_val)

    if key_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Free-tier usage enforcement ──
    # Only bypass the cap when is_paid is explicitly True (set via Stripe
    # webhook or admin action after payment is confirmed).
    # IMPORTANT: stripe_customer_id alone does NOT mean paid — a Stripe
    # Customer is created at signup before any payment occurs.
    is_paid = bool(key_record.get("is_paid", False))
    if not is_paid:
        total_used = get_total_usage_for_key(key_record["id"])
        if total_used >= settings.FREE_TIER_CALLS:
            logger.warning(
                "Free-tier limit reached: key_id=%d used=%d limit=%d",
                key_record["id"], total_used, settings.FREE_TIER_CALLS,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Free tier limit of {settings.FREE_TIER_CALLS} transactions exceeded "
                    f"({total_used} used). Upgrade to a paid plan to continue."
                ),
            )

    # Update last_used_at (fire-and-forget, non-critical).
    touch_key_last_used(key_record["id"])

    return key_record


async def verify_admin_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> str:
    """
    Validates the master admin token for key management endpoints
    (listing, revocation). Self-serve generation does NOT use this.

    Returns the token string on success.
    """
    token = credentials.credentials

    if token != settings.MASTER_ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )

    return token

