"""
API key management router.

Provides:
    POST /v1/keys/generate  — SELF-SERVE: any developer signs up with email,
                               gets a Stripe customer + API key automatically.
    GET  /v1/keys           — ADMIN: list all keys (requires admin token).
    POST /v1/keys/revoke    — ADMIN: soft-revoke a key by prefix.
"""

import logging
import re

import stripe
from fastapi import APIRouter, Depends, HTTPException, status

from api.core.config import get_settings
from api.core.database import (
    find_key_by_email,
    insert_api_key,
    list_all_keys,
    revoke_key_by_prefix,
)
from api.core.security import (
    generate_api_key,
    hash_key,
    verify_admin_token,
)
from api.models.schemas import (
    CreateKeyResponse,
    GenerateKeyRequest,
    GenerateKeyResponse,
    KeyInfo,
    ListKeysResponse,
    RevokeKeyRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/keys", tags=["Key Management"])

# Basic email validation pattern.
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


@router.post(
    "/generate",
    response_model=GenerateKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Self-serve API key generation",
    description=(
        "Any developer can hit this endpoint with their email to get an API key. "
        "A Stripe customer is created automatically and linked to the key for "
        "metered billing. No admin token required.\n\n"
        "If the email already has an active key, the existing key prefix is "
        "returned with instructions to contact support (the raw key is never "
        "shown again after initial creation)."
    ),
    responses={
        400: {"description": "Invalid email format."},
        409: {"description": "Email already has an active API key."},
        500: {"description": "Stripe or database error."},
    },
)
async def generate_key(payload: GenerateKeyRequest) -> GenerateKeyResponse:
    """
    Self-serve key generation flow:

    1. Validate email format.
    2. Check if email already has an active key → 409 if so.
    3. Create a Stripe customer with the email.
    4. Generate an nyz_live_* key, hash it.
    5. Store in Supabase with the Stripe customer ID.
    6. Return the raw key (shown only once) + Stripe customer ID.
    """
    email = payload.email.strip().lower()

    # ── Validate email ──
    if not _EMAIL_RE.match(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format.",
        )

    # ── Check for existing key ──
    existing = find_key_by_email(email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Email '{email}' already has an active API key "
                f"(prefix: {existing['key_prefix']}). "
                "If you lost your key, contact support for a rotation."
            ),
        )

    # ── Create Stripe customer ──
    settings = get_settings()
    stripe_customer_id = ""

    if settings.STRIPE_API_KEY:
        try:
            stripe.api_key = settings.STRIPE_API_KEY
            customer = stripe.Customer.create(
                email=email,
                metadata={"source": "financial-data-normalizer", "plan": "metered"},
            )
            stripe_customer_id = customer.id
            logger.info("Stripe customer created: %s for %s", customer.id, email)
        except stripe.StripeError as exc:
            logger.error("Stripe customer creation failed for %s: %s", email, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create billing account: {str(exc)}",
            ) from exc
    else:
        logger.warning(
            "STRIPE_API_KEY not set — skipping Stripe customer creation for %s",
            email,
        )

    # ── Generate and store API key ──
    raw_key = generate_api_key()
    key_hash_val = hash_key(raw_key)
    prefix = raw_key[:14]  # "nyz_live_" + first 5 hex chars
    label = f"auto-{email.split('@')[0]}"

    try:
        insert_api_key(
            key_prefix=prefix,
            key_hash=key_hash_val,
            label=label,
            email=email,
            stripe_customer_id=stripe_customer_id,
        )
    except Exception as exc:
        logger.exception("Failed to store API key for %s", email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key storage failed: {str(exc)}",
        ) from exc

    return GenerateKeyResponse(
        api_key=raw_key,
        key_prefix=prefix,
        email=email,
        stripe_customer_id=stripe_customer_id,
    )


# ──────────────────────────────────────────────
# Admin-only endpoints (require MASTER_ADMIN_TOKEN)
# ──────────────────────────────────────────────

@router.get(
    "",
    response_model=ListKeysResponse,
    summary="List all API keys (admin)",
    description="Returns metadata for all API keys. Never exposes raw keys or hashes.",
    responses={
        403: {"description": "Admin access required."},
    },
)
async def list_keys(
    _admin: str = Depends(verify_admin_token),
) -> ListKeysResponse:
    """List all API keys (active and revoked) with metadata."""
    rows = list_all_keys()

    keys = [
        KeyInfo(
            id=row["id"],
            key_prefix=row["key_prefix"],
            label=row["label"],
            email=row.get("email", ""),
            stripe_customer_id=row["stripe_customer_id"],
            is_active=bool(row["is_active"]),
            is_paid=bool(row.get("is_paid", False)),
            created_at=str(row["created_at"]),
            last_used_at=str(row["last_used_at"]) if row.get("last_used_at") else None,
        )
        for row in rows
    ]

    return ListKeysResponse(keys=keys)


@router.post(
    "/revoke",
    status_code=status.HTTP_200_OK,
    summary="Revoke an API key (admin)",
    description="Soft-deletes an API key by prefix. The key remains in the database but is marked inactive.",
    responses={
        403: {"description": "Admin access required."},
        404: {"description": "No active key found with that prefix."},
    },
)
async def revoke_key(
    payload: RevokeKeyRequest,
    _admin: str = Depends(verify_admin_token),
) -> dict:
    """Revoke an API key by setting is_active = false."""
    count = revoke_key_by_prefix(payload.key_prefix)

    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active key found with prefix '{payload.key_prefix}'.",
        )

    return {"status": "revoked", "key_prefix": payload.key_prefix}
