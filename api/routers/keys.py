"""
API key management router with email OTP verification.

Provides:
    POST /v1/keys/generate  — STEP 1: Send a 6-digit OTP to the developer's email.
    POST /v1/keys/verify    — STEP 2: Verify OTP and issue the API key.
    GET  /v1/keys           — ADMIN: list all keys (requires admin token).
    POST /v1/keys/revoke    — ADMIN: soft-revoke a key by prefix.
"""

import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
import stripe
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.core.config import get_settings
from api.core.database import (
    find_key_by_email,
    find_pending_otp,
    insert_api_key,
    insert_key_request,
    list_all_keys,
    mark_otp_used,
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


# ── OTP Helpers ──

def _generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


def _hash_otp(otp: str) -> str:
    """SHA-256 hash of the OTP for storage."""
    return hashlib.sha256(otp.encode()).hexdigest()


def _send_otp_email(email: str, otp: str) -> None:
    """Send the 6-digit verification code via Brevo."""
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = get_settings().BREVO_API_KEY
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": email}],
        sender={"name": "Normalyze", "email": "no-reply@sendinblue.com"},
        subject="Your Normalyze verification code",
        html_content=(
            f"<div style='font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;'>"
            f"<h2>Your verification code</h2>"
            f"<p style='color:#666;'>Enter this code to generate your API key.</p>"
            f"<div style='font-size:36px;font-weight:700;letter-spacing:8px;"
            f"text-align:center;background:#f5f5f0;border-radius:8px;"
            f"padding:1.5rem;margin-bottom:1.5rem;'>{otp}</div>"
            f"<p style='color:#999;font-size:13px;'>Expires in 10 minutes.</p>"
            f"</div>"
        ),
    )
    api_instance.send_transac_email(send_smtp_email)


# ── Request / Response Models ──

class OTPSentResponse(BaseModel):
    status: str = "otp_sent"
    message: str = "Check your email for a 6-digit verification code."


class VerifyOTPRequest(BaseModel):
    email: str = Field(..., description="The email address used in /generate.")
    otp: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="The 6-digit OTP from your email.",
    )


# ──────────────────────────────────────────────
# Step 1 — Send OTP
# ──────────────────────────────────────────────

@router.post(
    "/generate",
    response_model=OTPSentResponse,
    status_code=status.HTTP_200_OK,
    summary="Step 1 — Request an API key (sends OTP)",
    description=(
        "Validates the email, checks for existing keys, then sends a 6-digit "
        "verification code to the email via Resend. The OTP expires in 10 "
        "minutes. No key is created at this step — call /v1/keys/verify next."
    ),
    responses={
        400: {"description": "Invalid email format."},
        409: {"description": "Email already has an active API key."},
        500: {"description": "Email delivery or database error."},
    },
)
async def generate_key(payload: GenerateKeyRequest) -> OTPSentResponse:
    """
    Step 1 of the key generation flow:

    1. Validate email format.
    2. Check if email already has an active key → 409 if so.
    3. Generate a 6-digit OTP.
    4. Store the OTP hash + expiry in the key_requests table.
    5. Send the OTP via Resend.
    6. Return {"status": "otp_sent"}.
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

    # ── Generate OTP ──
    otp = _generate_otp()
    otp_hash = _hash_otp(otp)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

    # ── Store in key_requests ──
    try:
        insert_key_request(email=email, otp_hash=otp_hash, expires_at=expires_at)
    except Exception as exc:
        logger.exception("Failed to store OTP request for %s", email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create verification request.",
        ) from exc

    # ── Send email ──
    try:
        _send_otp_email(email, otp)
        logger.info("OTP sent to %s", email)
    except Exception as exc:
        logger.exception("Failed to send OTP email to %s", email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email. Please try again.",
        ) from exc

    return OTPSentResponse()


# ──────────────────────────────────────────────
# Step 2 — Verify OTP & Issue Key
# ──────────────────────────────────────────────

@router.post(
    "/verify",
    response_model=GenerateKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Step 2 — Verify OTP and get your API key",
    description=(
        "Submit the 6-digit OTP from your email along with the email address. "
        "If valid and not expired, the API key is created immediately and "
        "returned. The raw key is shown only once."
    ),
    responses={
        400: {"description": "Invalid or expired OTP."},
        409: {"description": "Email already has an active API key."},
        500: {"description": "Stripe or database error."},
    },
)
async def verify_otp(payload: VerifyOTPRequest) -> GenerateKeyResponse:
    """
    Step 2 of the key generation flow:

    1. Look up the most recent unused, unexpired OTP for the email.
    2. Verify the submitted OTP against the stored hash.
    3. Mark the OTP as used.
    4. Create a Stripe customer.
    5. Generate the API key, hash it, store it.
    6. Return the raw key (shown only once).
    """
    email = payload.email.strip().lower()
    otp = payload.otp.strip()

    # ── Find pending OTP ──
    pending = find_pending_otp(email)
    if pending is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending verification found for this email. Request a new code via /v1/keys/generate.",
        )

    # ── Verify OTP ──
    if _hash_otp(otp) != pending["otp_hash"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please check and try again.",
        )

    # ── Mark as used ──
    mark_otp_used(pending["id"])

    # ── Double-check no key was created in the meantime ──
    existing = find_key_by_email(email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Email '{email}' already has an active API key "
                f"(prefix: {existing['key_prefix']})."
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
