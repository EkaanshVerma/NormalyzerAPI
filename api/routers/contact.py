"""
Contact form endpoint.

Accepts name, email, and message from the landing page contact form,
persists the submission to a ``contact_messages`` Supabase table, and
forwards an email notification via Resend.

No authentication required — this is a public endpoint.
"""

import logging
from datetime import datetime, timezone

import resend
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field

from api.core.config import get_settings
from api.core.database import get_supabase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["Contact"])


# ── Request / Response Models ──

class ContactRequest(BaseModel):
    name: str
    email: EmailStr
    message: str = Field(..., max_length=2000)


class ContactResponse(BaseModel):
    status: str = "sent"


# ── Endpoint ──

@router.post(
    "/contact",
    response_model=ContactResponse,
    summary="Submit a contact message",
    description=(
        "Saves the message to Supabase and sends an email notification "
        "to the site owner via Resend. No auth required."
    ),
)
async def submit_contact(payload: ContactRequest) -> ContactResponse:
    """Handle a contact form submission."""
    settings = get_settings()

    # ── 1. Persist to Supabase ──
    try:
        client = get_supabase()
        client.table("contact_messages").insert({
            "name": payload.name,
            "email": payload.email,
            "message": payload.message,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:
        logger.error("Failed to insert contact message: %s", exc)
        raise HTTPException(status_code=500, detail="Database error") from exc

    # ── 2. Send notification email via Resend ──
    try:
        resend.api_key = settings.RESEND_API_KEY
        resend.Emails.send({
            "from": "Normalyze <onboarding@resend.dev>",
            "to": [settings.CONTACT_EMAIL],
            "subject": f"New contact from {payload.name} — Normalyze",
            "html": (
                f"<h2>New Contact Submission</h2>"
                f"<p><strong>Name:</strong> {payload.name}</p>"
                f"<p><strong>Email:</strong> {payload.email}</p>"
                f"<p><strong>Message:</strong></p>"
                f"<p>{payload.message}</p>"
            ),
        })
    except Exception as exc:
        logger.error("Failed to send contact email via Resend: %s", exc)
        # Don't fail the request — the message is already saved in Supabase.

    return ContactResponse()
