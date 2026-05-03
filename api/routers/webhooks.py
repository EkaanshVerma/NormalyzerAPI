"""
Stripe webhook handler.

Listens for checkout.session.completed and invoice.paid events,
verifies the Stripe signature, and flips is_paid = True on the
matching API key by stripe_customer_id.

Setup:
    1. In Stripe Dashboard → Developers → Webhooks, create an endpoint
       pointing to https://your-api.vercel.app/webhooks/stripe
    2. Select events: checkout.session.completed, invoice.paid
    3. Copy the signing secret (whsec_...) into STRIPE_WEBHOOK_SECRET
"""

import logging

import stripe
from fastapi import APIRouter, HTTPException, Request, status

from api.core.config import get_settings
from api.core.database import mark_paid_by_customer_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

# Events that confirm payment and should flip is_paid.
_PAID_EVENTS = {"checkout.session.completed", "invoice.paid"}


@router.post(
    "/stripe",
    status_code=status.HTTP_200_OK,
    summary="Stripe webhook receiver",
    description=(
        "Receives Stripe webhook events. Verifies the signature using "
        "STRIPE_WEBHOOK_SECRET, then processes checkout.session.completed "
        "and invoice.paid to activate paid status on matching API keys."
    ),
    include_in_schema=False,  # Hide from public OpenAPI docs.
)
async def stripe_webhook(request: Request) -> dict:
    """
    1. Read the raw body (Stripe requires the raw bytes for sig verification).
    2. Verify the webhook signature.
    3. For paid events, extract the customer ID and flip is_paid = True.
    """
    settings = get_settings()
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if not settings.STRIPE_WEBHOOK_SECRET:
        logger.error("STRIPE_WEBHOOK_SECRET not configured — rejecting webhook")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook secret not configured.",
        )

    # ── Verify signature ──
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except stripe.SignatureVerificationError:
        logger.warning("Stripe webhook signature verification failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature.",
        )
    except ValueError:
        logger.warning("Stripe webhook payload could not be parsed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid payload.",
        )

    # ── Process relevant events ──
    event_type = event.get("type", "")
    logger.info("Stripe webhook received: %s (id=%s)", event_type, event.get("id"))

    if event_type in _PAID_EVENTS:
        data_object = event["data"]["object"]
        customer_id = data_object.get("customer", "")

        if not customer_id:
            logger.warning("Paid event %s has no customer ID — skipping", event_type)
            return {"status": "skipped", "reason": "no customer ID"}

        updated = mark_paid_by_customer_id(customer_id)
        logger.info(
            "is_paid flipped for customer=%s (rows=%d, event=%s)",
            customer_id, updated, event_type,
        )
        return {"status": "processed", "customer": customer_id, "keys_updated": updated}

    # Acknowledge but ignore events we don't care about.
    return {"status": "ignored", "event_type": event_type}
