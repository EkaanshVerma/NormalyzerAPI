"""
Stripe metered billing integration.

Reports usage against a customer's metered subscription item after
normalization requests complete. Designed to run as a FastAPI
BackgroundTask so it does not block the response.

Flow:
    1. Customer subscribes to the metered price (via Checkout or API).
    2. Each normalization request triggers report_usage() as a background task.
    3. Stripe aggregates usage and invoices at the end of the billing period.
"""

import logging

import stripe

from api.core.config import get_settings

logger = logging.getLogger(__name__)


def _find_metered_subscription_item(customer_id: str, price_id: str) -> str | None:
    """
    Find the subscription item ID for the given customer + metered price.

    Returns the subscription item ID (si_...) or None if not found.
    """
    try:
        subscriptions = stripe.Subscription.list(
            customer=customer_id,
            status="active",
            limit=5,
        )
        for sub in subscriptions.auto_paging_iter():
            for item in sub["items"]["data"]:
                if item["price"]["id"] == price_id:
                    return item["id"]
    except stripe.StripeError as exc:
        logger.error(
            "Failed to find subscription item for customer=%s: %s",
            customer_id, exc,
        )
    return None


def report_usage(customer_id: str, transaction_count: int) -> None:
    """
    Report metered usage to Stripe.

    This function is intended to be called as a FastAPI BackgroundTask.
    It finds the customer's active metered subscription item and creates
    a usage record for the number of transactions processed.

    Args:
        customer_id:       The Stripe Customer ID (cus_...).
        transaction_count: Number of transactions normalised in this request.
    """
    settings = get_settings()

    if not settings.STRIPE_API_KEY:
        logger.warning(
            "STRIPE_API_KEY not configured — skipping usage report "
            "for customer=%s count=%d",
            customer_id,
            transaction_count,
        )
        return

    if not settings.STRIPE_METERED_PRICE_ID:
        logger.warning(
            "STRIPE_METERED_PRICE_ID not configured — skipping usage report "
            "for customer=%s count=%d",
            customer_id,
            transaction_count,
        )
        return

    if not customer_id:
        logger.debug("No customer_id provided — skipping usage report")
        return

    try:
        stripe.api_key = settings.STRIPE_API_KEY

        # Find the subscription item for this customer's metered plan.
        si_id = _find_metered_subscription_item(
            customer_id, settings.STRIPE_METERED_PRICE_ID
        )

        if not si_id:
            logger.debug(
                "No active metered subscription for customer=%s price=%s — "
                "skipping usage report (customer may be on free tier)",
                customer_id,
                settings.STRIPE_METERED_PRICE_ID,
            )
            return

        # Report usage against the subscription item.
        stripe.SubscriptionItem.create_usage_record(
            si_id,
            quantity=transaction_count,
            action="increment",
        )

        logger.info(
            "Stripe usage recorded: customer=%s si=%s count=%d",
            customer_id,
            si_id,
            transaction_count,
        )

    except stripe.StripeError as exc:
        # Log but do not re-raise — billing failures must not break the
        # data pipeline for the consumer.
        logger.error(
            "Stripe billing error for customer=%s: %s",
            customer_id,
            str(exc),
        )
    except Exception as exc:
        logger.error(
            "Unexpected error in billing report for customer=%s: %s",
            customer_id,
            str(exc),
        )
