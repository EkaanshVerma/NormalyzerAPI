"""
Public demo endpoint for the landing page.

Provides a single ``POST /v1/demo`` endpoint that normalizes one raw
transaction string without requiring authentication.  It reuses the same
``normalize_transactions`` pipeline as the authenticated endpoints.

Rate-limited to 30 requests per minute per IP using an in-memory dict.
No Redis or external store needed — sufficient for an MVP.
"""

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import List

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.models.schemas import NormalizedTransaction, SingleTransactionResponse
from api.services.mapper import normalize_transactions

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["Demo"])


# ── Request Model ──

class DemoRequest(BaseModel):
    """Public demo request — accepts a single raw transaction string."""
    transaction: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="A raw transaction string to normalize (e.g. 'UPI/ZOMATO/98123456/FOOD').",
        examples=["UPI/ZOMATO/98123456/FOOD"],
    )


# ── In-Memory Rate Limiter ──

_RATE_LIMIT = 30           # max requests
_RATE_WINDOW = 60          # per 60 seconds
_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = Lock()


def _check_rate_limit(client_ip: str) -> None:
    """
    Enforce per-IP rate limiting using a sliding-window counter.

    Raises HTTPException 429 if the caller exceeds 30 req/min.
    """
    now = time.time()
    cutoff = now - _RATE_WINDOW

    with _rate_lock:
        # Prune timestamps older than the window.
        timestamps = _rate_store[client_ip]
        _rate_store[client_ip] = [t for t in timestamps if t > cutoff]

        if len(_rate_store[client_ip]) >= _RATE_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded: {_RATE_LIMIT} requests per minute. "
                    "Please wait before trying again."
                ),
            )

        _rate_store[client_ip].append(now)


# ── Endpoint ──

@router.post(
    "/demo",
    response_model=SingleTransactionResponse,
    status_code=status.HTTP_200_OK,
    summary="Public demo — normalize a single transaction",
    description=(
        "A free, unauthenticated endpoint for the landing page demo. "
        "Normalizes a single raw transaction string using the same "
        "pipeline as /v1/normalize/transaction. Rate-limited to "
        "30 requests per minute per IP."
    ),
    responses={
        422: {"description": "Validation error on the input payload."},
        429: {"description": "Rate limit exceeded (30 req/min per IP)."},
        500: {"description": "Internal processing error."},
    },
)
async def demo_normalize(
    payload: DemoRequest,
    request: Request,
) -> SingleTransactionResponse:
    """
    Public demo endpoint — no API key required.

    Uses the same ``normalize_transactions`` pipeline as the authenticated
    ``/v1/normalize/transaction`` endpoint.  No usage logging or billing
    events are fired.
    """
    # Rate-limit by client IP.
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    try:
        results: List[NormalizedTransaction] = normalize_transactions(
            [payload.transaction]
        )
        return SingleTransactionResponse(data=results[0])

    except Exception as exc:
        logger.exception("Error in demo normalization")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Normalization failed: {str(exc)}",
        ) from exc
