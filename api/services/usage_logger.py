"""
Usage event logging service.

Records per-request metrics to the usage_events table in Supabase for
auditing, rate analysis, and the data flywheel (tracking which records
hit the LLM fallback so the keyword map can be expanded over time).
"""

import logging
from typing import List

from api.core.database import insert_usage_event
from api.models.schemas import NormalizedTransaction

logger = logging.getLogger(__name__)


def log_usage_event(
    api_key_id: int,
    endpoint: str,
    results: List[NormalizedTransaction],
) -> None:
    """
    Insert a usage event row summarizing a normalization request.

    Args:
        api_key_id:  The database ID of the API key that made the request.
        endpoint:    The endpoint path (e.g., "/v1/normalize/batch").
        results:     The list of normalized results (used to compute counters).
    """
    total = len(results)
    fallback_count = sum(1 for r in results if r.explain.path == "gemini_fallback")
    matched_count = sum(1 for r in results if r.explain.path == "keyword_match")
    unmatched_count = sum(1 for r in results if r.explain.path == "unmatched")

    insert_usage_event(
        api_key_id=api_key_id,
        endpoint=endpoint,
        transaction_count=total,
        matched_count=matched_count,
        fallback_count=fallback_count,
        unmatched_count=unmatched_count,
    )

    logger.info(
        "Usage logged: key_id=%d endpoint=%s total=%d matched=%d fallback=%d unmatched=%d",
        api_key_id, endpoint, total, matched_count, fallback_count, unmatched_count,
    )
