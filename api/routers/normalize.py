"""
API router for transaction normalization endpoints.

Provides:
    POST /v1/normalize/transaction  — Normalize a single transaction string.
    POST /v1/normalize/batch        — Normalize a batch of up to 500 strings.
    POST /v1/normalize/csv          — Upload a CSV bank statement for normalization.
"""

import io
import logging
from typing import List

import pandas as pd
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status

from api.core.security import verify_api_token
from api.models.schemas import (
    BatchTransactionRequest,
    BatchTransactionResponse,
    CSVUploadResponse,
    NormalizedTransaction,
    SingleTransactionRequest,
    SingleTransactionResponse,
)
from api.services.billing import report_usage
from api.services.mapper import normalize_transactions
from api.services.usage_logger import log_usage_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/normalize", tags=["Normalization"])

# Column names commonly used in Indian bank statement CSVs.
# We auto-detect by checking which one exists (case-insensitive).
_CANDIDATE_COLUMNS = [
    "description", "narration", "transaction_description",
    "transaction description", "particulars", "details",
    "remark", "remarks", "transaction_remarks",
    "transaction remarks", "txn_description", "txn description",
    "transaction_details", "transaction details",
]


@router.post(
    "/transaction",
    response_model=SingleTransactionResponse,
    status_code=status.HTTP_200_OK,
    summary="Normalize a single transaction",
    description=(
        "Accepts a single raw financial transaction string and returns a "
        "strictly typed JSON object with the cleaned merchant name, "
        "spending category, payment channel, normalized timestamp, "
        "transaction direction, confidence score, and fallback flag."
    ),
    responses={
        400: {"description": "Malformed request body."},
        401: {"description": "Missing or invalid API key."},
        422: {"description": "Validation error on the input payload."},
        500: {"description": "Internal processing error."},
    },
)
async def normalize_single(
    payload: SingleTransactionRequest,
    background_tasks: BackgroundTasks,
    key_record: dict = Depends(verify_api_token),
) -> SingleTransactionResponse:
    """
    Normalize a single raw transaction string.

    The pipeline cleans the string, extracts channel/timestamp metadata,
    matches against the keyword map (with optional Gemini fallback),
    infers transaction direction, and returns a deterministic result.
    """
    try:
        results: List[NormalizedTransaction] = normalize_transactions(
            [payload.raw_string]
        )

        # Log usage in background.
        background_tasks.add_task(
            log_usage_event,
            api_key_id=key_record["id"],
            endpoint="/v1/normalize/transaction",
            results=results,
        )

        return SingleTransactionResponse(data=results[0])

    except Exception as exc:
        logger.exception("Error normalizing single transaction")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Normalization failed: {str(exc)}",
        ) from exc


@router.post(
    "/batch",
    response_model=BatchTransactionResponse,
    status_code=status.HTTP_200_OK,
    summary="Normalize a batch of transactions",
    description=(
        "Accepts up to 500 raw transaction strings and returns an array "
        "of normalized results. Usage is logged and a Stripe metered "
        "billing event is fired in the background."
    ),
    responses={
        400: {"description": "Malformed request body."},
        401: {"description": "Missing or invalid API key."},
        422: {"description": "Validation error on the input payload."},
        500: {"description": "Internal processing error."},
    },
)
async def normalize_batch(
    payload: BatchTransactionRequest,
    background_tasks: BackgroundTasks,
    key_record: dict = Depends(verify_api_token),
) -> BatchTransactionResponse:
    """
    Normalize a batch of raw transaction strings.

    After processing, background tasks:
      1. Log usage metrics to the usage_events table.
      2. Report the count to Stripe's metered billing API.
    """
    try:
        results: List[NormalizedTransaction] = normalize_transactions(
            payload.transactions
        )

        # Background: usage logging.
        background_tasks.add_task(
            log_usage_event,
            api_key_id=key_record["id"],
            endpoint="/v1/normalize/batch",
            results=results,
        )

        # Background: Stripe billing (uses stripe_customer_id from the key record).
        stripe_cid = key_record.get("stripe_customer_id", "")
        if stripe_cid:
            background_tasks.add_task(
                report_usage,
                customer_id=stripe_cid,
                transaction_count=len(results),
            )

        return BatchTransactionResponse(
            count=len(results),
            data=results,
        )

    except Exception as exc:
        logger.exception("Error normalizing batch transactions")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch normalization failed: {str(exc)}",
        ) from exc


@router.post(
    "/csv",
    response_model=CSVUploadResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload a CSV bank statement",
    description=(
        "Accepts a CSV file upload (bank statement dump), auto-detects the "
        "transaction description column, and normalizes all rows. "
        "Maximum file size: 5 MB, maximum rows: 5000."
    ),
    responses={
        400: {"description": "CSV parsing error or no valid column found."},
        401: {"description": "Missing or invalid API key."},
        413: {"description": "File too large (max 5 MB)."},
        500: {"description": "Internal processing error."},
    },
)
async def normalize_csv(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="CSV file containing transaction data."),
    key_record: dict = Depends(verify_api_token),
) -> CSVUploadResponse:
    """
    Parse a CSV bank statement and normalize all transaction descriptions.

    The endpoint auto-detects the description column by checking against
    a list of common column names used by Indian banks (e.g., "Narration",
    "Description", "Particulars", "Remarks").
    """
    # ── Validate file type ──
    # Accept text/csv, application/csv, text/plain, and application/octet-stream
    # (curl's default). Also allow if the filename ends with .csv.
    allowed_types = {"text/csv", "application/csv", "text/plain", "application/octet-stream"}
    filename_ok = file.filename and file.filename.lower().endswith(".csv")
    content_type_ok = not file.content_type or file.content_type in allowed_types

    if not content_type_ok and not filename_ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Expected a CSV file, got content-type '{file.content_type}'.",
        )

    # ── Read and size-check ──
    try:
        contents = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        ) from exc

    max_size = 5 * 1024 * 1024  # 5 MB
    if len(contents) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds 5 MB limit ({len(contents)} bytes).",
        )

    # ── Parse CSV with Pandas ──
    try:
        df = pd.read_csv(io.BytesIO(contents), dtype=str, keep_default_na=False)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CSV parsing failed: {str(exc)}",
        ) from exc

    if len(df) > 5000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CSV has {len(df)} rows — maximum is 5000.",
        )

    if len(df) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV file is empty.",
        )

    # ── Auto-detect the transaction description column ──
    col_lower_map = {col.lower().strip(): col for col in df.columns}
    detected_col = None

    for candidate in _CANDIDATE_COLUMNS:
        if candidate in col_lower_map:
            detected_col = col_lower_map[candidate]
            break

    if detected_col is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Could not auto-detect a transaction description column. "
                f"Found columns: {list(df.columns)}. "
                f"Expected one of: {_CANDIDATE_COLUMNS}."
            ),
        )

    # ── Extract and normalize ──
    raw_strings = df[detected_col].tolist()
    # Filter out empty strings.
    raw_strings = [s for s in raw_strings if s.strip()]

    if not raw_strings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Column '{detected_col}' contains no non-empty values.",
        )

    try:
        results = normalize_transactions(raw_strings)
    except Exception as exc:
        logger.exception("Error normalizing CSV data")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CSV normalization failed: {str(exc)}",
        ) from exc

    # ── Background tasks ──
    background_tasks.add_task(
        log_usage_event,
        api_key_id=key_record["id"],
        endpoint="/v1/normalize/csv",
        results=results,
    )

    stripe_cid = key_record.get("stripe_customer_id", "")
    if stripe_cid:
        background_tasks.add_task(
            report_usage,
            customer_id=stripe_cid,
            transaction_count=len(results),
        )

    return CSVUploadResponse(
        filename=file.filename or "unknown.csv",
        rows_parsed=len(df),
        rows_normalized=len(results),
        column_used=detected_col,
        data=results,
    )
