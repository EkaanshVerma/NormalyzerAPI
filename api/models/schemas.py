"""
Pydantic v2 validation models for the Financial Data Normalizer API.

Defines strict input/output schemas for single, batch, and CSV transaction
normalization endpoints. All models enforce type coercion and range
constraints to guarantee deterministic, well-typed JSON responses.
"""

from enum import Enum
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class TransactionType(str, Enum):
    """Enumeration of possible transaction directions."""
    DEBIT = "debit"
    CREDIT = "credit"
    UNKNOWN = "unknown"


class PaymentChannel(str, Enum):
    """The payment channel / instrument extracted from the raw string."""
    UPI = "upi"
    NEFT = "neft"
    IMPS = "imps"
    RTGS = "rtgs"
    POS = "pos"
    ATM = "atm"
    NACH = "nach"
    ECS = "ecs"
    CHEQUE = "cheque"
    CARD = "card"
    INTERNET_BANKING = "internet_banking"
    MOBILE_BANKING = "mobile_banking"
    UNKNOWN = "unknown"


# ──────────────────────────────────────────────
# Request Models
# ──────────────────────────────────────────────

class SingleTransactionRequest(BaseModel):
    """
    Accepts a single raw financial transaction string for normalization.

    Example payload:
        {"raw_string": "UPI/ZOMATO/123456789/PAYMENT"}
    """
    raw_string: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="The raw, unprocessed transaction string from a bank statement.",
        examples=["UPI/ZOMATO/123456789/PAYMENT"],
    )

    @field_validator("raw_string")
    @classmethod
    def raw_string_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("raw_string must contain non-whitespace characters")
        return v


class BatchTransactionRequest(BaseModel):
    """
    Accepts a list of raw financial transaction strings for bulk normalization.

    The batch is capped at 500 items per request to prevent abuse and to keep
    response latency predictable under serverless execution limits.

    Example payload:
        {"transactions": ["UPI/ZOMATO/123456789/PAYMENT", "NEFT/SALARY/CR"]}
    """
    transactions: List[str] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="A list of raw transaction strings (max 500 per batch).",
        examples=[["UPI/ZOMATO/123456789/PAYMENT", "NEFT/SALARY/CR"]],
    )

    @field_validator("transactions")
    @classmethod
    def each_string_must_be_valid(cls, v: List[str]) -> List[str]:
        for idx, item in enumerate(v):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"Transaction at index {idx} must be a non-empty string"
                )
            if len(item) > 1024:
                raise ValueError(
                    f"Transaction at index {idx} exceeds 1024 character limit"
                )
        return v


# ──────────────────────────────────────────────
# Response Models
# ──────────────────────────────────────────────

class ExplainField(BaseModel):
    """
    Explains exactly how a transaction was categorized.

    Agents can inspect this to understand the classification path,
    which ruleset version produced it, and how confident the result is.
    """
    path: Literal["keyword_match", "gemini_fallback", "unmatched"] = Field(
        ...,
        description="The classification path taken: keyword_match, gemini_fallback, or unmatched.",
    )
    rule: Optional[str] = Field(
        None,
        description="The keyword rule that fired, e.g. 'zomato → Food and Beverage'. None for Gemini/unmatched.",
    )
    model: Optional[str] = Field(
        None,
        description="The LLM model used, e.g. 'gemini-2.0-flash'. None for keyword_match/unmatched.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score: 0.95 (keyword start), 0.85 (keyword found), 0.65 (Gemini), 0.10 (unmatched).",
    )
    ruleset_version: str = Field(
        ...,
        description="Version of the keyword ruleset that was active when this result was produced.",
    )


class NormalizedTransaction(BaseModel):
    """
    The canonical normalized output for a single transaction.

    Fields:
        raw_string:            The original input, echoed back for traceability.
        clean_merchant:        The cleaned, human-readable merchant or entity name.
        category:              A standardized spending category.
        transaction_type:      Whether the transaction is a debit, credit, or unknown.
        channel:               Payment channel extracted from the raw string.
        normalized_timestamp:  ISO-8601 timestamp parsed from the raw string, if found.
        ruleset_version:       Version of the keyword ruleset used for classification.
        explain:               Nested object explaining the classification path and confidence.
    """
    raw_string: str = Field(
        ...,
        description="The original raw transaction string.",
    )
    clean_merchant: str = Field(
        ...,
        description="Cleaned and standardized merchant name.",
    )
    category: str = Field(
        ...,
        description="Standardized spending category.",
    )
    transaction_type: TransactionType = Field(
        ...,
        description="Direction of the transaction: debit, credit, or unknown.",
    )
    channel: PaymentChannel = Field(
        ...,
        description="Payment channel / instrument (UPI, NEFT, POS, etc.).",
    )
    normalized_timestamp: Optional[str] = Field(
        None,
        description="ISO-8601 timestamp extracted from the raw string, or null.",
    )
    ruleset_version: str = Field(
        ...,
        description="Version of the keyword ruleset used for classification.",
    )
    is_reversal: bool = Field(
        False,
        description="True if the transaction is a refund, reversal, or chargeback.",
    )
    is_partial: bool = Field(
        False,
        description="True if the transaction is a split or partial payment.",
    )
    explain: ExplainField = Field(
        ...,
        description="Explains the classification path, matched rule, model used, and confidence.",
    )


class SingleTransactionResponse(BaseModel):
    """Wraps a single normalized transaction result."""
    status: str = "success"
    data: NormalizedTransaction


class BatchTransactionResponse(BaseModel):
    """Wraps a batch of normalized transaction results."""
    status: str = "success"
    count: int = Field(..., description="Number of transactions processed.")
    data: List[NormalizedTransaction]


class HealthResponse(BaseModel):
    """Health-check response payload."""
    status: str = "healthy"
    version: str
    service: str = "financial-data-normalizer"


# ──────────────────────────────────────────────
# API Key Management Models
# ──────────────────────────────────────────────

class GenerateKeyRequest(BaseModel):
    """
    Self-serve key generation request.

    Any developer can provide their email to get an API key.
    A Stripe customer is created automatically.
    """
    email: str = Field(
        ...,
        min_length=3,
        max_length=256,
        description="Developer's email address. Used for Stripe customer creation and key identification.",
        examples=["dev@example.com"],
    )


class GenerateKeyResponse(BaseModel):
    """
    Response after self-serve key generation.

    The raw key is returned ONLY in this response — it cannot be retrieved later.
    """
    status: str = "created"
    api_key: str = Field(..., description="The raw API key. Store it securely — shown only once.")
    key_prefix: str = Field(..., description="The key prefix for identification.")
    email: str
    stripe_customer_id: str = Field("", description="The Stripe Customer ID created for billing.")


class CreateKeyRequest(BaseModel):
    """Admin request body for generating a new API key (legacy/manual)."""
    label: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="A human-readable label for this key (e.g., 'prod-agent-1').",
    )
    stripe_customer_id: str = Field(
        "",
        max_length=256,
        description="Optional Stripe Customer ID to link for metered billing.",
    )


class CreateKeyResponse(BaseModel):
    """
    Response after admin key creation.

    The raw key is returned ONLY in this response — it cannot be retrieved later.
    """
    status: str = "created"
    api_key: str = Field(..., description="The raw API key. Store it securely — shown only once.")
    key_prefix: str = Field(..., description="The key prefix for identification.")
    label: str


class RevokeKeyRequest(BaseModel):
    """Request body for revoking an API key."""
    key_prefix: str = Field(..., description="The prefix of the key to revoke (first 14 chars).")


class KeyInfo(BaseModel):
    """Public info about an API key (never includes the hash or raw key)."""
    id: int
    key_prefix: str
    label: str
    email: str = ""
    stripe_customer_id: str
    is_active: bool
    is_paid: bool = False
    created_at: str
    last_used_at: Optional[str]


class ListKeysResponse(BaseModel):
    """Response listing all API keys."""
    status: str = "success"
    keys: List[KeyInfo]



# ──────────────────────────────────────────────
# CSV Upload Model
# ──────────────────────────────────────────────

class CSVUploadResponse(BaseModel):
    """Response for the CSV upload endpoint."""
    status: str = "success"
    filename: str
    rows_parsed: int
    rows_normalized: int
    column_used: str = Field(..., description="The CSV column that was auto-detected for transaction strings.")
    data: List[NormalizedTransaction]
