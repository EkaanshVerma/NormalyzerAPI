"""
Vectorized string-cleaning pipeline for raw financial transaction data.

Uses Pandas Series string methods for performance — even a single string
is promoted to a 1-element Series so that the same code path handles both
single and batch requests without branching.

Cleaning steps (in order):
    1. Lowercase the entire string.
    2. Replace common field separators (/, |, \\) with spaces.
    3. Strip banking channel prefixes (UPI, POS, NEFT, IMPS, RTGS, etc.).
    4. Remove date patterns (DD-MM-YYYY, DD/MM/YYYY, DD.MM.YYYY, YYYYMMDD).
    5. Remove long alphanumeric reference/transaction IDs (8+ chars).
    6. Remove standalone short numeric tokens (pure digit groups).
    7. Collapse multiple whitespace into a single space and strip edges.

Also provides:
    - Channel extraction (UPI, NEFT, POS, ATM, etc.)
    - Timestamp extraction and normalization to ISO-8601
"""

import re
from datetime import datetime
from typing import List, Optional, Tuple

import pandas as pd

from api.models.schemas import PaymentChannel


# ──────────────────────────────────────────────
# Pre-compiled regex patterns for performance
# ──────────────────────────────────────────────

# Channel detection — order matters, first match wins.
_CHANNEL_PATTERNS: List[Tuple[re.Pattern, PaymentChannel]] = [
    (re.compile(r"\bUPI\b", re.I), PaymentChannel.UPI),
    (re.compile(r"\bIMPS\b", re.I), PaymentChannel.IMPS),
    (re.compile(r"\bNEFT\b", re.I), PaymentChannel.NEFT),
    (re.compile(r"\bRTGS\b", re.I), PaymentChannel.RTGS),
    (re.compile(r"\bPOS\b", re.I), PaymentChannel.POS),
    (re.compile(r"\bATM\b", re.I), PaymentChannel.ATM),
    (re.compile(r"\bNACH\b", re.I), PaymentChannel.NACH),
    (re.compile(r"\bECS\b", re.I), PaymentChannel.ECS),
    (re.compile(r"\b(CHQ|CHEQUE)\b", re.I), PaymentChannel.CHEQUE),
    (re.compile(r"\b(VISA|MAST|RUPAY|CARD)\b", re.I), PaymentChannel.CARD),
    (re.compile(r"\b(INB|INET|INTERNET)\b", re.I), PaymentChannel.INTERNET_BANKING),
    (re.compile(r"\b(MOB|MOBILE)\b", re.I), PaymentChannel.MOBILE_BANKING),
]

# Date patterns for extraction — captures the date string.
# Supports: DD-MM-YYYY, DD/MM/YYYY, DD.MM.YYYY, DD-MM-YY, and compact YYYYMMDD.
_DATE_EXTRACT = re.compile(
    r"\b(\d{2}[-/.]\d{2}[-/.]\d{2,4})\b|\b(\d{8})\b"
)

# Date formats to try when parsing extracted date strings.
_DATE_FORMATS = [
    "%d-%m-%Y", "%d/%m/%Y", "%d.%m.%Y",
    "%d-%m-%y", "%d/%m/%y", "%d.%m.%y",
    "%Y%m%d",
]

# Common banking channel prefixes found in Indian bank statements.
_PREFIX_PATTERN = re.compile(
    r"\b(upi|pos|neft|imps|rtgs|nach|ach|ecs|cms|mmt|mob\s*trfr?|"
    r"inb|inet|atm|cdm|clg|chq|dd|trf|transfer|payment|paid to|"
    r"paid by|received from|dr|cr)\b",
    re.IGNORECASE,
)

# Date patterns for removal during cleaning.
_DATE_REMOVE = re.compile(
    r"\b\d{2}[-/.]\d{2}[-/.]\d{2,4}\b|\b\d{8}\b"
)

# Alphanumeric reference IDs — 8+ chars mixing letters and digits.
_REFID_PATTERN = re.compile(
    r"\b(?=[A-Za-z]*\d)(?=\d*[A-Za-z])[A-Za-z0-9]{8,}\b"
)

# Standalone pure-digit tokens.
_NUMERIC_PATTERN = re.compile(r"\b\d+\b")

# Collapse whitespace.
_MULTI_SPACE = re.compile(r"\s{2,}")


def extract_channel(raw: str) -> PaymentChannel:
    """Detect the payment channel from the raw transaction string."""
    for pattern, channel in _CHANNEL_PATTERNS:
        if pattern.search(raw):
            return channel
    return PaymentChannel.UNKNOWN


def extract_timestamp(raw: str) -> Optional[str]:
    """
    Extract and normalize a date from the raw string to ISO-8601.

    Returns None if no parseable date is found.
    """
    match = _DATE_EXTRACT.search(raw)
    if not match:
        return None

    date_str = match.group(1) or match.group(2)

    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(date_str, fmt)
            # Sanity: reject dates before 2000 or after 2099.
            if 2000 <= dt.year <= 2099:
                return dt.strftime("%Y-%m-%dT00:00:00Z")
        except ValueError:
            continue

    return None


def clean_transaction_strings(raw_strings: List[str]) -> pd.Series:
    """
    Accept a list of raw transaction strings and return a Pandas Series
    of cleaned, normalised merchant-like tokens.

    Args:
        raw_strings: One or more raw transaction description strings.

    Returns:
        A ``pd.Series`` of cleaned strings, index-aligned with the input list.

    Example:
        >>> clean_transaction_strings(["UPI/ZOMATO/123456789/15-04-2025/PAYMENT"])
        0    zomato
        dtype: object
    """
    # Promote to a Pandas Series to leverage vectorised string ops.
    series = pd.Series(raw_strings, dtype="string")

    # Step 1 — lowercase everything for uniform matching downstream.
    series = series.str.lower()

    # Step 2 — replace separators (/, |, \) with spaces so that
    # "UPI/ZOMATO/12345" becomes "upi zomato 12345".
    series = series.str.replace(r"[/|\\]", " ", regex=True)

    # Step 3 — remove banking channel prefixes.
    series = series.apply(lambda s: _PREFIX_PATTERN.sub(" ", s) if pd.notna(s) else s)

    # Step 4 — strip date strings that carry no merchant information.
    series = series.apply(lambda s: _DATE_REMOVE.sub(" ", s) if pd.notna(s) else s)

    # Step 5 — remove long alphanumeric reference IDs.
    series = series.apply(lambda s: _REFID_PATTERN.sub(" ", s) if pd.notna(s) else s)

    # Step 6 — remove standalone numeric tokens.
    series = series.apply(lambda s: _NUMERIC_PATTERN.sub(" ", s) if pd.notna(s) else s)

    # Step 7 — collapse residual whitespace and strip edges.
    series = series.apply(lambda s: _MULTI_SPACE.sub(" ", s).strip() if pd.notna(s) else s)

    return series
