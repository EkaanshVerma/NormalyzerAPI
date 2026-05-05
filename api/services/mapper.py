"""
Static keyword-to-category mapper with dynamic confidence scoring
and Gemini LLM fallback for unmatched transactions.

Confidence scoring logic:
    0.95  — keyword found at the START of the cleaned string (strong signal)
    0.85  — keyword found anywhere in the cleaned string (partial signal)
    0.65  — Gemini LLM fallback produced a result
    0.10  — no match, no fallback available

Transaction type (debit / credit / unknown) is inferred from directional
keywords present in the *original raw string* before cleaning.
"""

import re
from typing import Dict, List, Optional, Tuple

import pandas as pd

from api.core.config import get_settings
from api.models.schemas import ExplainField, NormalizedTransaction, PaymentChannel, TransactionType
from api.services.cleaner import clean_transaction_strings, extract_channel, extract_timestamp
from api.services.gemini_fallback import categorize_with_gemini

# Bump this manually when you add/remove/change keyword mappings.
RULESET_VERSION = "v1.0.0"


# ── CATEGORY MAPPING DICTIONARY ──
# Each key is a lowercase keyword; value is (category, display_name).

KEYWORD_MAP: Dict[str, Tuple[str, str]] = {
    # Food and Beverage
    "zomato": ("Food and Beverage", "Zomato"),
    "eternal limited": ("Food and Beverage", "Zomato"),
    "swiggy": ("Food and Beverage", "Swiggy"),
    "bundl technologies": ("Food and Beverage", "Swiggy"),
    "dominos": ("Food and Beverage", "Domino's Pizza"),
    "domino": ("Food and Beverage", "Domino's Pizza"),
    "mcdonalds": ("Food and Beverage", "McDonald's"),
    "starbucks": ("Food and Beverage", "Starbucks"),
    "kfc": ("Food and Beverage", "KFC"),
    "pizza hut": ("Food and Beverage", "Pizza Hut"),
    "dunzo": ("Food and Beverage", "Dunzo"),
    "blinkit": ("Food and Beverage", "Blinkit"),
    "zepto": ("Food and Beverage", "Zepto"),
    "burger king": ("Food and Beverage", "Burger King"),
    # Subscriptions
    "netflix": ("Subscriptions", "Netflix"),
    "spotify": ("Subscriptions", "Spotify"),
    "hotstar": ("Subscriptions", "Disney+ Hotstar"),
    "prime video": ("Subscriptions", "Amazon Prime Video"),
    "youtube": ("Subscriptions", "YouTube Premium"),
    "apple": ("Subscriptions", "Apple Services"),
    "google one": ("Subscriptions", "Google One"),
    "zee5": ("Subscriptions", "ZEE5"),
    # E-Commerce
    "amazon": ("E-Commerce", "Amazon"),
    "flipkart": ("E-Commerce", "Flipkart"),
    "myntra": ("E-Commerce", "Myntra"),
    "ajio": ("E-Commerce", "AJIO"),
    "meesho": ("E-Commerce", "Meesho"),
    "nykaa": ("E-Commerce", "Nykaa"),
    "snapdeal": ("E-Commerce", "Snapdeal"),
    "croma": ("E-Commerce", "Croma"),
    # Transport
    "uber": ("Transport", "Uber"),
    "ola": ("Transport", "Ola"),
    "rapido": ("Transport", "Rapido"),
    "irctc": ("Transport", "IRCTC"),
    "makemytrip": ("Transport", "MakeMyTrip"),
    "redbus": ("Transport", "redBus"),
    # Utilities
    "airtel": ("Utilities", "Airtel"),
    "jio": ("Utilities", "Jio"),
    "vodafone": ("Utilities", "Vodafone Idea"),
    "bsnl": ("Utilities", "BSNL"),
    "electricity": ("Utilities", "Electricity Board"),
    "bescom": ("Utilities", "BESCOM"),
    "broadband": ("Utilities", "Broadband Provider"),
    # Financial Services
    "groww": ("Financial Services", "Groww"),
    "zerodha": ("Financial Services", "Zerodha"),
    "upstox": ("Financial Services", "Upstox"),
    "mutual fund": ("Financial Services", "Mutual Fund"),
    "insurance": ("Financial Services", "Insurance"),
    "lic": ("Financial Services", "LIC"),
    "emi": ("Financial Services", "EMI Payment"),
    # Wallets
    "paytm": ("Wallet & Payments", "Paytm"),
    "phonepe": ("Wallet & Payments", "PhonePe"),
    "gpay": ("Wallet & Payments", "Google Pay"),
    "google pay": ("Wallet & Payments", "Google Pay"),
    "cred": ("Wallet & Payments", "CRED"),
    "mobikwik": ("Wallet & Payments", "MobiKwik"),
    # Health
    "pharmeasy": ("Health", "PharmEasy"),
    "netmeds": ("Health", "Netmeds"),
    "apollo": ("Health", "Apollo Pharmacy"),
    "hospital": ("Health", "Hospital"),
    # Education
    "udemy": ("Education", "Udemy"),
    "coursera": ("Education", "Coursera"),
    "byjus": ("Education", "BYJU'S"),
    "unacademy": ("Education", "Unacademy"),
    # Government
    "govt": ("Government", "Government"),
    "tax": ("Government", "Tax Payment"),
    "gst": ("Government", "GST Payment"),
    "challan": ("Government", "Challan Payment"),
    # Income
    "salary": ("Income", "Salary"),
    "interest": ("Income", "Interest Income"),
    "dividend": ("Income", "Dividend"),
    "cashback": ("Income", "Cashback"),
    "refund": ("Income", "Refund"),
    # Fuel
    "petrol": ("Fuel", "Petrol Pump"),
    "iocl": ("Fuel", "Indian Oil"),
    "bpcl": ("Fuel", "Bharat Petroleum"),
    "shell": ("Fuel", "Shell"),
    # Housing
    "rent": ("Housing", "Rent Payment"),
    "maintenance": ("Housing", "Society Maintenance"),
    "nobroker": ("Housing", "NoBroker"),
}

# Credit / Debit keyword patterns applied to the RAW string
_CREDIT_KW = re.compile(
    r"\b(credited|credit|received|cr|refund|cashback|salary|"
    r"stipend|interest|dividend|reversal|inward)\b",
    re.IGNORECASE,
)
_DEBIT_KW = re.compile(
    r"\b(debited|debit|paid|dr|purchase|payment|bought|spent|"
    r"withdrawn|withdrawal|outward|emi)\b",
    re.IGNORECASE,
)

# Reversal indicators — applied to the RAW string.
_REVERSAL_KW = re.compile(
    r"\b(refund|rev|reversal|reversed|chargeback|dispute|cancelled|canceled)\b",
    re.IGNORECASE,
)

# Partial / split payment indicators — applied to the RAW string.
_PARTIAL_KW = re.compile(
    r"\b(split|part|partial|instalment|installment|emi\s*\d)\b",
    re.IGNORECASE,
)


def _infer_type(raw: str) -> TransactionType:
    """Infer debit/credit from directional keywords in the raw string."""
    has_cr = bool(_CREDIT_KW.search(raw))
    has_dr = bool(_DEBIT_KW.search(raw))
    if has_cr and not has_dr:
        return TransactionType.CREDIT
    if has_dr and not has_cr:
        return TransactionType.DEBIT
    if has_cr and has_dr:
        return TransactionType.CREDIT  # credit wins on ambiguity (e.g., refund)
    return TransactionType.UNKNOWN


def _match(cleaned: str) -> Tuple[str, str, float, Optional[str]]:
    """
    Match against the keyword map with position-aware confidence scoring.

    Returns:
        (category, merchant, confidence_score, matched_keyword)
        0.95 if keyword appears at string start; 0.85 otherwise.
        matched_keyword is the dict key that fired (for the explain rule).
    """
    for kw, (cat, merch) in KEYWORD_MAP.items():
        if kw in cleaned:
            # Higher confidence when keyword leads the cleaned string.
            confidence = 0.95 if cleaned.startswith(kw) else 0.85
            return cat, merch, confidence, kw

    return "", "", 0.0, None  # sentinel — triggers fallback


def normalize_transactions(
    raw_strings: List[str],
    use_gemini_fallback: bool = True,
) -> List[NormalizedTransaction]:
    """
    End-to-end normalization pipeline.

    1. Extract channels and timestamps from raw strings.
    2. Clean all strings via the Pandas pipeline.
    3. Match each cleaned string against the keyword map.
    4. For unmatched strings, attempt Gemini LLM fallback.
    5. Infer transaction type from the original raw string.
    6. Return NormalizedTransaction objects with all metadata.

    Args:
        raw_strings:          List of raw transaction description strings.
        use_gemini_fallback:  Whether to invoke the Gemini API for unmatched strings.

    Returns:
        A list of NormalizedTransaction Pydantic models.
    """
    cleaned_series: pd.Series = clean_transaction_strings(raw_strings)
    settings = get_settings()

    results: List[NormalizedTransaction] = []
    for raw, cleaned in zip(raw_strings, cleaned_series):
        # ── Metadata extraction (from raw, before cleaning) ──
        channel = extract_channel(raw)
        timestamp = extract_timestamp(raw)
        tx_type = _infer_type(raw)

        # ── Category matching ──
        cat, merch, conf, matched_kw = _match(cleaned)

        if conf > 0.0:
            # Keyword match path.
            explain = ExplainField(
                path="keyword_match",
                rule=f"{matched_kw} \u2192 {cat}",
                model=None,
                confidence=conf,
                ruleset_version=RULESET_VERSION,
            )
        elif use_gemini_fallback:
            # No keyword match — try Gemini fallback.
            gemini_result = categorize_with_gemini(cleaned)
            if gemini_result:
                cat, merch, conf = gemini_result
                explain = ExplainField(
                    path="gemini_fallback",
                    rule=None,
                    model=settings.GEMINI_MODEL,
                    confidence=conf,
                    ruleset_version=RULESET_VERSION,
                )
            else:
                # Gemini unavailable or failed — truly unmatched.
                merch = cleaned.strip().title() if cleaned.strip() else "Unknown"
                cat = "Uncategorized"
                explain = ExplainField(
                    path="unmatched",
                    rule=None,
                    model=None,
                    confidence=0.10,
                    ruleset_version=RULESET_VERSION,
                )
        else:
            # Fallback disabled and no keyword match.
            merch = cleaned.strip().title() if cleaned.strip() else "Unknown"
            cat = "Uncategorized"
            explain = ExplainField(
                path="unmatched",
                rule=None,
                model=None,
                confidence=0.10,
                ruleset_version=RULESET_VERSION,
            )

        results.append(
            NormalizedTransaction(
                raw_string=raw,
                clean_merchant=merch,
                category=cat,
                transaction_type=tx_type,
                channel=channel,
                normalized_timestamp=timestamp,
                ruleset_version=RULESET_VERSION,
                is_reversal=bool(_REVERSAL_KW.search(raw)),
                is_partial=bool(_PARTIAL_KW.search(raw)),
                explain=explain,
            )
        )

    return results
