"""
Gemini LLM fallback for transactions that don't match the static keyword map.

When the keyword mapper returns "Uncategorized", this module sends the cleaned
string to the Gemini API with a structured prompt requesting category and
merchant extraction. The result feeds back into the normalization pipeline.

This is the data flywheel recovery path — unmatched records get a second
chance via LLM, and the results can be used to expand the keyword map.
"""

import json
import logging
from typing import Optional, Tuple

from api.core.config import get_settings

logger = logging.getLogger(__name__)

# Valid categories the LLM is allowed to return — constrained to prevent drift.
VALID_CATEGORIES = [
    "Food and Beverage", "Subscriptions", "E-Commerce", "Transport",
    "Utilities", "Financial Services", "Wallet & Payments", "Health",
    "Education", "Government", "Income", "Fuel", "Housing",
    "Entertainment", "Travel", "Insurance", "Groceries", "Personal Care",
    "Charity", "Other",
]

_SYSTEM_PROMPT = f"""You are a financial transaction categorizer for Indian banking data.
Given a cleaned transaction description, return ONLY a JSON object with:
- "merchant": the merchant or entity name (proper case, e.g., "Zomato")
- "category": one of {json.dumps(VALID_CATEGORIES)}

If you cannot determine the merchant, use the cleaned string in title case.
If you cannot determine the category, use "Other".
Return ONLY the JSON object, no markdown, no explanation."""


def categorize_with_gemini(cleaned_string: str) -> Optional[Tuple[str, str, float]]:
    """
    Call Gemini to categorize an unmatched transaction string.

    Args:
        cleaned_string: The already-cleaned transaction description.

    Returns:
        A tuple of (category, merchant, confidence) or None if Gemini
        is unavailable or the call fails.
    """
    settings = get_settings()

    if not settings.GEMINI_API_KEY:
        logger.debug("GEMINI_API_KEY not set — skipping LLM fallback")
        return None

    try:
        import google.generativeai as genai

        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel(settings.GEMINI_MODEL)

        response = model.generate_content(
            [_SYSTEM_PROMPT, f"Transaction: {cleaned_string}"],
            generation_config=genai.GenerationConfig(
                temperature=0.1,  # Low temp for deterministic output.
                max_output_tokens=150,
            ),
        )

        text = response.text.strip()

        # Strip markdown code fences if the model wraps the JSON.
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

        result = json.loads(text)

        merchant = result.get("merchant", cleaned_string.title())
        category = result.get("category", "Other")

        # Validate category against the allowed list.
        if category not in VALID_CATEGORIES:
            category = "Other"

        # Gemini fallback confidence: 0.65 — better than no match (0.1)
        # but lower than a static keyword hit (0.85–0.95).
        return category, merchant, 0.65

    except json.JSONDecodeError as exc:
        logger.warning("Gemini returned non-JSON response: %s", exc)
        return None
    except Exception as exc:
        logger.error("Gemini fallback failed: %s", exc)
        return None
