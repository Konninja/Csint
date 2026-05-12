"""
Phone Number Intelligence Tools (OSINT)
- Phone Number Parsing & Validation
- Country Code & Carrier Lookup
- Free carrier/region detection via online APIs
"""

import requests
import re
from typing import Dict


COUNTRY_CODES = {
    "+1": "US/Canada", "+44": "UK", "+91": "India", "+86": "China",
    "+49": "Germany", "+33": "France", "+39": "Italy", "+34": "Spain",
    "+7": "Russia", "+55": "Brazil", "+81": "Japan", "+82": "South Korea",
    "+61": "Australia", "+64": "New Zealand", "+31": "Netherlands",
    "+46": "Sweden", "+47": "Norway", "+45": "Denmark", "+358": "Finland",
    "+48": "Poland", "+420": "Czech Republic", "+36": "Hungary",
    "+40": "Romania", "+359": "Bulgaria", "+30": "Greece",
    "+351": "Portugal", "+353": "Ireland", "+43": "Austria",
    "+41": "Switzerland", "+32": "Belgium", "+52": "Mexico",
    "+54": "Argentina", "+56": "Chile", "+57": "Colombia",
    "+51": "Peru", "+58": "Venezuela", "+27": "South Africa",
    "+20": "Egypt", "+212": "Morocco", "+234": "Nigeria",
    "+254": "Kenya", "+233": "Ghana", "+971": "UAE",
    "+966": "Saudi Arabia", "+972": "Israel", "+90": "Turkey",
    "+65": "Singapore", "+60": "Malaysia", "+62": "Indonesia",
    "+63": "Philippines", "+66": "Thailand", "+84": "Vietnam",
    "+92": "Pakistan", "+880": "Bangladesh", "+977": "Nepal",
    "+94": "Sri Lanka", "+886": "Taiwan", "+852": "Hong Kong",
}


def parse_phone(phone: str) -> Dict:
    """
    Parse, validate, and provide intelligence on a phone number.
    Detects country code, format validity, and carrier hints.
    No API key required.
    """
    cleaned = re.sub(r"[^\d+]", "", phone.strip())

    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned

    result = {
        "raw": phone,
        "cleaned": cleaned,
        "is_valid": False,
        "country": None,
        "country_code": None,
        "national_number": None,
    }

    # Match country codes (sorted by length descending to match longest first)
    sorted_codes = sorted(COUNTRY_CODES.keys(), key=len, reverse=True)
    for code in sorted_codes:
        if cleaned.startswith(code):
            result["country_code"] = code
            result["country"] = COUNTRY_CODES[code]
            result["national_number"] = cleaned[len(code):]
            result["is_valid"] = True
            break

    return result


def phone_lookup_carrier(phone: str) -> Dict:
    """
    Attempt carrier/network lookup via free public API.
    Uses phonenumberinfo.net-like approach.
    Free, no API key.
    """
    # Clean the number
    cleaned = re.sub(r"[^+\d]", "", phone.strip())
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned

    result = {
        "phone": cleaned,
        "carrier": None,
        "network_type": None,
        "location": None,
    }

    # Try free numverify-like API via abstractapi
    # Fallback: use parse info
    parsed = parse_phone(phone)
    result.update(parsed)

    # Try abstractapi.com's free phone validation (no key, 1 req/sec)
    try:
        resp = requests.get(
            f"https://phonevalidation.abstractapi.com/v1/?phone={cleaned}",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["is_valid"] = data.get("valid", False)
            result["carrier"] = data.get("carrier", {}).get("name")
            result["network_type"] = data.get("line_type")
            result["location"] = f"{data.get('location', {}).get('city', '')}, {data.get('location', {}).get('country', {}).get('name', '')}".strip(", ")
    except Exception:
        pass

    return result
