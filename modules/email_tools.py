"""
Email Intelligence Tools (OSINT + CSINT)
- Email Reputation via emailrep.io (free, no key for basic, 250/mo with key)
- Breach Check via XposedOrNot (free, no key, unlimited)
"""

import requests
from typing import Dict


def email_reputation(email: str, api_key: str = "") -> Dict:
    """
    Check email reputation via emailrep.io.
    Free tier: no key required for basic lookups (10/day).
    With free API key: 250 queries/month.
    """
    url = f"https://emailrep.io/{email}"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "email": data.get("email"),
                "reputation": data.get("reputation"),
                "suspicious": data.get("suspicious"),
                "references": data.get("references"),
                "details": {
                    "blacklisted": data.get("details", {}).get("blacklisted"),
                    "malicious_activity": data.get("details", {}).get("malicious_activity"),
                    "malicious_activity_frequency": data.get("details", {}).get("malicious_activity_frequency"),
                    "credentials_leaked": data.get("details", {}).get("credentials_leaked"),
                    "credentials_leaked_count": data.get("details", {}).get("credentials_leaked_count"),
                    "first_seen": data.get("details", {}).get("first_seen"),
                    "last_seen": data.get("details", {}).get("last_seen"),
                    "domain_exists": data.get("details", {}).get("domain_exists"),
                    "domain_reputation": data.get("details", {}).get("domain_reputation"),
                    "new_domain": data.get("details", {}).get("new_domain"),
                    "days_since_domain_creation": data.get("details", {}).get("days_since_domain_creation"),
                    "suspicious_tld": data.get("details", {}).get("suspicious_tld"),
                    "spam": data.get("details", {}).get("spam"),
                    "free_provider": data.get("details", {}).get("free_provider"),
                    "disposable": data.get("details", {}).get("disposable"),
                    "deliverability": data.get("details", {}).get("deliverability"),
                    "profiles": data.get("details", {}).get("profiles", []),
                },
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def breach_check(email: str) -> Dict:
    """
    Check email for data breaches via XposedOrNot API.
    Free, no API key required. Unlimited.
    """
    url = f"https://api.xposedornot.com/v1/checkemail/{email}"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "email": data.get("email"),
                "breaches": data.get("breaches", []),
                "total_breaches": data.get("total_breaches", 0),
                "password_count": data.get("password_count", 0),
                "source_urls": data.get("source_urls", []),
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}
