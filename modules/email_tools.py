"""
Email Intelligence Tools (OSINT + CSINT)
- Email Reputation via emailrep.io (free, no key for basic, 250/mo with key)
- Breach Check via XposedOrNot (free, no key, unlimited)
- Email Verification via eva.pingutil.com (free, no key, unlimited)
- Disposable Email Detection via built-in domain list
"""

import requests
from typing import Dict

# Common disposable email domains (abbreviated list - real list would be larger)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "trashmail.com", "sharklasers.com",
    "maildrop.cc", "getnada.com", "temp-mail.org", "fakeinbox.com",
    "burnermail.io", "dispostable.com", "mailnesia.com", "spamgourmet.com",
    "guerrillamail.org", "mailcatch.com", "tempemail.net", "mintemail.com",
    "anonaddy.com", "simplelogin.co", "firefox.com", "relay.firefox.com",
}


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


def verify_email(email: str) -> Dict:
    """
    Email verification via eva.pingutil.com.
    Checks if email is deliverable, valid format, and has MX records.
    Free, no API key required. Unlimited.
    """
    url = f"https://eva.pingutil.com/email?id={email}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "email": data.get("email"),
                "valid_format": data.get("valid_format", False),
                "deliverable": data.get("deliverable", "unknown"),
                "disposable": data.get("disposable", False),
                "mx_records": data.get("mx_records", False),
                "mx_record": data.get("mx_record"),
                "smtp_check": data.get("smtp_check", False),
                "catch_all": data.get("catch_all"),
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_disposable(email: str) -> Dict:
    """
    Disposable email detection. Checks if the domain is a known
    temporary/disposable email provider.
    No API key required.
    """
    domain = email.split("@")[1].lower() if "@" in email else email.lower()
    is_disposable = domain in DISPOSABLE_DOMAINS

    return {
        "email": email,
        "domain": domain,
        "is_disposable": is_disposable,
        "note": "Disposable email detected - likely temporary/fake" if is_disposable else "Not a known disposable provider",
    }
