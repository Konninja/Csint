"""
Threat Intelligence Tools (CSINT + CLOSINT)
- URL/Domain Threat Check via URLhaus (free key required)
- HackerTarget reverse IP/DNS (free, no key, 50/day)
"""

import requests
from typing import Dict


def urlhaus_url_check(url: str, api_key: str = "") -> Dict:
    """
    Check a URL/domain against URLhaus malware database.
    Requires free Auth-Key from auth.abuse.ch.
    """
    if not api_key:
        return {"note": "No URLhaus API key configured"}

    headers = {"Auth-Key": api_key}
    payload = {"url": url}

    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers=headers,
            data=payload,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "query_status": data.get("query_status"),
                "url": data.get("url"),
                "urlhaus_reference": data.get("urlhaus_reference"),
                "threat": data.get("threat"),
                "tags": data.get("tags", []),
                "payloads": data.get("payloads", []),
                "host": data.get("host"),
                "date_added": data.get("date_added"),
                "reporter": data.get("reporter"),
                "url_status": data.get("url_status"),
                "last_online": data.get("last_online"),
            }
        return {"error": f"API error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def urlhaus_host_check(host: str, api_key: str = "") -> Dict:
    """
    Check a hostname/domain against URLhaus.
    Requires free Auth-Key from auth.abuse.ch.
    """
    if not api_key:
        return {"note": "No URLhaus API key configured"}

    headers = {"Auth-Key": api_key}
    payload = {"host": host}

    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers=headers,
            data=payload,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "query_status": data.get("query_status"),
                "host": data.get("host"),
                "url_count": data.get("url_count"),
                "urls": data.get("urls", []),
            }
        return {"error": f"API error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def hackertarget_reverse_ip(ip: str) -> Dict:
    """
    Reverse IP/DNS lookup via HackerTarget.
    Finds domains hosted on the same IP.
    Free, no key required. 50 queries/day limit.
    """
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            text = resp.text.strip()
            domains = [d.strip() for d in text.split("\n") if d.strip()]
            return {
                "ip": ip,
                "domains": domains,
                "count": len(domains),
                "raw": text,
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}
