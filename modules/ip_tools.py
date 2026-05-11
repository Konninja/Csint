"""
IP Intelligence Tools (OSINT + CSINT)
- IP Geolocation via ip-api.com (free, no key)
- IP Abuse Check via AbuseIPDB (free key required)
- ASN Lookup via HackerTarget (free, no key, 50/day)
"""

import requests
import socket
from typing import Dict, Optional


def geolocate_ip(ip: str) -> Dict:
    """
    Get IP geolocation data from ip-api.com.
    Free, no API key required. 45 requests/min limit.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "ip": data.get("query"),
                "continent": data.get("continent"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "asn_name": data.get("asname"),
                "reverse_dns": data.get("reverse"),
                "is_proxy": data.get("proxy"),
                "is_hosting": data.get("hosting"),
                "is_mobile": data.get("mobile"),
                "currency": data.get("currency"),
            }
        return {"error": data.get("message", "Lookup failed")}
    except Exception as e:
        return {"error": str(e)}


def check_abuseipdb(ip: str, api_key: str = "") -> Dict:
    """
    Check IP against AbuseIPDB blacklist.
    Requires free API key from abuseipdb.com.
    Returns abuse confidence score and reports.
    """
    if not api_key:
        return {"note": "No AbuseIPDB API key configured", "abuse_confidence_score": 0}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "ip": data.get("ipAddress"),
                "is_public": data.get("isPublic"),
                "is_whitelisted": data.get("isWhitelisted"),
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "total_reports": data.get("totalReports"),
                "last_reported_at": data.get("lastReportedAt"),
                "reports": data.get("reports", []),
            }
        return {"error": f"API error: {resp.status_code}", "abuse_confidence_score": 0}
    except Exception as e:
        return {"error": str(e), "abuse_confidence_score": 0}


def asn_lookup(target: str) -> Dict:
    """
    ASN lookup via HackerTarget.
    Free, no key required. 50 queries/day limit.
    Accepts IP or ASN number.
    """
    url = f"https://api.hackertarget.com/aslookup/?q={target}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            text = resp.text.strip()
            lines = [l.strip() for l in text.split("\n") if l.strip()]
            result = {"raw": text, "lines": lines}
            # Parse first line for quick reference
            if lines:
                result["summary"] = lines[0]
            return result
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def resolve_hostname(hostname: str) -> Optional[str]:
    """Simple DNS resolution to get IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
