"""
Threat Intelligence Tools (CSINT + CLOSINT)
- URL/Domain Threat Check via URLhaus (free key required)
- HackerTarget reverse IP/DNS (free, no key, 50/day)
- URLScan.io Search (free, no key for public search)
- AlienVault OTX Threat Feed Check (free, no key for basic)
- PhishTank-style URL check via public blocklists
"""

import requests
from typing import Dict
from urllib.parse import urlparse


def urlhaus_url_check(url: str, api_key: str = "") -> Dict:
    """Check a URL/domain against URLhaus malware database. Requires free Auth-Key."""
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
    """Check a hostname/domain against URLhaus. Requires free Auth-Key."""
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
    """Reverse IP/DNS lookup via HackerTarget. Free, no key. 50 queries/day."""
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


def urlscan_search(domain: str) -> Dict:
    """
    Search for a domain in urlscan.io public index.
    Free, no API key required (public search endpoint).
    Returns recent scans of the domain.
    """
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            scans = []
            for r in results:
                page = r.get("page", {})
                task = r.get("task", {})
                scans.append({
                    "uuid": r.get("_id"),
                    "url": task.get("url"),
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "country": page.get("country"),
                    "server": page.get("server"),
                    "status": page.get("status"),
                    "time": task.get("time"),
                    "result_url": r.get("result"),
                    "screenshot_url": r.get("screenshot"),
                })
            return {
                "domain": domain,
                "total": data.get("total", 0),
                "scans": scans,
                "malicious_count": sum(1 for s in scans if s.get("status") and s["status"] < 200 or s["status"] >= 400),
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def alienvault_otx_check(indicator: str, indicator_type: str = "domain") -> Dict:
    """
    Check indicator against AlienVault OTX pulse database.
    Free, no API key required for read-only queries.
    Types: 'domain', 'hostname', 'ip', 'url'
    """
    # Map our types to OTX endpoint types
    type_map = {
        "domain": "domain",
        "hostname": "hostname",
        "ip": "IPv4",
        "ipv6": "IPv6",
        "url": "url",
    }
    otx_type = type_map.get(indicator_type, "domain")

    url = f"https://otx.alienvault.com/api/v1/indicator/{otx_type}/{indicator}/general"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return {
                "indicator": indicator,
                "type": indicator_type,
                "pulse_count": len(pulses),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "description": p.get("description", "")[:200],
                        "tags": p.get("tags", []),
                        "created": p.get("created"),
                        "adversary": p.get("adversary"),
                        "reference": p.get("reference"),
                    }
                    for p in pulses[:10]  # Limit to 10 most recent pulses
                ],
                "malicious": len(pulses) > 0,
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def threatfox_check(ioc: str, ioc_type: str = "domain") -> Dict:
    """
    Check IOC against ThreatFox (abuse.ch) database.
    Free, no API key required for lookups.
    Types: 'domain', 'ip', 'url', 'md5', 'sha256'
    """
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {
        "query": "search_ioc",
        "search_term": ioc,
    }

    try:
        resp = requests.post(url, json=payload, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                threats = data["data"]
                return {
                    "ioc": ioc,
                    "threat_count": len(threats) if isinstance(threats, list) else 1,
                    "threats": threats[:10] if isinstance(threats, list) else [threats],
                    "malicious": True,
                }
            return {
                "ioc": ioc,
                "threat_count": 0,
                "threats": [],
                "malicious": False,
                "note": "No threats found in ThreatFox database",
            }
        return {"error": f"API error: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}
