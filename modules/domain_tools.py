"""
Domain Intelligence Tools (OSINT)
- DNS Lookup via Google DNS over HTTPS (free, no key)
- Subdomain Enumeration via crt.sh (free, no key)
- WHOIS/RDAP Lookup via who-dat.as93.net (free, no key)
- Technology Detection via web scraping (free)
"""

import requests
import json
from typing import Dict, List
from urllib.parse import urlparse


def dns_lookup(domain: str) -> Dict:
    """
    DNS lookup using Google DNS-over-HTTPS JSON API.
    Free, no API key required. Unlimited.
    Returns A, AAAA, MX, NS, TXT, CNAME records.
    """
    base = "https://dns.google/resolve"
    record_types = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5}
    results = {}

    for rtype, rtype_num in record_types.items():
        try:
            resp = requests.get(
                base,
                params={"name": domain, "type": rtype_num},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                records = []
                for ans in answers:
                    records.append({
                        "name": ans.get("name"),
                        "type": rtype,
                        "ttl": ans.get("TTL"),
                        "data": ans.get("data"),
                    })
                if records:
                    results[rtype] = records
        except Exception:
            pass

    return results


def subdomain_enum(domain: str) -> List[str]:
    """
    Enumerate subdomains via crt.sh Certificate Transparency logs.
    Free, no API key required.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.add(sub)
            return sorted(subdomains)
        return []
    except Exception:
        return []


def whois_lookup(domain: str) -> Dict:
    """
    WHOIS/RDAP lookup using who-dat.as93.net.
    Free, no API key, no CORS issues.
    """
    url = f"https://who-dat.as93.net/{domain}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def detect_tech(domain: str) -> Dict:
    """
    Basic technology detection by analyzing HTTP response headers
    and HTML meta tags. Free, no API key.
    """
    if not domain.startswith("http"):
        domain = f"https://{domain}"

    result = {
        "server": None,
        "powered_by": None,
        "cms": None,
        "frameworks": [],
        "analytics": [],
        "cdn": None,
        "ssl_issuer": None,
    }

    try:
        resp = requests.get(domain, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

        # Headers
        headers = resp.headers
        result["server"] = headers.get("Server")
        result["powered_by"] = headers.get("X-Powered-By")
        result["cdn"] = headers.get("CDN") or headers.get("X-CDN")

        # Check for Cloudflare
        if "cloudflare" in str(headers).lower():
            result["cdn"] = "Cloudflare"

        # SSL certificate info
        if resp.url.startswith("https"):
            try:
                import ssl
                import socket
                hostname = urlparse(resp.url).hostname
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                    result["ssl_issuer"] = dict(cert.get("issuer", []))
            except Exception:
                pass

        # HTML meta / scripts
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "lxml")

        # Generator meta tag
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            result["cms"] = gen["content"]

        # Script sources for framework detection
        scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
        all_scripts = " ".join(scripts).lower()

        framework_map = {
            "react": "React", "reactjs": "React", "next": "Next.js",
            "vue": "Vue.js", "nuxt": "Nuxt.js",
            "angular": "Angular", "jquery": "jQuery",
            "bootstrap": "Bootstrap", "tailwind": "Tailwind CSS",
            "django": "Django", "laravel": "Laravel",
            "wordpress": "WordPress", "wp-": "WordPress",
            "shopify": "Shopify", "squarespace": "Squarespace",
            "wix": "Wix", "webflow": "Webflow",
        }

        for keyword, framework in framework_map.items():
            if keyword in all_scripts:
                if framework not in result["frameworks"]:
                    result["frameworks"].append(framework)

        # Analytics detection
        analytics_map = {
            "gtag": "Google Analytics", "google-analytics": "Google Analytics",
            "ga.js": "Google Analytics", "fbevents": "Facebook Pixel",
            "fbq": "Facebook Pixel", "hotjar": "Hotjar",
            "clarity": "Microsoft Clarity", "mixpanel": "Mixpanel",
            "intercom": "Intercom", "hubspot": "HubSpot",
            "optimizely": "Optimizely", "segment": "Segment",
        }

        page_text = str(soup).lower()
        for keyword, analytics in analytics_map.items():
            if keyword in page_text:
                if analytics not in result["analytics"]:
                    result["analytics"].append(analytics)

    except Exception as e:
        result["error"] = str(e)

    return result
