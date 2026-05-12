"""
Domain Intelligence Tools (OSINT)
- DNS Lookup via Google DNS over HTTPS (free, no key)
- Subdomain Enumeration via crt.sh (free, no key)
- WHOIS/RDAP Lookup via who-dat.as93.net (free, no key)
- Technology Detection via web scraping (free)
- SSL Certificate Analysis via direct TLS connection
- HTTP Security Headers Analysis
- Redirect Chain & Response Metadata
"""

import requests
import json
import ssl
import socket
from typing import Dict, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def dns_lookup(domain: str) -> Dict:
    """
    DNS lookup using Google DNS-over-HTTPS JSON API.
    Free, no API key required. Unlimited.
    Returns A, AAAA, MX, NS, TXT, CNAME, SOA records.
    """
    base = "https://dns.google/resolve"
    record_types = {
        "A": 1, "AAAA": 28, "MX": 15, "NS": 2,
        "TXT": 16, "CNAME": 5, "SOA": 6
    }
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


def ssl_analysis(domain: str) -> Dict:
    """
    SSL/TLS certificate analysis via direct connection.
    Retrieves issuer, subject, validity dates, SANs, and protocol version.
    No API key required.
    """
    result = {
        "domain": domain,
        "has_ssl": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "san": [],
        "protocol": None,
        "self_signed": None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            protocol = s.version()

            result["has_ssl"] = True
            result["protocol"] = protocol

            # Issuer
            if cert.get("issuer"):
                result["issuer"] = dict(cert["issuer"])

            # Subject
            if cert.get("subject"):
                result["subject"] = dict(cert["subject"])

            # Validity
            if cert.get("notBefore"):
                result["valid_from"] = cert["notBefore"]
            if cert.get("notAfter"):
                result["valid_to"] = cert["notAfter"]
                from datetime import datetime
                try:
                    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days = (expiry - datetime.now()).days
                    result["days_remaining"] = days
                except Exception:
                    pass

            # Subject Alternative Names
            for sub in cert.get("subjectAltName", []):
                if sub[0] == "DNS":
                    result["san"].append(sub[1])

            # Check self-signed
            if cert.get("issuer") and cert.get("subject"):
                result["self_signed"] = (dict(cert["issuer"]) == dict(cert["subject"]))

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL cert verification failed: {str(e)[:100]}"
        result["has_ssl"] = True  # Still has SSL, just invalid
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {str(e)[:100]}"
    except socket.timeout:
        result["error"] = "Connection timed out on port 443"
    except ConnectionRefusedError:
        result["error"] = "Connection refused on port 443"
    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def http_headers_analysis(domain: str) -> Dict:
    """
    Analyze HTTP response headers for security configuration.
    Checks for HSTS, CSP, X-Frame-Options, CORS, and more.
    No API key required.
    """
    if not domain.startswith("http"):
        domain = f"https://{domain}"

    result = {
        "url": domain,
        "final_url": None,
        "status_code": None,
        "redirect_chain": [],
        "security_headers": {},
        "server_info": {},
        "response_time_ms": None,
    }

    try:
        start = requests.utils.timeout
        resp = requests.get(
            domain,
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            allow_redirects=True,
        )

        result["status_code"] = resp.status_code
        result["final_url"] = resp.url

        # Redirect chain
        if resp.history:
            for i, r in enumerate(resp.history):
                result["redirect_chain"].append({
                    "step": i + 1,
                    "status": r.status_code,
                    "url": r.url,
                    "location": r.headers.get("Location", ""),
                })

        # Security headers
        headers = resp.headers
        security_checks = {
            "strict-transport-security": headers.get("Strict-Transport-Security"),
            "content-security-policy": headers.get("Content-Security-Policy"),
            "x-frame-options": headers.get("X-Frame-Options"),
            "x-content-type-options": headers.get("X-Content-Type-Options"),
            "x-xss-protection": headers.get("X-XSS-Protection"),
            "referrer-policy": headers.get("Referrer-Policy"),
            "permissions-policy": headers.get("Permissions-Policy"),
            "access-control-allow-origin": headers.get("Access-Control-Allow-Origin"),
            "set-cookie": headers.get("Set-Cookie"),
        }
        result["security_headers"] = {k: v for k, v in security_checks.items() if v}

        # Server info
        result["server_info"] = {
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By"),
            "cdn": headers.get("CDN") or headers.get("X-CDN"),
            "via": headers.get("Via"),
        }
        # Detect CloudFlare
        all_headers = str(headers).lower()
        if "cloudflare" in all_headers:
            result["server_info"]["detected_cdn"] = "Cloudflare"
        elif "akamai" in all_headers:
            result["server_info"]["detected_cdn"] = "Akamai"
        elif "fastly" in all_headers:
            result["server_info"]["detected_cdn"] = "Fastly"
        elif "cloudfront" in all_headers:
            result["server_info"]["detected_cdn"] = "AWS CloudFront"

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL Error: {str(e)[:100]}"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection Error: {str(e)[:100]}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except Exception as e:
        result["error"] = str(e)[:100]

    return result


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
        "title": None,
        "description": None,
        "keywords": [],
        "lang": None,
        "social_links": [],
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

        if "cloudflare" in str(headers).lower():
            result["cdn"] = "Cloudflare"

        # SSL certificate info
        if resp.url.startswith("https"):
            try:
                hostname = urlparse(resp.url).hostname
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                    result["ssl_issuer"] = dict(cert.get("issuer", []))
            except Exception:
                pass

        # HTML analysis via BeautifulSoup
        soup = BeautifulSoup(resp.text, "lxml")

        # Page metadata
        if soup.title and soup.title.string:
            result["title"] = soup.title.string.strip()

        desc_meta = soup.find("meta", attrs={"name": "description"})
        if desc_meta and desc_meta.get("content"):
            result["description"] = desc_meta["content"].strip()

        kw_meta = soup.find("meta", attrs={"name": "keywords"})
        if kw_meta and kw_meta.get("content"):
            result["keywords"] = [k.strip() for k in kw_meta["content"].split(",")]

        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            result["lang"] = html_tag["lang"]

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
            "drupal": "Drupal", "joomla": "Joomla",
            "ruby": "Ruby on Rails", "rails": "Ruby on Rails",
            "express": "Express.js", "flask": "Flask",
            "fastapi": "FastAPI", "svelte": "Svelte",
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
            "amplitude": "Amplitude", "fullstory": "FullStory",
            "mouseflow": "Mouseflow", "crazyegg": "CrazyEgg",
            "linkedin": "LinkedIn Insights", "ads": "Google Ads",
        }

        page_text = str(soup).lower()
        for keyword, analytics in analytics_map.items():
            if keyword in page_text:
                if analytics not in result["analytics"]:
                    result["analytics"].append(analytics)

        # Social links detection
        social_patterns = {
            "twitter.com": "Twitter/X",
            "facebook.com": "Facebook",
            "linkedin.com": "LinkedIn",
            "github.com": "GitHub",
            "youtube.com": "YouTube",
            "instagram.com": "Instagram",
            "tiktok.com": "TikTok",
            "reddit.com": "Reddit",
            "medium.com": "Medium",
        }
        found_socials = set()
        for link in soup.find_all("a", href=True):
            href = link["href"].lower()
            for domain_key, platform in social_patterns.items():
                if domain_key in href:
                    found_socials.add((platform, link["href"]))
        result["social_links"] = [{"platform": p, "url": u} for p, u in found_socials]

    except Exception as e:
        result["error"] = str(e)

    return result
