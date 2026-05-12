"""
Social Media & Profile Intelligence Tools (OSINT)
- Username search across platforms
- Email-to-Profile lookup (via emailrep.io integration)
- Social presence analysis
"""

import requests
from typing import Dict, List

# Common social platforms and their profile URL patterns
SOCIAL_PLATFORMS = {
    "Twitter/X": "https://x.com/{username}",
    "Twitter": "https://twitter.com/{username}",
    "GitHub": "https://github.com/{username}",
    "Instagram": "https://instagram.com/{username}",
    "Reddit": "https://reddit.com/user/{username}",
    "LinkedIn": "https://linkedin.com/in/{username}",
    "Facebook": "https://facebook.com/{username}",
    "YouTube": "https://youtube.com/@{username}",
    "TikTok": "https://tiktok.com/@{username}",
    "Pinterest": "https://pinterest.com/{username}",
    "Medium": "https://medium.com/@{username}",
    "Dev.to": "https://dev.to/{username}",
    "Twitch": "https://twitch.tv/{username}",
    "Telegram": "https://t.me/{username}",
    "WhatsApp": "https://wa.me/{username}",
    "Snapchat": "https://snapchat.com/add/{username}",
    "Mastodon": "https://mastodon.social/@{username}",
    "Keybase": "https://keybase.io/{username}",
    "HackerNews": "https://news.ycombinator.com/user?id={username}",
    "ProductHunt": "https://producthunt.com/@{username}",
    "Behance": "https://behance.net/{username}",
    "Dribbble": "https://dribbble.com/{username}",
    "AngelList": "https://angel.co/u/{username}",
    "Crunchbase": "https://crunchbase.com/person/{username}",
    "About.me": "https://about.me/{username}",
    "Linktree": "https://linktr.ee/{username}",
}


def username_search(username: str) -> Dict:
    """
    Search for a username across multiple social media platforms.
    Uses HTTP HEAD/GET to check if profile exists.
    No API key required.
    """
    results = []

    for platform, url_pattern in SOCIAL_PLATFORMS.items():
        profile_url = url_pattern.format(username=username)
        try:
            resp = requests.get(
                profile_url,
                timeout=8,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
                allow_redirects=True,
            )
            status = resp.status_code
            exists = status == 200

            results.append({
                "platform": platform,
                "url": profile_url,
                "exists": exists,
                "status_code": status,
                "final_url": resp.url,
            })
        except requests.exceptions.ConnectionError:
            results.append({
                "platform": platform,
                "url": profile_url,
                "exists": False,
                "status_code": None,
                "error": "Connection error",
            })
        except requests.exceptions.Timeout:
            results.append({
                "platform": platform,
                "url": profile_url,
                "exists": False,
                "status_code": None,
                "error": "Timeout",
            })
        except Exception as e:
            results.append({
                "platform": platform,
                "url": profile_url,
                "exists": False,
                "status_code": None,
                "error": str(e)[:50],
            })

    found = [r for r in results if r.get("exists")]
    return {
        "username": username,
        "platforms_checked": len(results),
        "profiles_found": len(found),
        "results": results,
        "found_profiles": found,
    }


def social_from_domain(domain: str) -> Dict:
    """
    Discover social media links associated with a domain.
    Scrapes the website for social media profile links.
    No API key required.
    """
    if not domain.startswith("http"):
        domain = f"https://{domain}"

    result = {
        "domain": domain,
        "social_links": [],
        "email_contacts": [],
    }

    social_patterns = {
        "twitter.com": "Twitter/X",
        "x.com": "Twitter/X",
        "facebook.com": "Facebook",
        "linkedin.com": "LinkedIn",
        "github.com": "GitHub",
        "youtube.com": "YouTube",
        "instagram.com": "Instagram",
        "tiktok.com": "TikTok",
        "reddit.com": "Reddit",
        "medium.com": "Medium",
        "dev.to": "Dev.to",
        "twitch.tv": "Twitch",
        "pinterest.com": "Pinterest",
        "snapchat.com": "Snapchat",
        "telegram.org": "Telegram",
        "t.me": "Telegram",
        "whatsapp.com": "WhatsApp",
    }

    try:
        resp = requests.get(
            domain,
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        )

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "lxml")

        found_links = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            href_lower = href.lower()

            for domain_key, platform in social_patterns.items():
                if domain_key in href_lower:
                    found_links.add((platform, href))

        result["social_links"] = [
            {"platform": p, "url": u} for p, u in sorted(found_links)
        ]

        # Extract mailto links
        mailto_links = []
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.startswith("mailto:"):
                email = href.replace("mailto:", "").split("?")[0]
                mailto_links.append(email)

        # Also scrape for email patterns in text
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        found_emails = set(re.findall(email_pattern, resp.text))
        for email in found_emails:
            if email not in mailto_links:
                mailto_links.append(email)

        result["email_contacts"] = mailto_links[:20]  # Limit to 20

    except Exception as e:
        result["error"] = str(e)[:100]

    return result


import re
