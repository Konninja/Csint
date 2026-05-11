# OSINT / CSINT / CLOSINT Intelligence Dashboard

A web-based intelligence gathering dashboard for private investors, due diligence professionals, and corporate security teams. Combines **Open Source Intelligence (OSINT)**, **Closed Source Intelligence (CSINT)** indicators, and **Classified/Closed Intelligence (CLOSINT)** signals into one unified interface.

**Deployable on Render's free tier.** No database required. All primary APIs are free and require no API keys.

![Dashboard Screenshot](screenshot.png)

---

## 🧠 Intelligence Framework

| Type | Definition | Examples in This Tool |
|------|-----------|----------------------|
| **OSINT** | Publicly available data | DNS records, certificate transparency logs, IP geolocation, WHOIS |
| **CSINT** | Commercial/closed-source signals | Email reputation scores, breach databases, threat intelligence feeds |
| **CLOSINT** | Classified/closed indicators | AbuseIPDB blacklists, URLhaus malware URLs, HackerTarget ASN data |

---

## 🔍 Modules

| Module | What It Does | API Used | Auth Required |
|--------|-------------|----------|---------------|
| **IP Intelligence** | Geolocation, ISP, org, ASN | ip-api.com | ❌ None |
| **DNS Lookup** | A, AAAA, MX, NS, TXT, CNAME records | Google DoH | ❌ None |
| **Email Reputation** | Risk score, breach count, domain age | emailrep.io | ❌ None (basic) |
| **Breach Check** | Find data breaches for an email | XposedOrNot | ❌ None |
| **Subdomain Enumeration** | Discover subdomains via SSL certs | crt.sh | ❌ None |
| **ASN / Network Lookup** | ASN owner, IP range, CIDR | HackerTarget | ❌ None (50/day) |
| **Threat Intel (IP)** | Check if IP is malicious | AbuseIPDB | 🔑 Free key |
| **WHOIS / RDAP** | Domain registration details | who-dat.as93.net | ❌ None |
| **URL / Domain Rep** | Check if domain hosts malware | URLhaus | 🔑 Free key |
| **Tech Stack Detection** | Identify website technologies | WhatRuns (web scrape) | ❌ None |

---

## 🚀 Quick Deploy (Render Free Tier)

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/osint-csint-closint-dashboard.git
cd osint-csint-closint-dashboard
