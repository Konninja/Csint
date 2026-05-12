"""
OSINT / CSINT / CLOSINT Intelligence Dashboard
Flask web application for private investors and due diligence professionals.
Deploys on Render free tier. No database needed.
"""

import os
import re
import json
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

from modules.ip_tools import (
    geolocate_ip,
    check_abuseipdb,
    asn_lookup,
    resolve_hostname,
)
from modules.domain_tools import (
    dns_lookup,
    subdomain_enum,
    whois_lookup,
    detect_tech,
)
from modules.email_tools import email_reputation, breach_check
from modules.threat_tools import (
    urlhaus_url_check,
    urlhaus_host_check,
    hackertarget_reverse_ip,
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24).hex())

# API Keys (optional — tools work without them but with reduced functionality)
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
URLHAUS_KEY = os.getenv("URLHAUS_API_KEY", "")
EMAILREP_KEY = os.getenv("EMAILREP_API_KEY", "")


# ============================
# ROUTES
# ============================

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


@app.route("/about")
def about():
    """About page with methodology."""
    return render_template("about.html")


# ============================
# API ENDPOINTS
# ============================

@app.route("/api/ip", methods=["POST"])
def api_ip():
    """IP Intelligence: geolocation + abuse check + ASN."""
    data = request.get_json() or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # Check if it's a domain (resolve to IP)
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if not ip_pattern.match(target):
        resolved = resolve_hostname(target)
        if resolved:
            target = resolved
        else:
            return jsonify({"error": f"Could not resolve hostname: {target}"}), 400

    result = {
        "geolocation": geolocate_ip(target),
        "abuse": check_abuseipdb(target, ABUSEIPDB_KEY),
        "asn": asn_lookup(target),
        "reverse_ip": hackertarget_reverse_ip(target),
    }

    return jsonify(result)


@app.route("/api/dns", methods=["POST"])
def api_dns():
    """DNS Lookup + Subdomain Enumeration."""
    data = request.get_json() or {}
    domain = data.get("target", "").strip().lower()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # Strip protocol if present
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain

    result = {
        "domain": domain,
        "dns_records": dns_lookup(domain),
        "subdomains": subdomain_enum(domain),
        "whois": whois_lookup(domain),
        "tech_stack": detect_tech(domain),
    }

    # URLhaus check if key configured
    if URLHAUS_KEY:
        result["urlhaus"] = urlhaus_host_check(domain, URLHAUS_KEY)

    return jsonify(result)


@app.route("/api/email", methods=["POST"])
def api_email():
    """Email Intelligence: reputation + breach check."""
    data = request.get_json() or {}
    email = data.get("target", "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400

    result = {
        "email": email,
        "reputation": email_reputation(email, EMAILREP_KEY),
        "breaches": breach_check(email),
    }

    return jsonify(result)


@app.route("/api/domain", methods=["POST"])
def api_domain():
    """Domain Intelligence: WHOIS + tech stack + subdomains."""
    data = request.get_json() or {}
    domain = data.get("target", "").strip().lower()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain

    result = {
        "domain": domain,
        "whois": whois_lookup(domain),
        "tech_stack": detect_tech(domain),
        "subdomains": subdomain_enum(domain),
    }

    # URLhaus check
    if URLHAUS_KEY:
        result["urlhaus"] = urlhaus_host_check(domain, URLHAUS_KEY)

    return jsonify(result)


@app.route("/api/all", methods=["POST"])
def api_all():
    """
    Full intelligence sweep on a target.
    Determines target type (IP, domain, email) and runs all relevant tools.
    """
    data = request.get_json() or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    result = {"target": target, "type": "unknown"}

    # Check if email
    if "@" in target:
        result["type"] = "email"
        result["email"] = target
        result["reputation"] = email_reputation(target, EMAILREP_KEY)
        result["breaches"] = breach_check(target)
        domain_part = target.split("@")[1]
        result["domain_info"] = {
            "domain": domain_part,
            "whois": whois_lookup(domain_part),
            "dns": dns_lookup(domain_part),
            "tech": detect_tech(domain_part),
        }

    # Check if IP
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        result["type"] = "ip"
        result["geolocation"] = geolocate_ip(target)
        result["abuse"] = check_abuseipdb(target, ABUSEIPDB_KEY)
        result["asn"] = asn_lookup(target)
        result["reverse_ip"] = hackertarget_reverse_ip(target)
        # Check associated domain
        rd = hackertarget_reverse_ip(target)
        if rd.get("domains"):
            result["associated_domains"] = rd["domains"][:20]

    # Domain
    else:
        if target.startswith("http"):
            target = urlparse(target).hostname or target

        result["type"] = "domain"
        result["domain"] = target
        result["dns_records"] = dns_lookup(target)
        result["subdomains"] = subdomain_enum(target)
        result["whois"] = whois_lookup(target)
        result["tech_stack"] = detect_tech(target)

        # Try to get IP
        ip = resolve_hostname(target)
        if ip:
            result["ip_address"] = ip
            result["geolocation"] = geolocate_ip(ip)
            result["abuse"] = check_abuseipdb(ip, ABUSEIPDB_KEY)

        # URLhaus
        if URLHAUS_KEY:
            result["urlhaus"] = urlhaus_host_check(target, URLHAUS_KEY)

    return jsonify(result)


@app.route("/api/raw/<tool>", methods=["POST"])
def api_raw(tool):
    """
    Raw endpoint for individual tools.
    Returns the unprocessed JSON directly from the API.
    """
    data = request.get_json() or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    tool_map = {
        "geolocate": lambda: geolocate_ip(target),
        "dns": lambda: dns_lookup(target),
        "subdomains": lambda: subdomain_enum(target),
        "whois": lambda: whois_lookup(target),
        "emailrep": lambda: email_reputation(target, EMAILREP_KEY),
        "breaches": lambda: breach_check(target),
        "asn": lambda: asn_lookup(target),
        "abuseipdb": lambda: check_abuseipdb(target, ABUSEIPDB_KEY),
        "tech": lambda: detect_tech(target),
        "reverseip": lambda: hackertarget_reverse_ip(target),
        "urlhaus": lambda: urlhaus_host_check(target, URLHAUS_KEY) if URLHAUS_KEY else {"note": "No key"},
    }

    func = tool_map.get(tool)
    if not func:
        return jsonify({"error": f"Unknown tool: {tool}"}), 400

    return jsonify(func())


# ============================
# ENTRY POINT
# ============================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
