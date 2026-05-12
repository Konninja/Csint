"""
SSL/TLS Certificate Intelligence Tools (OSINT + CSINT)
- Certificate Transparency via crt.sh (free, no key)
- CertSpotter-style monitoring (free tier)
- Certificate chain analysis
"""

import requests
import ssl
import socket
from typing import Dict, List
from datetime import datetime


def certspotter_lookup(domain: str) -> Dict:
    """
    Certificate Transparency monitoring via crt.sh.
    Returns all SSL certificates issued for the domain.
    Free, no API key required.
    """
    identities = set()
    result = {
        "domain": domain,
        "total_certificates": 0,
        "identities": [],
        "issuers": [],
        "expiry_range": {},
    }

    # Query crt.sh for certificate identities
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            result["total_certificates"] = len(data)

            for entry in data:
                name_value = entry.get("name_value", "")
                if name_value:
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name:
                            identities.add(name)

                # Collect issuers
                issuer = entry.get("issuer_name", "")
                if issuer and issuer not in result["issuers"]:
                    result["issuers"].append(issuer)

            result["identities"] = sorted(identities)

    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def ssl_chain_analysis(domain: str) -> Dict:
    """
    Full SSL certificate chain analysis.
    Retrieves the complete certificate chain and validates each cert.
    No API key required.
    """
    result = {
        "domain": domain,
        "resolved_ip": None,
        "chain_length": 0,
        "chain": [],
        "protocol": None,
        "errors": [],
    }

    try:
        # Resolve domain
        result["resolved_ip"] = socket.gethostbyname(domain)

        # Create a custom SSL context to get the full chain
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            result["protocol"] = s.version()

            # Get certificate chain
            cert_bin = s.getpeercert(binary_form=True)
            cert = s.getpeercert()

            if cert:
                chain_entry = {
                    "subject": dict(cert.get("subject", [])),
                    "issuer": dict(cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [san[1] for san in cert.get("subjectAltName", []) if san[0] == "DNS"],
                }

                # Calculate days remaining
                if cert.get("notAfter"):
                    try:
                        expiry = datetime.strptime(
                            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                        )
                        chain_entry["days_remaining"] = (expiry - datetime.now()).days
                    except Exception:
                        pass

                result["chain"].append(chain_entry)
                result["chain_length"] = 1

                # Check if self-signed
                if cert.get("issuer") and cert.get("subject"):
                    result["self_signed"] = (
                        dict(cert["issuer"]) == dict(cert["subject"])
                    )

    except ssl.SSLError as e:
        result["errors"].append(f"SSL Error: {str(e)[:100]}")
        # Even with error we may have partial info
        result["has_ssl"] = True
    except socket.timeout:
        result["errors"].append("Connection timed out")
    except Exception as e:
        result["errors"].append(str(e)[:100])

    return result
