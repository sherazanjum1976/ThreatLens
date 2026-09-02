"""
input_helpers.py
=================
ThreatLens — input validation and source-checking functions.

STRICT ONE-WAY DEPENDENCY
--------------------------
This module has ZERO knowledge of Streamlit, Gemini, or any UI/orchestration
concern. `app.py` imports from this file. This file must NEVER import from
`app.py` (or anything that imports app.py). That is what keeps the
dependency graph a strict one-way arrow: app.py -> input_helpers.py.

EXTENSIBILITY CONTRACT (read this before adding a new source)
---------------------------------------------------------------
To plug in a new intelligence source (e.g. AbuseIPDB, Shodan, URLScan...),
write exactly ONE function in this file with this exact signature:

    def check_<sourcename>(indicator: str, indicator_type: str) -> dict:
        # indicator      -> the cleaned value to look up (IP string, bare
        #                   domain, or full URL — see indicator_type)
        # indicator_type -> one of "IP", "Domain", "URL"
        ...
        return {
            "source":  "<Human-readable source name>",
            "status":  "clean" | "suspicious" | "malicious" | "unknown" | "info" | "error",
            "score":   <int 0-100 or None>,   # optional risk score
            "summary": "<one-line human summary for the results table>",
            "raw":     {<full raw response, shown in the expandable panel>},
        }

Then add ONE line to the SOURCES dict at the bottom of this file:

    SOURCES["MySource"] = check_mysource

No other file needs to change. app.py discovers every source purely by
iterating over SOURCES — it has no source-specific logic at all.
"""

import os
import re
import ipaddress
import base64
from urllib.parse import urlparse

import requests
import whois as pywhois


# ---------------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)


def validate_input(raw_value: str, declared_type: str) -> dict:
    """
    Validate `raw_value` against the `declared_type` the user selected in
    the UI ("IP", "Domain", or "URL"). We validate against the declared
    type (rather than auto-detecting) so the user's explicit choice is
    always respected.

    Returns on success:
        {"valid": True, "type": "IP"/"Domain"/"URL", "value": <cleaned>,
         "host": <bare host, used for WHOIS/domain-style lookups>}

    Returns on failure:
        {"valid": False, "error": "<human-readable reason>"}
    """
    value = (raw_value or "").strip()
    if not value:
        return {"valid": False, "error": "Input cannot be empty."}

    declared_type = (declared_type or "").strip().lower()

    if declared_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return {"valid": False, "error": f"'{value}' is not a valid IP address."}
        return {"valid": True, "type": "IP", "value": value, "host": value}

    if declared_type == "domain":
        candidate = value.lower().rstrip("/")
        if not _DOMAIN_RE.match(candidate):
            return {"valid": False, "error": f"'{value}' is not a valid domain name."}
        return {"valid": True, "type": "Domain", "value": candidate, "host": candidate}

    if declared_type == "url":
        candidate = value if "://" in value else f"http://{value}"
        parsed = urlparse(candidate)
        if not parsed.scheme or not parsed.netloc:
            return {"valid": False, "error": f"'{value}' is not a valid URL."}
        host = parsed.hostname or ""
        if not host:
            return {"valid": False, "error": f"Could not extract a host from '{value}'."}
        return {"valid": True, "type": "URL", "value": candidate, "host": host}

    return {"valid": False, "error": f"Unknown indicator type '{declared_type}'."}


# ---------------------------------------------------------------------------
# SOURCE FUNCTIONS — one function per source
# ---------------------------------------------------------------------------

def check_virustotal(indicator: str, indicator_type: str) -> dict:
    """
    Queries VirusTotal API v3 for an IP, Domain, or URL.
    Expects the env var VT_API_KEY to already be set (app.py sets it from
    the sidebar / st.secrets before calling this).
    """
    source_name = "VirusTotal"
    api_key = os.environ.get("VT_API_KEY", "")

    if not api_key:
        return {
            "source": source_name, "status": "error", "score": None,
            "summary": "No VirusTotal API key configured.",
            "raw": {"error": "missing_api_key"},
        }

    headers = {"x-apikey": api_key}

    try:
        if indicator_type == "IP":
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
                headers=headers, timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return _vt_build_result(source_name, stats, data)

        if indicator_type == "Domain":
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{indicator}",
                headers=headers, timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return _vt_build_result(source_name, stats, data)

        # indicator_type == "URL"
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=15,
        )
        if resp.status_code == 404:
            # VT has never seen this URL — submit it, then read the analysis.
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": indicator}, timeout=15,
            )
            submit.raise_for_status()
            analysis_id = submit.json()["data"]["id"]
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=15,
            )
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats") or attrs.get("last_analysis_stats", {})
        return _vt_build_result(source_name, stats, data)

    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        return {
            "source": source_name, "status": "error", "score": None,
            "summary": f"VirusTotal request failed (HTTP {code}).",
            "raw": {"error": str(e)},
        }
    except Exception as e:
        return {
            "source": source_name, "status": "error", "score": None,
            "summary": "VirusTotal request failed unexpectedly.",
            "raw": {"error": str(e)},
        }


def _vt_build_result(source_name: str, stats: dict, raw_data: dict) -> dict:
    """Shared helper for turning VT's last_analysis_stats into our standard shape."""
    if not stats:
        return {
            "source": source_name, "status": "unknown", "score": None,
            "summary": "VirusTotal has no analysis data for this indicator yet.",
            "raw": raw_data,
        }

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = (malicious + suspicious + harmless + undetected) or 1
    score = round((malicious + suspicious) / total * 100)

    if malicious > 0:
        status = "malicious"
        summary = f"{malicious} security vendor(s) flagged this as malicious."
    elif suspicious > 0:
        status = "suspicious"
        summary = f"{suspicious} security vendor(s) flagged this as suspicious."
    else:
        status = "clean"
        summary = f"No vendors flagged this indicator ({harmless} marked it clean)."

    return {"source": source_name, "status": status, "score": score, "summary": summary, "raw": raw_data}


def check_whois(indicator: str, indicator_type: str) -> dict:
    """
    WHOIS / registration-data lookup. No API key required.
      - IP addresses  -> public RDAP lookup (rdap.org), which proxies to the
                          correct regional registry automatically.
      - Domain / URL  -> python-whois against the bare hostname.
    """
    source_name = "WHOIS"
    try:
        if indicator_type == "IP":
            resp = requests.get(f"https://rdap.org/ip/{indicator}", timeout=15)
            resp.raise_for_status()
            data = resp.json()

            registration_date = None
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    registration_date = event.get("eventDate")
                    break

            summary = f"IP block registered to: {data.get('name', 'Unknown')}"
            if registration_date:
                summary += f" (registered {registration_date[:10]})"

            return {"source": source_name, "status": "info", "score": None, "summary": summary, "raw": data}

        # Domain or URL -> lookup on the bare hostname
        w = pywhois.whois(indicator)

        def _jsonable(v):
            if isinstance(v, (list, dict, str, int, float, type(None), bool)):
                return v
            return str(v)

        raw = {k: _jsonable(v) for k, v in dict(w).items()}

        if not w.domain_name:
            return {
                "source": source_name, "status": "unknown", "score": None,
                "summary": "No WHOIS record found (domain may be unregistered).",
                "raw": raw,
            }

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        summary = f"Registrar: {w.registrar or 'Unknown'}"
        if creation:
            summary += f" | Created: {str(creation)[:10]}"

        return {"source": source_name, "status": "info", "score": None, "summary": summary, "raw": raw}

    except Exception as e:
        return {
            "source": source_name, "status": "error", "score": None,
            "summary": "WHOIS lookup failed.",
            "raw": {"error": str(e)},
        }


# ---------------------------------------------------------------------------
# SOURCE REGISTRY — the ONLY place app.py looks to know what sources exist.
# Add a new source by adding ONE line here. Nothing else changes.
# ---------------------------------------------------------------------------

SOURCES = {
    "VirusTotal": check_virustotal,
    "WHOIS": check_whois,
    # "AbuseIPDB": check_abuseipdb,   # <- example of how a future source slots in
}
