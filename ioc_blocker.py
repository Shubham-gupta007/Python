#!/usr/bin/env python3
"""
Threat Intel IOC Blocker - Trend Micro Apex Central + FortiGate (DC + DR) + Palo Alto

Single entry point for the threat-intel workflow:

    1. Read a raw CSV feed from the threat intel team
       (columns: type, indicator/value, description).
    2. For every row, clean up and validate the indicator - defanged
       values (hxxp://, [.], etc.), stray whitespace, wrong case and
       missing URL schemes are auto-corrected BEFORE anything is sent
       anywhere. A row that still doesn't look right after fixing is
       never blocked - it's reported as invalid instead.
    3. Before an IP is actually blocked on FortiGate, two extra
       safeguards run (IPs only - domains/URLs/hashes are unaffected):

           - Allowlist check: IPs matching an entry in an optional
             IP_ALLOWLIST_FILE (exact IP, CIDR, or wildcard like
             "94.*") are skipped, never blocked.

           - Geo-IP check: an IP that falls in the UAE ("AE") is
             skipped. By default this is a fully offline check
             against a local file of UAE CIDR ranges (UAE_CIDR_FILE) -
             no network access or extra packages needed, so it works
             on an air-gapped machine. Two live-lookup modes are also
             available for machines with some internet access:
             GEOIP_METHOD="virustotal" (a plain HTTPS call to the
             VirusTotal IP report API - the practical choice when
             only one domain gets whitelisted through a firewall) or
             GEOIP_METHOD="network" (RDAP/WHOIS against public
             registries, needs broader internet access).

    4. Route the now-valid, non-allowlisted, non-UAE indicator to
       every configured platform that can block its type - an IOC can
       go to more than one platform, and each attempt gets its own row
       in the results CSV:

           IP        -> FortiGate DC, FortiGate DR, AND Palo Alto
                         (each independently configured/optional -
                         only the ones you've actually set up are used)

           DOMAIN    -> FortiGate DC and FortiGate DR
                         (address object + address group on each site)

           URL, SHA1, SHA256
                     -> Trend Micro Apex Central
                        (User-Defined Suspicious Object)

    5. Write one results CSV you can open in Excel: original value,
       auto-corrected value, which platform it went to, the IP's
       country (when looked up), and whether it was blocked
       successfully - so a quick filter tells you exactly what
       succeeded, what was skipped, and what needs a human look.

Firewall platforms:

    FortiGate DC and FortiGate DR are two independent, optional
    FortiGate instances - configure either, both, or neither (per IOC
    type; DOMAIN needs at least one FortiGate site). Each site has its
    own host/key/vdom/groups, and IPs/domains are blocked on every
    site that's configured, not just one - the point is both your
    primary and DR firewalls end up with the same block, not just
    whichever one you happened to configure.

    Palo Alto blocks IPs only (this tool doesn't send domains there).
    Address/address-group changes are staged during the run and
    committed once at the end (PAN-OS requires an explicit commit for
    config changes to take effect - committing after every single IP
    would be far too slow for a bulk run).

Requirements:
    pip install requests

    openpyxl is optional: if installed, it's used to write the
    multi-sheet .xlsx results workbook (see "Output" below). If it's
    not installed (e.g. on an air-gapped machine with no pip access),
    a small built-in stdlib-only .xlsx writer is used instead -
    same output format, zero extra installs either way.

    Geo-IP checking needs no extra packages for either
    GEOIP_METHOD="offline" (default) or GEOIP_METHOD="virustotal" -
    both use only "requests", which this tool already depends on.
    Only GEOIP_METHOD="network" (RDAP/WHOIS against public registries)
    optionally benefits from:
    pip install ipwhois

Environment variables:

    Trend Micro Apex Central:
        APEX_CENTRAL_URL        e.g. "https://10.10.10.10:443"
        APEX_APPLICATION_ID
        APEX_API_KEY
        APEX_VERIFY_TLS          optional, "true"/"false", default "false"

    FortiGate DC and FortiGate DR (each optional/independent - set the
    ones you have; at least one of the two is required if the CSV
    contains any IP/DOMAIN rows):
        FORTIGATE_DC_HOST            e.g. "https://192.168.1.1:443"
        FORTIGATE_DC_API_KEY
        FORTIGATE_DC_VDOM            optional, default "root"
        FORTIGATE_DC_IP_GROUP        optional, default "Blocked-IPs"
        FORTIGATE_DC_DOMAIN_GROUP    optional, default "Blocked-Domains"
        FORTIGATE_DC_VERIFY_TLS      optional, "true"/"false", default "false"

        FORTIGATE_DR_HOST            same shape as DC, for the DR site
        FORTIGATE_DR_API_KEY
        FORTIGATE_DR_VDOM
        FORTIGATE_DR_IP_GROUP
        FORTIGATE_DR_DOMAIN_GROUP
        FORTIGATE_DR_VERIFY_TLS

    Palo Alto (optional; IP blocking only):
        PALOALTO_HOST            e.g. "https://192.168.1.1"
        PALOALTO_API_KEY         a pre-generated PAN-OS API key
        PALOALTO_VSYS            optional, default "vsys1"
        PALOALTO_IP_GROUP        optional, default "Blocked-IPs"
        PALOALTO_VERIFY_TLS      optional, "true"/"false", default "false"

    Only the variables for the platform(s) actually needed by the
    CSV's IOC types are required - a CSV with only URL/hash rows never
    asks for firewall credentials, and vice versa. For IP/DOMAIN rows,
    at least one applicable platform (any combination of FortiGate
    DC/DR, plus Palo Alto for IPs) must be configured, or the run
    refuses to start with a clear error naming what's missing.

    IP safeguards (all optional):
        IP_ALLOWLIST_FILE           path to a CSV of IPs/ranges to
                                     never block (see below), unset by
                                     default (no allowlist applied)
        GEOIP_METHOD                "offline" (default, air-gap safe),
                                     "virustotal" (HTTPS to one domain,
                                     www.virustotal.com), or "network"
                                     (broader RDAP/WHOIS lookup)
        UAE_CIDR_FILE               GEOIP_METHOD="offline" only: path
                                     to a plain-text list of UAE CIDR
                                     ranges (see below), unset by
                                     default (UAE geo-block disabled)
        VT_API_KEY                  GEOIP_METHOD="virustotal" only:
                                     your VirusTotal API key
        VT_REQUEST_DELAY_SECONDS    GEOIP_METHOD="virustotal" only:
                                     seconds to sleep before each VT
                                     call, default 0 - set e.g. 15 on
                                     VT's 4-requests/minute free tier
        GEOIP_LOOKUP_FAILURE_ACTION GEOIP_METHOD="network" or
                                     "virustotal" only: "block"
                                     (default) or "skip" - what to do
                                     with an IP whose country could
                                     not be determined at all

Allowlist CSV format (column names are case-insensitive; one of
"ip_or_range"/"ip"/"range"/"value" is required):

    ip_or_range
    94.*
    203.0.113.0/24
    198.51.100.7

UAE_CIDR_FILE format (plain text, one CIDR or IP per line, "#"
comments and blank lines ignored - the same shape as country zone
files from sources like ipdeny.com, so one can be dropped in as-is
after being carried onto the air-gapped machine through your normal
offline transfer process):

    # Example only - replace with the real UAE CIDR ranges from your
    # own data source (see note below); these are just illustrative.
    192.0.2.0/24
    198.51.100.0/24

Run:

    python3 ioc_blocker.py

    The program will display a menu.

Input CSV format (column names are case-insensitive):

    type,indicator,description
    IP,192.168.1[.]100,C2 server for campaign X
    URL,hxxps://evil[.]example.com/malware.exe,Malware download URL
    DOMAIN,evil[.]example[.]com,Phishing domain
    SHA1,0123456789abcdef0123456789abcdef01234567,Dropper hash
    SHA256,c71ddfa376b2a86bae93d46d997742502d127979a8774402c936ec6832bb91d0,Ransomware hash

Output: <input file name>_results_<YYYYMMDD_HHMMSS>.xlsx - a new,
timestamped file every run, so nothing gets overwritten. It's an Excel
workbook with four sheets, each using the same columns (Row, Type,
Original_Value, Fixed_Value, Auto_Fixed, Description, Target_Tool,
Country, Status, Detail, Processed_At):

    Summary      - how many rows were Blocked/Failed/Invalid/Skipped/
                   Would Block overall, and broken down by IOC type
    Blocked      - only the rows that were successfully blocked
    Not Blocked  - everything else (Failed, Invalid, Skipped, or
                   Would Block in a dry run) - i.e. what did NOT end
                   up blocked and may need a human look
    All Results  - every row, unfiltered, for full traceability
"""

import base64
import csv
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# ============================================================
# CONFIGURATION - TREND MICRO APEX CENTRAL
# ============================================================

APEX_CENTRAL_URL = os.environ.get("APEX_CENTRAL_URL", "")
APEX_APPLICATION_ID = os.environ.get("APEX_APPLICATION_ID", "")
APEX_API_KEY = os.environ.get("APEX_API_KEY", "")
APEX_VERIFY_TLS = os.environ.get("APEX_VERIFY_TLS", "false").lower() == "true"

APEX_API_PATH = "/WebApp/api/SuspiciousObjects/UserDefinedSO/"

# Fallback note used only when a row's "description" column is blank.
DEFAULT_NOTE = "WO0000000208886-WO0000000208904"
SCAN_ACTION = "block"

APEX_TYPE_MAP = {
    "URL": "url",
    "SHA1": "file_sha1",
    "SHA256": "file_sha256",
}


# ============================================================
# CONFIGURATION - FORTIGATE DC (BRANCH OFFICE 1)
# ============================================================
#
# Fill these in directly (same style as the Apex Central / Palo Alto
# settings above) to hardcode this site's connection details instead
# of relying on environment variables - e.g. change the "" below to
# FORTIGATE_DC_HOST = "https://10.10.10.10:443". An env var of the
# same name still overrides whatever is hardcoded here, if set.

FORTIGATE_DC_HOST = os.environ.get("FORTIGATE_DC_HOST", "")
FORTIGATE_DC_API_KEY = os.environ.get("FORTIGATE_DC_API_KEY", "")
FORTIGATE_DC_VDOM = os.environ.get("FORTIGATE_DC_VDOM", "root")
FORTIGATE_DC_IP_GROUP = os.environ.get("FORTIGATE_DC_IP_GROUP", "Blocked-IPs")
FORTIGATE_DC_DOMAIN_GROUP = os.environ.get("FORTIGATE_DC_DOMAIN_GROUP", "Blocked-Domains")
FORTIGATE_DC_VERIFY_TLS = os.environ.get("FORTIGATE_DC_VERIFY_TLS", "false").lower() == "true"


# ============================================================
# CONFIGURATION - FORTIGATE DR (BRANCH OFFICE 2)
# ============================================================
#
# Same idea as DC above - independent of it, and optional. Leaving a
# site's host/api_key blank just means that site is skipped.

FORTIGATE_DR_HOST = os.environ.get("FORTIGATE_DR_HOST", "")
FORTIGATE_DR_API_KEY = os.environ.get("FORTIGATE_DR_API_KEY", "")
FORTIGATE_DR_VDOM = os.environ.get("FORTIGATE_DR_VDOM", "root")
FORTIGATE_DR_IP_GROUP = os.environ.get("FORTIGATE_DR_IP_GROUP", "Blocked-IPs")
FORTIGATE_DR_DOMAIN_GROUP = os.environ.get("FORTIGATE_DR_DOMAIN_GROUP", "Blocked-Domains")
FORTIGATE_DR_VERIFY_TLS = os.environ.get("FORTIGATE_DR_VERIFY_TLS", "false").lower() == "true"

FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

# Two independent, optional FortiGate sites, built from the DC/DR
# settings above. An IP/DOMAIN is blocked on every site that's
# configured (not just one) - see fortigate_site_configured() and
# block_via_fortigate() below.
FORTIGATE_SITES = {
    "DC": {
        "host": FORTIGATE_DC_HOST,
        "api_key": FORTIGATE_DC_API_KEY,
        "vdom": FORTIGATE_DC_VDOM,
        "ip_group": FORTIGATE_DC_IP_GROUP,
        "domain_group": FORTIGATE_DC_DOMAIN_GROUP,
        "verify_tls": FORTIGATE_DC_VERIFY_TLS,
    },
    "DR": {
        "host": FORTIGATE_DR_HOST,
        "api_key": FORTIGATE_DR_API_KEY,
        "vdom": FORTIGATE_DR_VDOM,
        "ip_group": FORTIGATE_DR_IP_GROUP,
        "domain_group": FORTIGATE_DR_DOMAIN_GROUP,
        "verify_tls": FORTIGATE_DR_VERIFY_TLS,
    },
}


def fortigate_site_configured(site_name):
    site = FORTIGATE_SITES[site_name]
    return bool(site["host"] and site["api_key"])


# ============================================================
# CONFIGURATION - PALO ALTO (IP BLOCKING ONLY)
# ============================================================

PALOALTO_HOST = os.environ.get("PALOALTO_HOST", "")
PALOALTO_API_KEY = os.environ.get("PALOALTO_API_KEY", "")
PALOALTO_VSYS = os.environ.get("PALOALTO_VSYS", "vsys1")
PALOALTO_IP_GROUP = os.environ.get("PALOALTO_IP_GROUP", "Blocked-IPs")
PALOALTO_VERIFY_TLS = os.environ.get("PALOALTO_VERIFY_TLS", "false").lower() == "true"

PALOALTO_API_PATH = "/api/"
PALOALTO_BASE_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    f"/vsys/entry[@name='{PALOALTO_VSYS}']"
)
PALOALTO_ADDRESS_XPATH = PALOALTO_BASE_XPATH + "/address/entry[@name='{name}']"
PALOALTO_GROUP_STATIC_XPATH = PALOALTO_BASE_XPATH + "/address-group/entry[@name='{group}']/static"


def paloalto_configured():
    return bool(PALOALTO_HOST and PALOALTO_API_KEY)


if (
    not APEX_VERIFY_TLS
    or any(not site["verify_tls"] for site in FORTIGATE_SITES.values())
    or not PALOALTO_VERIFY_TLS
):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ============================================================
# CONFIGURATION - IP SAFEGUARDS (ALLOWLIST + GEO-BLOCK)
# ============================================================

# Optional CSV of IPs/ranges that must never be blocked, regardless of
# what the threat intel feed says. Unset by default (no allowlist).
IP_ALLOWLIST_FILE = os.environ.get("IP_ALLOWLIST_FILE", "")

# ISO 3166-1 alpha-2 country code(s) that an IP is never blocked for.
UAE_COUNTRY_CODES = {"AE"}

# How to determine an IP's country:
#   "offline" (default) - match against a local file of known UAE
#       CIDR ranges (UAE_CIDR_FILE below). No network access and no
#       extra pip packages required - the only method that works on
#       a fully air-gapped machine. If UAE_CIDR_FILE isn't set, this
#       check is simply skipped (no UAE IPs can be identified).
#   "virustotal" - live lookup via the VirusTotal IP report API
#       (VT_API_KEY below). A single plain HTTPS request to
#       www.virustotal.com - the practical option when only one
#       specific domain gets whitelisted through an otherwise
#       locked-down firewall, since it needs nothing beyond the
#       "requests" library this tool already depends on (no raw
#       WHOIS port 43, no extra pip installs).
#   "network" - live RDAP lookup (pip install ipwhois) with a
#       fallback to a built-in legacy WHOIS client. Needs outbound
#       internet access to public registries on port 43/443 - only
#       use this where that's actually reachable.
GEOIP_METHOD = os.environ.get("GEOIP_METHOD", "offline").lower()

# Local file of UAE IP ranges for GEOIP_METHOD="offline": plain text,
# one CIDR (or bare IP) per line, blank lines and "#" comments
# ignored - the same format country zone files from sources like
# ipdeny.com's country CIDR lists use, so one of those (or an export
# from your own threat intel/network team) can be dropped in as-is
# after being carried over via your normal offline transfer process.
UAE_CIDR_FILE = os.environ.get("UAE_CIDR_FILE", "")

# GEOIP_METHOD="virustotal" only.
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
# VirusTotal's free-tier API allows 4 requests/minute. Set this (in
# seconds) if you're on the free tier and blocking many IPs in one
# run - e.g. 15 keeps you under the limit. Leave at 0 for a paid tier
# with a higher/no rate limit.
VT_REQUEST_DELAY_SECONDS = float(os.environ.get("VT_REQUEST_DELAY_SECONDS", "0"))

# GEOIP_METHOD="network"/"virustotal" only: what to do when the live
# lookup itself fails (network issue, bad/missing API key, no ipwhois
# installed and the WHOIS fallback also failed, rate-limited, etc.):
#   "block" (default) - proceed with the block; we simply couldn't
#                        confirm the country, which is not evidence
#                        it's a UAE IP.
#   "skip"             - err on the side of caution and don't block an
#                         IP whose country is unknown.
GEOIP_LOOKUP_FAILURE_ACTION = os.environ.get("GEOIP_LOOKUP_FAILURE_ACTION", "block").lower()

GEOIP_TIMEOUT_SECONDS = 10

# Looked up at most once per IP per run (live-lookup methods only).
_GEOIP_CACHE = {}


# ============================================================
# ROUTING - WHICH PLATFORM(S) HANDLE WHICH IOC TYPE
# ============================================================
#
# An IOC type can route to more than one platform - e.g. an IP goes to
# FortiGate DC, FortiGate DR, AND Palo Alto, whichever of those are
# actually configured. Each attempt gets its own row in the results
# CSV (see process_file()).

BASE_ROUTES = {
    "IP": ["FORTIGATE_DC", "FORTIGATE_DR", "PALOALTO"],
    "DOMAIN": ["FORTIGATE_DC", "FORTIGATE_DR"],
    "URL": ["APEX"],
    "SHA1": ["APEX"],
    "SHA256": ["APEX"],
}

ROUTE_TO_APEX = {ioc_type for ioc_type, targets in BASE_ROUTES.items() if "APEX" in targets}

TARGET_LABEL = {
    "FORTIGATE_DC": "FortiGate-DC",
    "FORTIGATE_DR": "FortiGate-DR",
    "PALOALTO": "Palo Alto",
    "APEX": "Trend Micro Apex Central",
}


def is_target_configured(target_key):
    if target_key in ("FORTIGATE_DC", "FORTIGATE_DR"):
        return fortigate_site_configured(target_key.split("_")[1])
    if target_key == "PALOALTO":
        return paloalto_configured()
    if target_key == "APEX":
        return bool(APEX_CENTRAL_URL and APEX_APPLICATION_ID and APEX_API_KEY)
    return False


def targets_for_type(ioc_type):
    """Configured platforms only - what a real run will actually use."""
    return [target for target in BASE_ROUTES.get(ioc_type, []) if is_target_configured(target)]


def validate_apex_configuration():
    missing = [
        name
        for name, value in (
            ("APEX_CENTRAL_URL", APEX_CENTRAL_URL),
            ("APEX_APPLICATION_ID", APEX_APPLICATION_ID),
            ("APEX_API_KEY", APEX_API_KEY),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing Apex Central environment variable(s): " + ", ".join(missing)
        )


def validate_fortigate_site_configuration(site_name):
    site = FORTIGATE_SITES[site_name]

    # Not configured at all is fine - it just means this site is unused.
    if not site["host"] and not site["api_key"]:
        return

    missing = [
        name
        for name, value in (
            (f"FORTIGATE_{site_name}_HOST", site["host"]),
            (f"FORTIGATE_{site_name}_API_KEY", site["api_key"]),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"Missing FortiGate {site_name} environment variable(s): " + ", ".join(missing)
        )


def validate_paloalto_configuration():
    # Not configured at all is fine - Palo Alto is optional.
    if not PALOALTO_HOST and not PALOALTO_API_KEY:
        return

    missing = [
        name
        for name, value in (
            ("PALOALTO_HOST", PALOALTO_HOST),
            ("PALOALTO_API_KEY", PALOALTO_API_KEY),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing Palo Alto environment variable(s): " + ", ".join(missing)
        )


def validate_platform_coverage(present_types):
    """
    For every IOC type actually present in the file, make sure at
    least one applicable platform is configured - otherwise the file
    would silently have nothing to send those rows to.
    """
    for ioc_type in present_types:
        if ioc_type in BASE_ROUTES and not targets_for_type(ioc_type):
            candidates = ", ".join(TARGET_LABEL[t] for t in BASE_ROUTES[ioc_type])
            raise RuntimeError(
                f"No configured platform can block IOC type '{ioc_type}'. "
                f"Configure at least one of: {candidates}."
            )


def validate_virustotal_configuration():
    if not VT_API_KEY:
        raise RuntimeError(
            "Missing VT_API_KEY environment variable (required for "
            "GEOIP_METHOD=virustotal). Without it every IP's geo-lookup "
            f"would fail and, per GEOIP_LOOKUP_FAILURE_ACTION="
            f"{GEOIP_LOOKUP_FAILURE_ACTION!r}, "
            + ("every IP would be blocked without ever checking for UAE."
               if GEOIP_LOOKUP_FAILURE_ACTION != "skip"
               else "no IP would ever be blocked.")
        )


# ============================================================
# IOC TYPE NORMALIZATION
# ============================================================

TYPE_ALIASES = {
    "IP": "IP",
    "IP_ADDRESS": "IP",
    "IP ADDRESS": "IP",
    "URL": "URL",
    "DOMAIN": "DOMAIN",
    "FQDN": "DOMAIN",
    "SHA1": "SHA1",
    "SHA-1": "SHA1",
    "SHA256": "SHA256",
    "SHA-256": "SHA256",
}


def normalize_type(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("IOC 'type' is missing or empty.")

    key = value.strip().upper()

    if key not in TYPE_ALIASES:
        raise ValueError(
            f"Unsupported IOC type '{value}'. Supported: IP (FortiGate "
            "DC/DR, Palo Alto), DOMAIN (FortiGate DC/DR), URL, SHA1, "
            "SHA256 (Trend Micro Apex Central)."
        )

    return TYPE_ALIASES[key]


# ============================================================
# AUTO-FIX (DEFANG / FORMAT REPAIR) + VALIDATION
# ============================================================

def strip_wrapping(value):
    """Removes surrounding quotes/angle-brackets/whitespace a feed may add."""
    return value.strip().strip("\"'<>").strip()


def defang_fix(value):
    """
    Reverses the common ways threat-intel feeds "defang" an indicator so
    it can't be clicked/resolved by accident.
    """
    value = strip_wrapping(value)

    value = re.sub(r"hxxps://", "https://", value, flags=re.IGNORECASE)
    value = re.sub(r"hxxp://", "http://", value, flags=re.IGNORECASE)

    for pattern in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        value = re.sub(re.escape(pattern), ".", value, flags=re.IGNORECASE)

    for pattern in ("[:]", "(:)"):
        value = value.replace(pattern, ":")

    value = value.replace("[at]", "@").replace("(at)", "@")

    return value.strip()


def fix_ip(raw_value):
    return defang_fix(raw_value)


def fix_domain(raw_value):
    value = defang_fix(raw_value).rstrip(".").lower()
    return value


def fix_url(raw_value):
    value = defang_fix(raw_value)

    if not re.match(r"^https?://", value, flags=re.IGNORECASE):
        # Feed dropped the scheme (e.g. "evil.example.com/malware.exe").
        # A URL block needs one, so assume the common case.
        value = "http://" + value

    return value


def fix_hash(raw_value):
    value = defang_fix(raw_value)
    # Some feeds separate hash bytes with spaces, dashes or colons.
    value = re.sub(r"[\s:-]", "", value)
    return value.upper()


def validate_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"Invalid IP address: {value}")

    if address.version != 4:
        raise ValueError(
            f"Apex/FortiGate blocking here expects IPv4, got IPv{address.version}: {value}"
        )

    return str(address)


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def validate_domain(value):
    if not DOMAIN_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid domain: {value}")

    return value


def validate_url(value):
    if not (value.startswith("http://") or value.startswith("https://")):
        raise ValueError("URL must start with http:// or https://")

    if len(value) > 2047:
        raise ValueError("URL exceeds 2047 characters.")

    if not urlparse(value).netloc:
        raise ValueError("URL does not contain a valid hostname.")

    return value


def validate_sha1(value):
    if not re.fullmatch(r"[0-9A-F]{40}", value):
        raise ValueError("SHA-1 must contain exactly 40 hexadecimal characters.")

    return value


def validate_sha256(value):
    if not re.fullmatch(r"[0-9A-F]{64}", value):
        raise ValueError("SHA-256 must contain exactly 64 hexadecimal characters.")

    return value


FIXERS = {
    "IP": fix_ip,
    "DOMAIN": fix_domain,
    "URL": fix_url,
    "SHA1": fix_hash,
    "SHA256": fix_hash,
}

VALIDATORS = {
    "IP": validate_ip,
    "DOMAIN": validate_domain,
    "URL": validate_url,
    "SHA1": validate_sha1,
    "SHA256": validate_sha256,
}


def normalize_and_validate(ioc_type, raw_value):
    """
    Auto-corrects a raw indicator for its declared type and validates
    the result. Returns (fixed_value, was_auto_fixed). Raises
    ValueError if the value still doesn't look right even after the
    fix-up pass - such a value is never sent to either tool.
    """
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise ValueError("Indicator value is missing or empty.")

    original = raw_value.strip()

    fixed = FIXERS[ioc_type](raw_value)
    fixed = VALIDATORS[ioc_type](fixed)

    was_fixed = fixed != original

    return fixed, was_fixed


# ============================================================
# TREND MICRO APEX CENTRAL - JWT SIGNING
# ============================================================

def compact_json(data):
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def apex_create_checksum(http_method, raw_url, canonical_headers, request_body):
    checksum_input = (
        http_method.upper() + "|" + raw_url.lower() + "|" + canonical_headers + "|" + request_body
    )
    digest = hashlib.sha256(checksum_input.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def apex_create_jwt(http_method, raw_url, request_body):
    header = {"alg": "HS256", "typ": "JWT"}
    canonical_headers = ""

    checksum = apex_create_checksum(http_method, raw_url, canonical_headers, request_body)

    payload = {
        "appid": APEX_APPLICATION_ID,
        "iat": time.time(),
        "version": "V1",
        "checksum": checksum,
    }

    encoded_header = base64url_encode(compact_json(header).encode("utf-8"))
    encoded_payload = base64url_encode(compact_json(payload).encode("utf-8"))
    signing_input = encoded_header + "." + encoded_payload

    signature = hmac.new(
        APEX_API_KEY.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()

    return signing_input + "." + base64url_encode(signature)


# ============================================================
# TREND MICRO APEX CENTRAL - BLOCK
# ============================================================

def build_apex_payload(ioc_type, value, note):
    return {
        "param": {
            "type": APEX_TYPE_MAP[ioc_type],
            "content": value,
            "notes": note,
            "scan_action": SCAN_ACTION,
        }
    }


def block_via_apex(ioc_type, value, note):
    """Returns (success, detail_text) - detail_text is plain English for the results CSV."""
    payload = build_apex_payload(ioc_type, value, note)
    request_body = compact_json(payload)

    token = apex_create_jwt("PUT", APEX_API_PATH, request_body)

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json;charset=utf-8",
    }

    url = APEX_CENTRAL_URL + APEX_API_PATH

    response = requests.put(
        url,
        headers=headers,
        data=request_body.encode("utf-8"),
        verify=APEX_VERIFY_TLS,
        timeout=30,
    )

    try:
        response_json = response.json()
    except ValueError:
        return False, f"HTTP {response.status_code} - non-JSON response from Apex Central"

    meta = response_json.get("Meta", {})
    result = str(meta.get("Result", ""))
    error_code = meta.get("ErrorCode")
    error_message = meta.get("ErrorMsg")

    if response.status_code == 200 and result == "1":
        return True, f"HTTP {response.status_code} - added to Apex Central UDSO (block)"

    return False, f"HTTP {response.status_code} - ErrorCode={error_code} ErrorMsg={error_message}"


# ============================================================
# FORTIGATE - BLOCK (DC + DR)
# ============================================================
# Every function here takes the target site's config dict (one of
# FORTIGATE_SITES["DC"]/["DR"]) so the exact same code blocks either
# site - block_via_fortigate(site_name, ...) below is the entry point.

def fortigate_api_headers(site):
    return {
        "Authorization": f"Bearer {site['api_key']}",
        "Content-Type": "application/json",
    }


def fortigate_normalize_subnet(value):
    network = ipaddress.ip_network(value, strict=False)
    return f"{network.network_address} {network.netmask}"


def build_fortigate_payload(ioc_type, value, comment):
    if ioc_type == "IP":
        return {
            "name": value,
            "type": "ipmask",
            "subnet": fortigate_normalize_subnet(value),
            "comment": comment or "",
        }

    return {
        "name": value,
        "type": "fqdn",
        "fqdn": value,
        "comment": comment or "",
    }


def fortigate_is_duplicate(response):
    try:
        return response.json().get("error") == -5
    except ValueError:
        return False


def fortigate_create_or_update_address(site, payload):
    name = payload["name"]
    url = f"{site['host']}{FORTIGATE_ADDRESS_PATH}"

    response = requests.post(
        url,
        headers=fortigate_api_headers(site),
        params={"vdom": site["vdom"]},
        json=payload,
        verify=site["verify_tls"],
        timeout=30,
    )

    if response.status_code == 200:
        return True, response

    if response.status_code == 500 and fortigate_is_duplicate(response):
        response = requests.put(
            f"{url}/{name}",
            headers=fortigate_api_headers(site),
            params={"vdom": site["vdom"]},
            json=payload,
            verify=site["verify_tls"],
            timeout=30,
        )
        return response.status_code == 200, response

    return False, response


def fortigate_add_to_group(site, group_name, member_name):
    url = f"{site['host']}{FORTIGATE_GROUP_PATH}/{group_name}"

    response = requests.get(
        url,
        headers=fortigate_api_headers(site),
        params={"vdom": site["vdom"]},
        verify=site["verify_tls"],
        timeout=30,
    )

    if response.status_code != 200:
        return False, f"HTTP {response.status_code} - could not look up group '{group_name}'"

    body = response.json()
    results = body.get("results", [])
    existing_members = [m["name"] for m in results[0].get("member", [])] if results else []

    if member_name in existing_members:
        return True, f"already a member of group '{group_name}'"

    payload = {"member": [{"name": m} for m in existing_members + [member_name]]}

    response = requests.put(
        url,
        headers=fortigate_api_headers(site),
        params={"vdom": site["vdom"]},
        json=payload,
        verify=site["verify_tls"],
        timeout=30,
    )

    if response.status_code == 200:
        return True, f"added to group '{group_name}'"

    return False, f"HTTP {response.status_code} - could not update group '{group_name}'"


def block_via_fortigate(site_name, ioc_type, value, comment):
    """Returns (success, detail_text). site_name is "DC" or "DR"."""
    site = FORTIGATE_SITES[site_name]
    payload = build_fortigate_payload(ioc_type, value, comment)

    success, response = fortigate_create_or_update_address(site, payload)

    if not success:
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return False, f"[{site_name}] HTTP {response.status_code} - address object failed: {body}"

    group = site["ip_group"] if ioc_type == "IP" else site["domain_group"]
    group_success, group_detail = fortigate_add_to_group(site, group, value)

    address_type = "ipmask" if ioc_type == "IP" else "fqdn"
    detail = f"[{site_name}] HTTP {response.status_code} - {address_type} address created/updated, {group_detail}"

    return group_success, detail


# ============================================================
# PALO ALTO - BLOCK (IP ONLY)
# ============================================================
# Uses the PAN-OS XML API (type=config, action=set/get) rather than
# the newer REST API for maximum compatibility across PAN-OS versions.
# Config changes are staged, not applied immediately - a single
# commit_paloalto_changes() call at the end of the run (see
# process_file()) pushes everything made during the run in one shot,
# since committing after every IP would be far too slow in bulk.

_paloalto_pending_commit = False


def paloalto_request(params):
    return requests.get(
        f"{PALOALTO_HOST}{PALOALTO_API_PATH}",
        params=params,
        verify=PALOALTO_VERIFY_TLS,
        timeout=30,
    )


def paloalto_parse_status(response):
    """Returns (success, error_message_or_None)."""
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError:
        return False, f"HTTP {response.status_code} - non-XML response from Palo Alto"

    if root.get("status") == "success":
        return True, None

    message = root.findtext(".//msg") or root.findtext(".//line") or response.text[:200]
    return False, f"HTTP {response.status_code} - {message}"


def build_paloalto_address_element(ip_value, comment):
    element = f"<ip-netmask>{ip_value}/32</ip-netmask>"

    if comment:
        element += f"<description>{xml_escape(comment)}</description>"

    return element


def paloalto_set_address_object(name, ip_value, comment):
    response = paloalto_request({
        "type": "config",
        "action": "set",
        "key": PALOALTO_API_KEY,
        "xpath": PALOALTO_ADDRESS_XPATH.format(name=name),
        "element": build_paloalto_address_element(ip_value, comment),
    })

    success, error = paloalto_parse_status(response)

    return success, error, response


def paloalto_get_group_members(group_name):
    response = paloalto_request({
        "type": "config",
        "action": "get",
        "key": PALOALTO_API_KEY,
        "xpath": PALOALTO_GROUP_STATIC_XPATH.format(group=group_name),
    })

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError:
        return None, f"HTTP {response.status_code} - non-XML response from Palo Alto"

    if root.get("status") != "success":
        message = root.findtext(".//msg") or response.text[:200]
        return None, f"could not read group '{group_name}' (does it exist?): {message}"

    members = [member.text for member in root.findall(".//member") if member.text]

    return members, None


def paloalto_set_group_members(group_name, members):
    element = "<static>" + "".join(f"<member>{xml_escape(m)}</member>" for m in members) + "</static>"

    response = paloalto_request({
        "type": "config",
        "action": "set",
        "key": PALOALTO_API_KEY,
        "xpath": PALOALTO_GROUP_STATIC_XPATH.format(group=group_name),
        "element": element,
    })

    return paloalto_parse_status(response)


def block_via_paloalto(ioc_type, value, comment):
    """Returns (success, detail_text). IP only - see BASE_ROUTES."""
    global _paloalto_pending_commit

    if ioc_type != "IP":
        return False, f"Palo Alto blocking here only supports IP, got {ioc_type}"

    success, error, response = paloalto_set_address_object(value, value, comment)

    if not success:
        return False, f"HTTP {response.status_code} - address object failed: {error}"

    members, get_error = paloalto_get_group_members(PALOALTO_IP_GROUP)

    if members is None:
        return False, f"HTTP {response.status_code} - address object ok, {get_error}"

    if value in members:
        detail = f"HTTP {response.status_code} - address object created/updated, already a member of group '{PALOALTO_IP_GROUP}'"
    else:
        group_success, group_error = paloalto_set_group_members(PALOALTO_IP_GROUP, members + [value])

        if not group_success:
            return False, f"HTTP {response.status_code} - address object ok, group update failed: {group_error}"

        detail = f"HTTP {response.status_code} - address object created/updated, added to group '{PALOALTO_IP_GROUP}'"

    _paloalto_pending_commit = True

    return True, detail + " (staged, pending commit)"


def commit_paloalto_changes():
    """
    Call once after processing the whole file. Returns None if nothing
    was staged (no commit needed), otherwise (success, detail_text).
    """
    global _paloalto_pending_commit

    if not _paloalto_pending_commit:
        return None

    response = paloalto_request({
        "type": "commit",
        "cmd": "<commit></commit>",
        "key": PALOALTO_API_KEY,
    })

    success, error = paloalto_parse_status(response)

    _paloalto_pending_commit = False

    if not success:
        return False, f"commit failed: {error}"

    job_id = None
    try:
        job_id = ET.fromstring(response.text).findtext(".//job")
    except ET.ParseError:
        pass

    return True, f"commit job enqueued{f' (job id {job_id})' if job_id else ''}"


# Every entry takes (ioc_type, value, comment) and returns (success, detail).
BLOCK_FUNCTIONS = {
    "FORTIGATE_DC": lambda ioc_type, value, comment: block_via_fortigate("DC", ioc_type, value, comment),
    "FORTIGATE_DR": lambda ioc_type, value, comment: block_via_fortigate("DR", ioc_type, value, comment),
    "PALOALTO": lambda ioc_type, value, comment: block_via_paloalto(ioc_type, value, comment),
    "APEX": lambda ioc_type, value, comment: block_via_apex(ioc_type, value, comment),
}


# ============================================================
# IP SAFEGUARDS - ALLOWLIST
# ============================================================

def wildcard_to_network(pattern):
    """
    Converts a wildcard range into an ip_network. A "*" means "this
    octet and everything after it is wildcarded" - you don't need to
    repeat it for every remaining octet:

        "94.*"        -> 94.0.0.0/8
        "94.10.*"     -> 94.10.0.0/16
        "94.10.20.*"  -> 94.10.20.0/24
        "94.*.*.*"    -> 94.0.0.0/8   (equivalent to "94.*")

    Wildcards must trail the concrete octets - "94.*.5.6" is rejected.
    """
    octets = pattern.split(".")

    if not 1 <= len(octets) <= 4:
        raise ValueError(f"Invalid wildcard IP range: {pattern}")

    concrete_octets = []
    prefix_len = 0
    seen_wildcard = False

    for octet in octets:
        if octet == "*":
            seen_wildcard = True
            continue

        if seen_wildcard:
            raise ValueError(
                f"Invalid wildcard IP range '{pattern}': wildcards must "
                "trail the concrete octets, e.g. '94.*' or '94.10.*'."
            )

        if not octet.isdigit() or not 0 <= int(octet) <= 255:
            raise ValueError(f"Invalid wildcard IP range: {pattern}")

        concrete_octets.append(octet)
        prefix_len += 8

    if not seen_wildcard:
        raise ValueError(f"No wildcard '*' found in pattern: {pattern}")

    if not concrete_octets:
        raise ValueError(
            f"Invalid wildcard IP range '{pattern}': a bare '*' would "
            "allowlist every IPv4 address. Give at least one concrete "
            "octet, e.g. '94.*'."
        )

    while len(concrete_octets) < 4:
        concrete_octets.append("0")

    network_str = ".".join(concrete_octets) + f"/{prefix_len}"

    return ipaddress.ip_network(network_str, strict=False)


def parse_allowlist_entry(raw_entry):
    entry = raw_entry.strip()

    if "*" in entry:
        return wildcard_to_network(entry)

    if "/" in entry:
        return ipaddress.ip_network(entry, strict=False)

    return ipaddress.ip_network(entry + "/32", strict=False)


def load_ip_allowlist(filename):
    with open(filename, mode="r", encoding="utf-8-sig", newline="") as csv_file:
        sample = csv_file.read(4096)
        csv_file.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(csv_file, dialect=dialect)

        if reader.fieldnames:
            reader.fieldnames = [
                field.strip().lower() if field else field for field in reader.fieldnames
            ]

        fieldnames = reader.fieldnames or []

        for candidate in ("ip_or_range", "ip", "range", "value"):
            if candidate in fieldnames:
                column = candidate
                break
        else:
            raise ValueError(
                "Allowlist CSV must contain an 'ip_or_range' (or "
                f"'ip'/'range'/'value') column. Found: {fieldnames}"
            )

        networks = []

        for row_number, row in enumerate(reader, start=2):
            raw_entry = (row.get(column) or "").strip()

            if not raw_entry:
                continue

            try:
                networks.append(parse_allowlist_entry(raw_entry))
            except ValueError as error:
                raise ValueError(f"Allowlist file '{filename}' row {row_number}: {error}")

    return networks


def is_ip_allowlisted(ip_value, allowlist_networks):
    address = ipaddress.ip_address(ip_value)
    return any(address in network for network in allowlist_networks)


def load_cidr_list_file(filename):
    """
    Loads a plain-text list of CIDR ranges/IPs, one per line - blank
    lines and lines starting with "#" are skipped. This is the format
    used by GEOIP_METHOD="offline" for UAE_CIDR_FILE, and matches
    country zone files as published by sources like ipdeny.com, so
    one of those can be used with zero preprocessing.
    """
    networks = []

    with open(filename, mode="r", encoding="utf-8-sig") as text_file:
        for line_number, line in enumerate(text_file, start=1):
            entry = line.strip()

            if not entry or entry.startswith("#"):
                continue

            try:
                networks.append(parse_allowlist_entry(entry))
            except ValueError as error:
                raise ValueError(f"{filename} line {line_number}: {error}")

    return networks


# ============================================================
# IP SAFEGUARDS - GEO-IP (UAE BLOCK)
# ============================================================
#
# Three independent methods, selected by GEOIP_METHOD:
#
#   "offline" (default) - is_ip_in_uae_offline() below, a pure
#       stdlib CIDR-membership check against UAE_CIDR_FILE. No
#       network access, no extra packages - works fully air-gapped.
#
#   "virustotal" - _geoip_lookup_virustotal() below, a live HTTPS
#       lookup against the VirusTotal IP report API. Needs only the
#       "requests" library this tool already uses and one domain
#       (www.virustotal.com) reachable - the practical choice when a
#       firewall whitelists a single URL/tool rather than opening
#       general internet access.
#
#   "network" - _geoip_lookup_rdap()/_geoip_lookup_whois_fallback()
#       below, a live lookup against public WHOIS/RDAP registries.
#       Needs broader outbound internet access (and ideally
#       pip install ipwhois); not usable air-gapped.

def is_ip_in_uae_offline(ip_value, uae_networks):
    return bool(uae_networks) and is_ip_allowlisted(ip_value, uae_networks)


def _geoip_lookup_virustotal(ip_value):
    """
    Looks up an IP's country via VirusTotal's IP address report:
        GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
    Needs only VT_API_KEY and outbound HTTPS to www.virustotal.com -
    no raw WHOIS port 43, no extra pip packages.
    """
    if not VT_API_KEY:
        return None, "VT_API_KEY not set"

    if VT_REQUEST_DELAY_SECONDS > 0:
        time.sleep(VT_REQUEST_DELAY_SECONDS)

    try:
        response = requests.get(
            VT_API_URL + ip_value,
            headers={"x-apikey": VT_API_KEY},
            timeout=GEOIP_TIMEOUT_SECONDS,
        )
    except requests.RequestException as error:
        return None, f"VirusTotal lookup failed: {error}"

    if response.status_code == 429:
        return None, "VirusTotal rate limit hit (HTTP 429) - see VT_REQUEST_DELAY_SECONDS"

    if response.status_code != 200:
        return None, f"VirusTotal returned HTTP {response.status_code}"

    try:
        data = response.json()
    except ValueError:
        return None, "VirusTotal returned a non-JSON response"

    country = (data.get("data") or {}).get("attributes", {}).get("country")

    if not country:
        return None, "VirusTotal response did not include a country"

    return country.upper(), None


def _geoip_lookup_rdap(ip_value):
    """
    RDAP, the structured successor to WHOIS, via the ipwhois library.
    Scraping who.is directly isn't used here - it has no supported
    API and scraping a website in an automated blocking pipeline is
    fragile and against most sites' terms of use. RDAP queries the
    same regional internet registries (ARIN/RIPE/APNIC/LACNIC/
    AFRINIC) that WHOIS does, with reliable structured output.
    Requires outbound internet access - not usable air-gapped, which
    is why GEOIP_METHOD defaults to "offline" instead.
    """
    try:
        from ipwhois import IPWhois
    except ImportError:
        return None, "ipwhois library not installed (pip install ipwhois)"

    try:
        result = IPWhois(ip_value).lookup_rdap(depth=0)
    except Exception as error:
        return None, f"RDAP lookup failed: {error}"

    country = result.get("asn_country_code")

    if not country:
        country = (result.get("network") or {}).get("country")

    if not country:
        return None, "RDAP response did not include a country code"

    return country.upper(), None


def _whois_query(server, target, timeout):
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((target + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)

    return b"".join(chunks).decode("utf-8", errors="replace")


def _geoip_lookup_whois_fallback(ip_value):
    """
    Used only when ipwhois isn't installed: a minimal legacy WHOIS
    client. Asks IANA who's responsible for this IP, follows the
    referral to that registry, and reads its "country:" field.
    """
    try:
        iana_response = _whois_query("whois.iana.org", ip_value, GEOIP_TIMEOUT_SECONDS)
    except OSError as error:
        return None, f"WHOIS lookup failed: {error}"

    referral_match = re.search(r"(?im)^refer:\s*(\S+)", iana_response)

    if not referral_match:
        country_match = re.search(r"(?im)^country:\s*(\S+)", iana_response)
        if country_match:
            return country_match.group(1).upper(), None
        return None, "No referral or country field in IANA WHOIS response"

    try:
        registry_response = _whois_query(referral_match.group(1), ip_value, GEOIP_TIMEOUT_SECONDS)
    except OSError as error:
        return None, f"WHOIS lookup failed: {error}"

    country_match = re.search(r"(?im)^country:\s*(\S+)", registry_response)

    if not country_match:
        return None, "Registry WHOIS response did not include a country field"

    return country_match.group(1).upper(), None


def get_ip_country(ip_value):
    """
    GEOIP_METHOD="network" or "virustotal" only. Returns
    (country_code, error). country_code is an ISO 3166-1 alpha-2 code
    (e.g. "AE") or None if it couldn't be determined - error then
    explains why. Cached so the same IP is never looked up twice in
    one run (also saves VirusTotal API quota).
    """
    cache_key = (GEOIP_METHOD, ip_value)

    if cache_key in _GEOIP_CACHE:
        return _GEOIP_CACHE[cache_key]

    if GEOIP_METHOD == "virustotal":
        country, error = _geoip_lookup_virustotal(ip_value)
    else:
        country, error = _geoip_lookup_rdap(ip_value)
        if country is None:
            country, error = _geoip_lookup_whois_fallback(ip_value)

    _GEOIP_CACHE[cache_key] = (country, error)

    return country, error


def determine_uae_status(ip_value, uae_networks):
    """
    Returns (is_uae, country_or_empty, error_or_None), dispatching to
    the offline CIDR check or a live lookup per GEOIP_METHOD.
    """
    if GEOIP_METHOD in ("network", "virustotal"):
        country, error = get_ip_country(ip_value)

        if country and country in UAE_COUNTRY_CODES:
            return True, country, None

        return False, (country or ""), error

    # "offline" (default) - pure local CIDR match, no network calls.
    if is_ip_in_uae_offline(ip_value, uae_networks):
        return True, "AE", None

    return False, "", None


def check_ip_safeguards(ip_value, allowlist_networks, uae_networks):
    """
    Runs both IP-only safety gates before a block is allowed to
    proceed. Returns (allowed, country, skip_reason) - skip_reason is
    None when allowed is True.
    """
    if allowlist_networks and is_ip_allowlisted(ip_value, allowlist_networks):
        return False, "", "IP is allowlisted - not blocked"

    is_uae, country, error = determine_uae_status(ip_value, uae_networks)

    if is_uae:
        return False, country, f"IP geolocates to UAE ({country}) - not blocked per policy"

    if GEOIP_METHOD in ("network", "virustotal") and not country and error and GEOIP_LOOKUP_FAILURE_ACTION == "skip":
        return False, "", f"GeoIP lookup failed ({error}) - skipped per GEOIP_LOOKUP_FAILURE_ACTION=skip"

    return True, country, None


# ============================================================
# CSV INPUT
# ============================================================

def load_csv_rows(input_file):
    with open(input_file, mode="r", encoding="utf-8-sig", newline="") as csv_file:
        sample = csv_file.read(4096)
        csv_file.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(csv_file, dialect=dialect)

        if reader.fieldnames:
            reader.fieldnames = [
                field.strip().lower() if field else field for field in reader.fieldnames
            ]

        fieldnames = reader.fieldnames or []

        if "type" not in fieldnames:
            raise ValueError(f"CSV must contain a 'type' column. Found: {fieldnames}")

        value_column = "indicator" if "indicator" in fieldnames else "value"
        if value_column not in fieldnames:
            raise ValueError(
                "CSV must contain an 'indicator' (or 'value') column. "
                f"Found: {fieldnames}"
            )

        rows = list(reader)

    return rows, value_column


# ============================================================
# ROW PROCESSING
# ============================================================

def process_row(row_number, raw_type, raw_value, description):
    """
    Validates/auto-fixes one row and returns a base result dict (no
    Target_Tool/Status/Detail yet - process_file() clones this once
    per platform the IOC routes to) plus (ioc_type, fixed_value) - or
    None as the second item if the row can't be blocked at all.
    """
    result = {
        "Row": row_number,
        "Type": raw_type,
        "Original_Value": raw_value,
        "Fixed_Value": "",
        "Auto_Fixed": "No",
        "Description": description,
        "Target_Tool": "",
        "Country": "",
        "Status": "",
        "Detail": "",
        "Processed_At": "",
    }

    try:
        ioc_type = normalize_type(raw_type)
    except ValueError as error:
        result["Status"] = "Invalid"
        result["Detail"] = str(error)
        return result, None

    result["Type"] = ioc_type

    try:
        fixed_value, was_fixed = normalize_and_validate(ioc_type, raw_value)
    except ValueError as error:
        result["Status"] = "Invalid"
        result["Detail"] = f"Could not validate/auto-correct: {error}"
        return result, None

    result["Fixed_Value"] = fixed_value
    result["Auto_Fixed"] = "Yes" if was_fixed else "No"

    return result, (ioc_type, fixed_value)


# ============================================================
# FULL RUN
# ============================================================

RESULT_FIELDNAMES = [
    "Row",
    "Type",
    "Original_Value",
    "Fixed_Value",
    "Auto_Fixed",
    "Description",
    "Target_Tool",
    "Country",
    "Status",
    "Detail",
    "Processed_At",
]

STATUS_KEYS = ("Blocked", "Failed", "Invalid", "Skipped", "Would Block")


def compute_summary_counts(results):
    """Returns (by_status, by_type) count dicts, shared by the console
    summary and the workbook's Summary sheet."""
    by_status = {}
    by_type = {}

    for row in results:
        by_status[row["Status"]] = by_status.get(row["Status"], 0) + 1
        by_type.setdefault(row["Type"], {key: 0 for key in STATUS_KEYS})
        status = row["Status"]
        if status in by_type[row["Type"]]:
            by_type[row["Type"]][status] += 1

    return by_status, by_type


def print_summary(results):
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    by_status, by_type = compute_summary_counts(results)

    print(f"Total rows processed: {len(results)}")
    for status, count in sorted(by_status.items()):
        print(f"  {status:<12}: {count}")

    print()
    print(
        f"{'Type':<10} {'Blocked':<10} {'Failed':<10} {'Invalid':<10} "
        f"{'Skipped':<10} {'Would Block':<12}"
    )
    for ioc_type, counts in sorted(by_type.items()):
        print(
            f"{ioc_type:<10} {counts['Blocked']:<10} {counts['Failed']:<10} "
            f"{counts['Invalid']:<10} {counts['Skipped']:<10} {counts['Would Block']:<12}"
        )


# ============================================================
# STDLIB .XLSX FALLBACK (used when openpyxl isn't installed)
# ============================================================
#
# A minimal, hand-rolled .xlsx writer: just zipfile + string-built
# OOXML XML, both standard library. Not a general-purpose xlsx
# library - it implements exactly the small slice of openpyxl's API
# that _write_detail_sheet()/_write_summary_sheet()/_autofit_columns()
# below use (Workbook, worksheet.append(), worksheet[1]/["A1"],
# worksheet.columns, column_dimensions[...].width, freeze_panes,
# Font(bold=...), PatternFill(...)) so those three functions work
# unchanged no matter which backend is active.

def _stdlib_xlsx_column_letter(index):
    """1-indexed column number -> spreadsheet column letters (1->A, 27->AA)."""
    letters = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _stdlib_xlsx_column_index(letters):
    """Spreadsheet column letters -> 1-indexed column number (inverse of the above)."""
    index = 0
    for char in letters:
        index = index * 26 + (ord(char.upper()) - 64)
    return index


class _StdlibXlsxFont:
    def __init__(self, bold=False, size=11):
        self.bold = bold
        self.size = size


class _StdlibXlsxPatternFill:
    def __init__(self, start_color=None, end_color=None, fill_type=None):
        self.start_color = start_color
        self.fill_type = fill_type


class _StdlibXlsxCell:
    __slots__ = ("value", "font", "fill", "column_letter")

    def __init__(self, value=None, column_letter=""):
        self.value = value
        self.font = None
        self.fill = None
        self.column_letter = column_letter


class _StdlibXlsxColumnDimension:
    def __init__(self):
        self.width = None


class _StdlibXlsxColumnDimensions(dict):
    def __getitem__(self, key):
        if key not in self:
            dict.__setitem__(self, key, _StdlibXlsxColumnDimension())
        return dict.__getitem__(self, key)


class _StdlibXlsxWorksheet:
    def __init__(self, title):
        self.title = title
        self.rows = []
        self.freeze_panes = None
        self.column_dimensions = _StdlibXlsxColumnDimensions()

    def append(self, values):
        self.rows.append([_StdlibXlsxCell(value, _stdlib_xlsx_column_letter(i + 1)) for i, value in enumerate(values)])

    @property
    def max_row(self):
        return len(self.rows)

    @property
    def columns(self):
        width = max((len(row) for row in self.rows), default=0)
        columns = []
        for col_index in range(width):
            column_cells = []
            for row in self.rows:
                if col_index < len(row):
                    column_cells.append(row[col_index])
                else:
                    column_cells.append(_StdlibXlsxCell(None, _stdlib_xlsx_column_letter(col_index + 1)))
            columns.append(column_cells)
        return columns

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.rows[key - 1]

        letters = "".join(ch for ch in key if ch.isalpha())
        row_number = int("".join(ch for ch in key if ch.isdigit()))
        col_index = _stdlib_xlsx_column_index(letters) - 1

        row = self.rows[row_number - 1]
        while len(row) <= col_index:
            row.append(_StdlibXlsxCell(None, _stdlib_xlsx_column_letter(len(row) + 1)))
        return row[col_index]


class _StdlibXlsxWorkbook:
    def __init__(self):
        self._sheets = [_StdlibXlsxWorksheet("Sheet")]

    @property
    def active(self):
        return self._sheets[0]

    def create_sheet(self, title):
        sheet = _StdlibXlsxWorksheet(title)
        self._sheets.append(sheet)
        return sheet

    def save(self, output_file):
        _stdlib_xlsx_save(self._sheets, output_file)


def _stdlib_xlsx_cell_style_key(cell):
    bold = bool(cell.font and cell.font.bold)
    size = cell.font.size if (cell.font and cell.font.bold) else 11
    filled = bool(cell.fill and cell.fill.fill_type)
    return (bold, size, filled)


def _stdlib_xlsx_sheet_xml(worksheet, style_index):
    column_widths = []
    for letters, dimension in worksheet.column_dimensions.items():
        if dimension.width:
            column_widths.append((_stdlib_xlsx_column_index(letters), dimension.width))
    column_widths.sort()

    cols_xml = ""
    if column_widths:
        cols_xml = "<cols>" + "".join(
            f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>' for index, width in column_widths
        ) + "</cols>"

    view_xml = "<sheetViews><sheetView workbookViewId=\"0\">"
    if worksheet.freeze_panes:
        view_xml += '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        view_xml += '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/>'
    view_xml += "</sheetView></sheetViews>"

    rows_xml = []
    for row_number, row in enumerate(worksheet.rows, start=1):
        cells_xml = []
        for cell in row:
            if cell.value is None or cell.value == "":
                continue
            style_attr = f' s="{style_index[_stdlib_xlsx_cell_style_key(cell)]}"'
            ref = f"{cell.column_letter}{row_number}"
            if isinstance(cell.value, (int, float)) and not isinstance(cell.value, bool):
                cells_xml.append(f'<c r="{ref}"{style_attr}><v>{cell.value}</v></c>')
            else:
                text = xml_escape(str(cell.value))
                cells_xml.append(f'<c r="{ref}" t="inlineStr"{style_attr}><is><t xml:space="preserve">{text}</t></is></c>')
        rows_xml.append(f'<row r="{row_number}">' + "".join(cells_xml) + "</row>")

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        + cols_xml + view_xml + "<sheetData>" + "".join(rows_xml) + "</sheetData>"
        "</worksheet>"
    )


def _stdlib_xlsx_styles_xml(style_index):
    # style_index maps (bold, size, filled) -> cellXfs index. Index 0
    # is always the default (no bold, size 11, no fill).
    fonts_xml = []
    fills_xml = ['<fill><patternFill patternType="none"/></fill>', '<fill><patternFill patternType="gray125"/></fill>']
    xfs_xml = []

    fill_id_for_filled = 2  # first two fill slots (0,1) are reserved by the xlsx spec
    fills_xml.append('<fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/><bgColor indexed="64"/></patternFill></fill>')

    for key, index in sorted(style_index.items(), key=lambda item: item[1]):
        bold, size, filled = key
        fonts_xml.append(f'<font><sz val="{size}"/><name val="Calibri"/>{"<b/>" if bold else ""}</font>')
        fill_id = fill_id_for_filled if filled else 0
        xfs_xml.append(
            f'<xf numFmtId="0" fontId="{index}" fillId="{fill_id}" borderId="0" xfId="0" '
            f'applyFont="1" applyFill="{"1" if filled else "0"}"/>'
        )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<fonts count="{len(fonts_xml)}">' + "".join(fonts_xml) + "</fonts>"
        f'<fills count="{len(fills_xml)}">' + "".join(fills_xml) + "</fills>"
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        f'<cellXfs count="{len(xfs_xml)}">' + "".join(xfs_xml) + "</cellXfs>"
        "</styleSheet>"
    )


def _stdlib_xlsx_save(sheets, output_file):
    import zipfile

    # Collect every distinct (bold, size, filled) style combo used
    # across all sheets, in first-seen order, and give each one a
    # cellXfs index - referenced by each cell's s="..." attribute.
    style_index = {(False, 11, False): 0}
    for sheet in sheets:
        for row in sheet.rows:
            for cell in row:
                key = _stdlib_xlsx_cell_style_key(cell)
                if key not in style_index:
                    style_index[key] = len(style_index)

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + "".join(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            for i in range(1, len(sheets) + 1)
        )
        + "</Types>"
    )

    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<sheets>"
        + "".join(
            f'<sheet name="{xml_escape(sheet.title)}" sheetId="{i}" r:id="rId{i}"/>'
            for i, sheet in enumerate(sheets, start=1)
        )
        + "</sheets></workbook>"
    )

    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(
            f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>'
            for i in range(1, len(sheets) + 1)
        )
        + f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        "</Relationships>"
    )

    with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", workbook_xml)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/styles.xml", _stdlib_xlsx_styles_xml(style_index))
        for i, sheet in enumerate(sheets, start=1):
            archive.writestr(f"xl/worksheets/sheet{i}.xml", _stdlib_xlsx_sheet_xml(sheet, style_index))


def _xlsx_backend():
    """
    Returns (Workbook, Font, PatternFill) - from openpyxl if it's
    installed, otherwise from the pure-stdlib fallback above (zero
    pip installs needed, which matters on an air-gapped machine).
    Same three names either way, so _write_detail_sheet(),
    _write_summary_sheet() and write_results_workbook() below never
    need to know which backend is actually in use.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill

        return Workbook, Font, PatternFill
    except ImportError:
        return _StdlibXlsxWorkbook, _StdlibXlsxFont, _StdlibXlsxPatternFill


def _autofit_columns(worksheet):
    for column_cells in worksheet.columns:
        length = max((len(str(cell.value)) for cell in column_cells if cell.value is not None), default=8)
        worksheet.column_dimensions[column_cells[0].column_letter].width = min(length + 2, 60)


def _write_detail_sheet(worksheet, rows):
    _, Font, PatternFill = _xlsx_backend()

    header_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")

    worksheet.append(RESULT_FIELDNAMES)
    for cell in worksheet[1]:
        cell.font = Font(bold=True)
        cell.fill = header_fill

    for row in rows:
        worksheet.append([row.get(field, "") for field in RESULT_FIELDNAMES])

    worksheet.freeze_panes = "A2"
    _autofit_columns(worksheet)


def _write_summary_sheet(worksheet, results):
    _, Font, PatternFill = _xlsx_backend()

    header_fill = PatternFill(start_color="DDEBF7", end_color="DDEBF7", fill_type="solid")
    bold = Font(bold=True)

    by_status, by_type = compute_summary_counts(results)

    worksheet.append(["Threat Intel IOC Blocker - Run Summary"])
    worksheet["A1"].font = Font(bold=True, size=14)
    worksheet.append([f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}"])
    worksheet.append([f"Total rows processed: {len(results)}"])
    worksheet.append([])

    worksheet.append(["Status", "Count"])
    for cell in worksheet[worksheet.max_row]:
        cell.font = bold
        cell.fill = header_fill
    for status in STATUS_KEYS:
        worksheet.append([status, by_status.get(status, 0)])
    # Any status not in the known list (shouldn't normally happen) still gets counted.
    for status, count in sorted(by_status.items()):
        if status not in STATUS_KEYS:
            worksheet.append([status, count])

    worksheet.append([])

    header_row = ["Type"] + list(STATUS_KEYS)
    worksheet.append(header_row)
    for cell in worksheet[worksheet.max_row]:
        cell.font = bold
        cell.fill = header_fill
    for ioc_type, counts in sorted(by_type.items()):
        worksheet.append([ioc_type] + [counts[key] for key in STATUS_KEYS])

    _autofit_columns(worksheet)


def write_results_workbook(output_file, results):
    """
    Writes the run's results as an .xlsx workbook with four sheets:
        Summary      - counts by status, and by IOC type x status
        Blocked      - every row that was successfully blocked
        Not Blocked  - everything else (Failed/Invalid/Skipped/Would Block)
        All Results  - every row, unfiltered (the full detail)

    Uses openpyxl if it's installed, otherwise the stdlib-only
    fallback writer above - see _xlsx_backend().
    """
    Workbook, _, _ = _xlsx_backend()

    workbook = Workbook()

    summary_sheet = workbook.active
    summary_sheet.title = "Summary"
    _write_summary_sheet(summary_sheet, results)

    blocked_sheet = workbook.create_sheet("Blocked")
    _write_detail_sheet(blocked_sheet, [row for row in results if row["Status"] == "Blocked"])

    not_blocked_sheet = workbook.create_sheet("Not Blocked")
    _write_detail_sheet(not_blocked_sheet, [row for row in results if row["Status"] != "Blocked"])

    all_results_sheet = workbook.create_sheet("All Results")
    _write_detail_sheet(all_results_sheet, results)

    workbook.save(output_file)


def process_file(input_file, dry_run):
    rows, value_column = load_csv_rows(input_file)

    print()
    print("=" * 72)
    print("DRY RUN - VALIDATE & AUTO-FIX ONLY" if dry_run else "IOC BLOCK RUN")
    print("=" * 72)
    print(f"Input file : {input_file}")
    print(f"Row count  : {len(rows)}")

    # Pre-scan: which IOC types are actually present, so we only ask
    # for credentials the CSV's IOC types actually require.
    present_types = set()
    for row in rows:
        try:
            present_types.add(normalize_type(row.get("type", "")))
        except ValueError:
            continue

    if not dry_run:
        validate_fortigate_site_configuration("DC")
        validate_fortigate_site_configuration("DR")
        validate_paloalto_configuration()

        if present_types & ROUTE_TO_APEX:
            validate_apex_configuration()

        validate_platform_coverage(present_types)

        if GEOIP_METHOD == "virustotal" and "IP" in present_types:
            validate_virustotal_configuration()

    allowlist_networks = []
    if IP_ALLOWLIST_FILE:
        allowlist_networks = load_ip_allowlist(IP_ALLOWLIST_FILE)
        print(f"IP allowlist: {len(allowlist_networks)} entr{'y' if len(allowlist_networks) == 1 else 'ies'} loaded from {IP_ALLOWLIST_FILE}")

    uae_networks = []
    if GEOIP_METHOD == "offline":
        if UAE_CIDR_FILE:
            uae_networks = load_cidr_list_file(UAE_CIDR_FILE)
            print(f"UAE geo-block: offline mode, {len(uae_networks)} range(s) loaded from {UAE_CIDR_FILE}")
        else:
            print("UAE geo-block: disabled (GEOIP_METHOD=offline but UAE_CIDR_FILE is not set)")
    elif GEOIP_METHOD == "virustotal":
        print(f"UAE geo-block: VirusTotal mode (lookup failure -> {GEOIP_LOOKUP_FAILURE_ACTION})")
    else:
        print(f"UAE geo-block: network mode (live RDAP/WHOIS lookup, lookup failure -> {GEOIP_LOOKUP_FAILURE_ACTION})")

    results = []

    for row_number, row in enumerate(rows, start=2):
        raw_type = (row.get("type") or "").strip()
        raw_value = (row.get(value_column) or "").strip()
        description = (row.get("description") or "").strip()

        if not raw_type and not raw_value:
            continue

        print()
        print("-" * 72)
        print(f"[Row {row_number}] type={raw_type!r} value={raw_value!r}")

        base_result, route = process_row(row_number, raw_type, raw_value, description)
        base_result["Processed_At"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

        if route is None:
            print(f"  INVALID - {base_result['Detail']}")
            results.append(base_result)
            continue

        ioc_type, fixed_value = route

        if base_result["Auto_Fixed"] == "Yes":
            print(f"  Auto-fixed: {raw_value!r} -> {fixed_value!r}")

        if ioc_type == "IP":
            allowed, country, skip_reason = check_ip_safeguards(fixed_value, allowlist_networks, uae_networks)
            base_result["Country"] = country

            if not allowed:
                base_result["Status"] = "Skipped"
                base_result["Detail"] = skip_reason
                print(f"  SKIPPED - {skip_reason}")
                results.append(base_result)
                continue

            if country:
                print(f"  Country: {country}")

        # An IOC type can route to more than one platform (e.g. an IP
        # goes to FortiGate DC, FortiGate DR, and Palo Alto) - each
        # attempt below gets its own row in the results CSV. In dry
        # run, show every platform the type *could* go to, even ones
        # not currently configured, so the preview is complete.
        targets = BASE_ROUTES.get(ioc_type, []) if dry_run else targets_for_type(ioc_type)

        if not targets:
            row = dict(base_result)
            row["Status"] = "Failed"
            row["Detail"] = f"No configured platform for type {ioc_type}"
            print(f"  FAILED - {row['Detail']}")
            results.append(row)
            continue

        for target in targets:
            row = dict(base_result)
            row["Target_Tool"] = TARGET_LABEL[target]

            if dry_run:
                row["Status"] = "Would Block"
                row["Detail"] = f"Would send to {row['Target_Tool']}"
                print(f"  {row['Detail']}")
                results.append(row)
                continue

            comment = (description or DEFAULT_NOTE) if target == "APEX" else description
            success, detail = BLOCK_FUNCTIONS[target](ioc_type, fixed_value, comment)

            row["Status"] = "Blocked" if success else "Failed"
            row["Detail"] = detail

            print(f"  [{row['Target_Tool']}] [{'BLOCKED' if success else 'FAILED'}] {detail}")

            results.append(row)

    if not dry_run:
        commit_result = commit_paloalto_changes()
        if commit_result is not None:
            commit_success, commit_detail = commit_result
            print()
            print("=" * 72)
            print("PALO ALTO COMMIT")
            print("=" * 72)
            print(("SUCCESS - " if commit_success else "FAILED - ") + commit_detail)
            if not commit_success:
                print("WARNING: Palo Alto address/group changes were staged but NOT")
                print("committed - review and commit manually via the Palo Alto UI/CLI.")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{os.path.splitext(input_file)[0]}_results_{timestamp}.xlsx"
    write_results_workbook(output_file, results)

    print_summary(results)

    print()
    print(f"Results saved: {output_file}")

    return results


# ============================================================
# MENU
# ============================================================

def show_configuration():
    print()
    print("Trend Micro Apex Central")
    print("-" * 40)
    print("URL:", APEX_CENTRAL_URL or "NOT SET")
    print("Application ID:", "SET" if APEX_APPLICATION_ID else "NOT SET")
    print("API Key:", "SET" if APEX_API_KEY else "NOT SET")
    print("TLS verification:", APEX_VERIFY_TLS)

    for site_name in ("DC", "DR"):
        site = FORTIGATE_SITES[site_name]
        print()
        print(f"FortiGate {site_name}")
        print("-" * 40)
        print("Host:", site["host"] or "NOT SET")
        print("API Key:", "SET" if site["api_key"] else "NOT SET")
        print("VDOM:", site["vdom"])
        print("IP block group:", site["ip_group"])
        print("Domain block group:", site["domain_group"])
        print("TLS verification:", site["verify_tls"])
        print("Configured:", fortigate_site_configured(site_name))

    print()
    print("Palo Alto")
    print("-" * 40)
    print("Host:", PALOALTO_HOST or "NOT SET")
    print("API Key:", "SET" if PALOALTO_API_KEY else "NOT SET")
    print("Vsys:", PALOALTO_VSYS)
    print("IP block group:", PALOALTO_IP_GROUP)
    print("TLS verification:", PALOALTO_VERIFY_TLS)
    print("Configured:", paloalto_configured())

    print()
    print("Routing")
    print("-" * 40)
    print("IP                    -> FortiGate DC, FortiGate DR, Palo Alto (whichever are configured)")
    print("DOMAIN                -> FortiGate DC, FortiGate DR (whichever are configured)")
    print("URL, SHA1, SHA256     -> Trend Micro Apex Central")

    print()
    print("IP Safeguards")
    print("-" * 40)
    print("Allowlist file:", IP_ALLOWLIST_FILE or "NOT SET (no allowlist applied)")
    print("Blocked country codes skipped:", ", ".join(sorted(UAE_COUNTRY_CODES)))
    print("GeoIP method:", GEOIP_METHOD)
    if GEOIP_METHOD == "offline":
        print("UAE CIDR file:", UAE_CIDR_FILE or "NOT SET (UAE geo-block disabled)")
    elif GEOIP_METHOD == "virustotal":
        print("VT_API_KEY:", "SET" if VT_API_KEY else "NOT SET")
        print("VT request delay:", f"{VT_REQUEST_DELAY_SECONDS}s")
        print("On GeoIP lookup failure:", GEOIP_LOOKUP_FAILURE_ACTION)
    else:
        print("On GeoIP lookup failure:", GEOIP_LOOKUP_FAILURE_ACTION)
        try:
            import ipwhois  # noqa: F401
            print("Network lookup: ipwhois (RDAP)")
        except ImportError:
            print("Network lookup: built-in WHOIS fallback (pip install ipwhois for RDAP)")


def show_menu():
    while True:
        print()
        print("=" * 72)
        print("THREAT INTEL IOC BLOCKER - APEX CENTRAL + FORTIGATE (DC/DR) + PALO ALTO")
        print("=" * 72)

        print()
        print("1. Process CSV file (validate, auto-fix, block, save results CSV)")
        print("2. Dry-run CSV file (validate & auto-fix only, no blocking)")
        print("3. Show configuration")
        print("4. Exit")

        print()
        choice = input("Select option [1-4]: ").strip()

        if choice == "1":
            filename = input("\nEnter IOC CSV file: ").strip()
            if not filename:
                print("No file specified.")
                continue

            try:
                process_file(filename, dry_run=False)
            except Exception as error:
                print(f"\nERROR: {error}")

        elif choice == "2":
            filename = input("\nEnter IOC CSV file: ").strip()
            if not filename:
                print("No file specified.")
                continue

            try:
                process_file(filename, dry_run=True)
            except Exception as error:
                print(f"\nERROR: {error}")

        elif choice == "3":
            show_configuration()

        elif choice == "4":
            print("\nExiting.")
            break

        else:
            print("\nInvalid option.")


# ============================================================
# MAIN
# ============================================================

def main():
    try:
        show_menu()
    except KeyboardInterrupt:
        print("\n\nExiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()
