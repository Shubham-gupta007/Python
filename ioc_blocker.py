#!/usr/bin/env python3
"""
Threat Intel IOC Blocker - Trend Micro Apex Central + FortiGate

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

    4. Route the now-valid, non-allowlisted, non-UAE indicator to the
       right tool:

           IP, DOMAIN              -> FortiGate firewall
                                      (address object + address group)

           URL, SHA1, SHA256       -> Trend Micro Apex Central
                                      (User-Defined Suspicious Object)

    5. Write one results CSV you can open in Excel: original value,
       auto-corrected value, which tool it went to, the IP's country
       (when looked up), and whether it was blocked successfully - so
       a quick filter tells you exactly what succeeded, what was
       skipped, and what needs a human look.

Requirements:
    pip install requests

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

    FortiGate:
        FORTIGATE_HOST           e.g. "https://192.168.1.1:443"
        FORTIGATE_API_KEY
        FORTIGATE_VDOM           optional, default "root"
        FORTIGATE_IP_GROUP       optional, default "Blocked-IPs"
        FORTIGATE_DOMAIN_GROUP   optional, default "Blocked-Domains"
        FORTIGATE_VERIFY_TLS     optional, "true"/"false", default "false"

    Only the variables for the tool(s) actually needed by the CSV's
    IOC types are required - a CSV with only IPs/domains never asks
    for Apex Central credentials, and vice versa.

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

Output: <input file name>_results.csv, with columns:

    Row, Type, Original_Value, Fixed_Value, Auto_Fixed, Description,
    Target_Tool, Country, Status, Detail, Processed_At
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
from datetime import datetime, timezone
from urllib.parse import urlparse

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
# CONFIGURATION - FORTIGATE
# ============================================================

FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "")
FORTIGATE_API_KEY = os.environ.get("FORTIGATE_API_KEY", "")
FORTIGATE_VDOM = os.environ.get("FORTIGATE_VDOM", "root")
FORTIGATE_IP_GROUP = os.environ.get("FORTIGATE_IP_GROUP", "Blocked-IPs")
FORTIGATE_DOMAIN_GROUP = os.environ.get("FORTIGATE_DOMAIN_GROUP", "Blocked-Domains")
FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_VERIFY_TLS", "false").lower() == "true"

FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

if not APEX_VERIFY_TLS or not FORTIGATE_VERIFY_TLS:
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
# ROUTING - WHICH TOOL HANDLES WHICH IOC TYPE
# ============================================================

ROUTE_TO_FORTIGATE = {"IP", "DOMAIN"}
ROUTE_TO_APEX = {"URL", "SHA1", "SHA256"}

TARGET_LABEL = {
    "FORTIGATE": "FortiGate",
    "APEX": "Trend Micro Apex Central",
}


def target_for_type(ioc_type):
    if ioc_type in ROUTE_TO_FORTIGATE:
        return "FORTIGATE"
    if ioc_type in ROUTE_TO_APEX:
        return "APEX"
    return None


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


def validate_fortigate_configuration():
    missing = [
        name
        for name, value in (
            ("FORTIGATE_HOST", FORTIGATE_HOST),
            ("FORTIGATE_API_KEY", FORTIGATE_API_KEY),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing FortiGate environment variable(s): " + ", ".join(missing)
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
            f"Unsupported IOC type '{value}'. Supported: IP, DOMAIN "
            "(blocked on FortiGate), URL, SHA1, SHA256 (blocked on "
            "Trend Micro Apex Central)."
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
# FORTIGATE - BLOCK
# ============================================================

def fortigate_api_headers():
    return {
        "Authorization": f"Bearer {FORTIGATE_API_KEY}",
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


def fortigate_create_or_update_address(payload):
    name = payload["name"]
    url = f"{FORTIGATE_HOST}{FORTIGATE_ADDRESS_PATH}"

    response = requests.post(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        json=payload,
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code == 200:
        return True, response

    if response.status_code == 500 and fortigate_is_duplicate(response):
        response = requests.put(
            f"{url}/{name}",
            headers=fortigate_api_headers(),
            params={"vdom": FORTIGATE_VDOM},
            json=payload,
            verify=FORTIGATE_VERIFY_TLS,
            timeout=30,
        )
        return response.status_code == 200, response

    return False, response


def fortigate_add_to_group(group_name, member_name):
    url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"

    response = requests.get(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        verify=FORTIGATE_VERIFY_TLS,
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
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        json=payload,
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code == 200:
        return True, f"added to group '{group_name}'"

    return False, f"HTTP {response.status_code} - could not update group '{group_name}'"


def block_via_fortigate(ioc_type, value, comment):
    """Returns (success, detail_text)."""
    payload = build_fortigate_payload(ioc_type, value, comment)

    success, response = fortigate_create_or_update_address(payload)

    if not success:
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return False, f"HTTP {response.status_code} - address object failed: {body}"

    group = FORTIGATE_IP_GROUP if ioc_type == "IP" else FORTIGATE_DOMAIN_GROUP
    group_success, group_detail = fortigate_add_to_group(group, value)

    address_type = "ipmask" if ioc_type == "IP" else "fqdn"
    detail = f"HTTP {response.status_code} - {address_type} address created/updated, {group_detail}"

    return group_success, detail


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
    Validates/auto-fixes one row and returns a result dict ready for
    the results CSV, plus (ioc_type, fixed_value, target) to block -
    or None as the second item if the row can't be blocked at all.
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

    target = target_for_type(ioc_type)
    result["Target_Tool"] = TARGET_LABEL[target]

    return result, (ioc_type, fixed_value, target)


# ============================================================
# FULL RUN
# ============================================================

def write_results_csv(output_file, results):
    fieldnames = [
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

    with open(output_file, mode="w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_summary(results):
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    by_status = {}
    by_type = {}

    status_keys = ("Blocked", "Failed", "Invalid", "Skipped", "Would Block")

    for row in results:
        by_status[row["Status"]] = by_status.get(row["Status"], 0) + 1
        by_type.setdefault(row["Type"], {key: 0 for key in status_keys})
        status = row["Status"]
        if status in by_type[row["Type"]]:
            by_type[row["Type"]][status] += 1

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


def process_file(input_file, dry_run):
    rows, value_column = load_csv_rows(input_file)

    print()
    print("=" * 72)
    print("DRY RUN - VALIDATE & AUTO-FIX ONLY" if dry_run else "IOC BLOCK RUN")
    print("=" * 72)
    print(f"Input file : {input_file}")
    print(f"Row count  : {len(rows)}")

    # Pre-scan: which tool(s) will actually be needed, so we only ask
    # for credentials the CSV's IOC types actually require.
    needed_targets = set()
    for row in rows:
        try:
            ioc_type = normalize_type(row.get("type", ""))
            target = target_for_type(ioc_type)
            if target:
                needed_targets.add(target)
        except ValueError:
            continue

    if not dry_run:
        if "APEX" in needed_targets:
            validate_apex_configuration()
        if "FORTIGATE" in needed_targets:
            validate_fortigate_configuration()
        if GEOIP_METHOD == "virustotal" and "IP" in {(row.get("type") or "").strip().upper() for row in rows}:
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

        result, route = process_row(row_number, raw_type, raw_value, description)
        result["Processed_At"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

        if route is None:
            print(f"  INVALID - {result['Detail']}")
            results.append(result)
            continue

        ioc_type, fixed_value, target = route

        if result["Auto_Fixed"] == "Yes":
            print(f"  Auto-fixed: {raw_value!r} -> {fixed_value!r}")

        if ioc_type == "IP":
            allowed, country, skip_reason = check_ip_safeguards(fixed_value, allowlist_networks, uae_networks)
            result["Country"] = country

            if not allowed:
                result["Status"] = "Skipped"
                result["Detail"] = skip_reason
                print(f"  SKIPPED - {skip_reason}")
                results.append(result)
                continue

            if country:
                print(f"  Country: {country}")

        if dry_run:
            result["Status"] = "Would Block"
            result["Detail"] = f"Would send to {result['Target_Tool']}"
            print(f"  {result['Detail']}")
            results.append(result)
            continue

        if target == "APEX":
            note = description or DEFAULT_NOTE
            success, detail = block_via_apex(ioc_type, fixed_value, note)
        else:
            success, detail = block_via_fortigate(ioc_type, fixed_value, description)

        result["Status"] = "Blocked" if success else "Failed"
        result["Detail"] = detail

        print(f"  [{'BLOCKED' if success else 'FAILED'}] {detail}")

        results.append(result)

    output_file = os.path.splitext(input_file)[0] + "_results.csv"
    write_results_csv(output_file, results)

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

    print()
    print("FortiGate")
    print("-" * 40)
    print("Host:", FORTIGATE_HOST or "NOT SET")
    print("API Key:", "SET" if FORTIGATE_API_KEY else "NOT SET")
    print("VDOM:", FORTIGATE_VDOM)
    print("IP block group:", FORTIGATE_IP_GROUP)
    print("Domain block group:", FORTIGATE_DOMAIN_GROUP)
    print("TLS verification:", FORTIGATE_VERIFY_TLS)

    print()
    print("Routing")
    print("-" * 40)
    print("IP, DOMAIN            -> FortiGate")
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
        print("THREAT INTEL IOC BLOCKER - APEX CENTRAL + FORTIGATE")
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
