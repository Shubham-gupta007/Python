#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 2: Normalize, auto-fix and route one IOC

Takes one {"type": ..., "value": ...} item at a time (from step 1's
extraction, or straight from a clean CSV row) and:

    1. Auto-corrects defanged/malformed values (hxxp://, [.], spaced
       hashes, missing URL scheme, wrong case) - the exact same rules
       used by the CLI tools, so results stay consistent.
    2. Validates the fixed value actually matches its declared type.
       A value that still fails is marked invalid and is NOT routed
       anywhere.
    3. Says which platform block/unblock step should run next.

How to paste this into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function.
    2. Input parameters: ioc_type (string), raw_value (string)
    3. Output parameters: is_valid (boolean), fixed_value (string),
       auto_fixed (boolean), target_tool (string), error (string)
    4. Paste the body of normalize_validate_custom_function() into the
       generated stub.
    5. Feed step1's per-item type/value into this block's inputs -
       SOAR auto-loops this block once per item when its inputs are
       wired to a list (no manual for-loop needed in the playbook).
    6. Put a Decision block right after this one, branching on
       target_tool ("FORTIGATE" / "APEX") - that's the idiomatic SOAR
       way to route, rather than writing routing logic in code.
"""

import re
from urllib.parse import urlparse


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

ROUTE_TO_FORTIGATE = {"IP", "DOMAIN"}
ROUTE_TO_APEX = {"URL", "SHA1", "SHA256"}


def normalize_type(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("IOC 'type' is missing or empty.")

    key = value.strip().upper()

    if key not in TYPE_ALIASES:
        raise ValueError(
            f"Unsupported IOC type '{value}'. Supported: IP, DOMAIN "
            "(FortiGate), URL, SHA1, SHA256 (Trend Micro Apex Central)."
        )

    return TYPE_ALIASES[key]


def target_for_type(ioc_type):
    if ioc_type in ROUTE_TO_FORTIGATE:
        return "FORTIGATE"
    if ioc_type in ROUTE_TO_APEX:
        return "APEX"
    return ""


# ============================================================
# AUTO-FIX (DEFANG / FORMAT REPAIR)
# ============================================================

def strip_wrapping(value):
    return value.strip().strip("\"'<>").strip()


def defang_fix(value):
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
    return defang_fix(raw_value).rstrip(".").lower()


def fix_url(raw_value):
    value = defang_fix(raw_value)

    if not re.match(r"^https?://", value, flags=re.IGNORECASE):
        value = "http://" + value

    return value


def fix_hash(raw_value):
    value = defang_fix(raw_value)
    value = re.sub(r"[\s:-]", "", value)
    return value.upper()


# ============================================================
# VALIDATION
# ============================================================

def validate_ip(value):
    import ipaddress

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"Invalid IP address: {value}")

    if address.version != 4:
        raise ValueError(f"Expected IPv4, got IPv{address.version}: {value}")

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
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise ValueError("Indicator value is missing or empty.")

    original = raw_value.strip()
    fixed = FIXERS[ioc_type](raw_value)
    fixed = VALIDATORS[ioc_type](fixed)

    return fixed, fixed != original


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def normalize_validate_custom_function(ioc_type=None, raw_value=None, **kwargs):
    """
    Paste into the SOAR custom function editor.
    Inputs:  ioc_type (string), raw_value (string)
    Outputs: is_valid (boolean), fixed_value (string),
             auto_fixed (boolean), target_tool (string), error (string)
    """
    try:
        normalized_type = normalize_type(ioc_type)
        fixed_value, auto_fixed = normalize_and_validate(normalized_type, raw_value)
    except ValueError as error:
        return {
            "is_valid": False,
            "fixed_value": "",
            "auto_fixed": False,
            "target_tool": "",
            "error": str(error),
        }

    return {
        "is_valid": True,
        "fixed_value": fixed_value,
        "auto_fixed": auto_fixed,
        "target_tool": target_for_type(normalized_type),
        "error": "",
    }


if __name__ == "__main__":
    samples = [
        ("IP", "192.168.1[.]100"),
        ("URL", "evil-noscheme.example.com/x"),
        ("SHA1", "01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67"),
        ("IP", "999.999.999.999"),
    ]

    for ioc_type, raw_value in samples:
        print(ioc_type, raw_value, "->", normalize_validate_custom_function(ioc_type, raw_value))
