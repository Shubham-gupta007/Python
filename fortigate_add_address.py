#!/usr/bin/env python3
"""
FortiGate Firewall - IOC Blocker (IP / Domain) via REST API

Reads an IOC JSON file (the same {type, value, description} shape produced
by ioc_csv_to_json.py / apexcentral_ioc_blocker.py) and, for each entry:

    IP      -> creates an "ipmask" firewall address object and adds it
               to the IP block address group (IP_GROUP)

    DOMAIN  -> creates an "fqdn" firewall address object and adds it
               to the domain block address group (DOMAIN_GROUP)

    other   -> skipped (FortiGate address objects only block IP/DOMAIN;
               URL/SHA1/SHA256 are not applicable here)

For every entry, "value" is used as the address object's name and
"description" is used as its comment.

Authentication: API key via "Authorization: Bearer <key>" header.

Docs: https://fndn.fortinet.net -> FortiOS REST API -> cmdb/firewall/address

Requirements:
    pip install requests

Environment variables:

    FORTIGATE_HOST      e.g. "https://192.168.1.1:443" (no trailing slash)
    FORTIGATE_API_KEY   REST API admin's API key
    FORTIGATE_VDOM       optional, defaults to "root"
    FORTIGATE_IP_GROUP     optional, defaults to "Blocked-IPs"
    FORTIGATE_DOMAIN_GROUP optional, defaults to "Blocked-Domains"
    FORTIGATE_VERIFY_TLS   optional, "true"/"false", defaults to "false"

Both address groups must already exist on the FortiGate (create them once,
and reference them in your deny/DNS-filter/web-filter policies).

Run:

    python3 fortigate_add_address.py

    The program will ask for the IOC JSON file to process.

Non-interactive / scripted use:

    python3 fortigate_add_address.py --file iocs.json
    python3 fortigate_add_address.py --file iocs.json --dry-run

Input JSON format:

    [
        {"type": "IP", "value": "203.0.113.50", "description": "C2 server"},
        {"type": "DOMAIN", "value": "evil.example.com", "description": "Phishing"}
    ]
"""

import argparse
import ipaddress
import json
import os
import re
import sys

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# ============================================================
# CONFIGURATION
# ============================================================

FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "")
API_KEY = os.environ.get("FORTIGATE_API_KEY", "")
VDOM = os.environ.get("FORTIGATE_VDOM", "root")

# Address groups that IP / domain address objects are added to so a
# firewall/DNS-filter/web-filter policy can reference just the group.
IP_GROUP = os.environ.get("FORTIGATE_IP_GROUP", "Blocked-IPs")
DOMAIN_GROUP = os.environ.get("FORTIGATE_DOMAIN_GROUP", "Blocked-Domains")

# Set to True only if the FortiGate's certificate is trusted/valid.
VERIFY_TLS = os.environ.get("FORTIGATE_VERIFY_TLS", "false").lower() == "true"

ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

if not VERIFY_TLS:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def validate_configuration():
    missing = [
        name
        for name, value in (
            ("FORTIGATE_HOST", FORTIGATE_HOST),
            ("FORTIGATE_API_KEY", API_KEY),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing environment variable(s): " + ", ".join(missing)
        )


def api_headers():
    return {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }


# ============================================================
# TYPE NORMALIZATION
# ============================================================

# Only IP and DOMAIN map to a FortiGate address object type. Other IOC
# types (URL, SHA1, SHA256, ...) aren't something a firewall "address"
# object can represent, so they're rejected here rather than silently
# mishandled.
TYPE_ALIASES = {
    "IP": "IP",
    "IP_ADDRESS": "IP",
    "IP ADDRESS": "IP",
    "DOMAIN": "DOMAIN",
    "FQDN": "DOMAIN",
}


def normalize_type(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("IOC 'type' is missing or empty.")

    key = value.strip().upper()

    if key not in TYPE_ALIASES:
        raise ValueError(
            f"Type '{value}' is not supported for FortiGate address "
            "blocking (only IP and DOMAIN are)."
        )

    return TYPE_ALIASES[key]


# ============================================================
# VALUE VALIDATION
# ============================================================

def normalize_subnet(value):
    """
    Accepts a bare IP ("203.0.113.50") or CIDR ("203.0.113.0/24") and
    returns the FortiGate-style "subnet" string: "<ip> <netmask>".
    """
    value = value.strip()

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError(f"Invalid IP address/subnet: {value}")

    if network.version != 4:
        raise ValueError(f"Only IPv4 is supported here, got: {value}")

    return f"{network.network_address} {network.netmask}"


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def validate_domain(value):
    value = value.strip().lower()

    if value.endswith("."):
        value = value[:-1]

    if not DOMAIN_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid domain: {value}")

    return value


# ============================================================
# PAYLOAD BUILDERS
# ============================================================

def build_ip_payload(value, comment):
    return {
        "name": value,
        "type": "ipmask",
        "subnet": normalize_subnet(value),
        "comment": comment or "",
    }


def build_domain_payload(value, comment):
    domain = validate_domain(value)
    return {
        "name": domain,
        "type": "fqdn",
        "fqdn": domain,
        "comment": comment or "",
    }


def build_payload(ioc_type, value, comment):
    """
    ioc_type must already be normalized ("IP" or "DOMAIN").
    "value" becomes the address object's name; "comment" (the IOC's
    description) becomes the address object's comment.
    """
    if ioc_type == "IP":
        return build_ip_payload(value, comment)

    if ioc_type == "DOMAIN":
        return build_domain_payload(value, comment)

    raise ValueError(f"Unsupported IOC type: {ioc_type}")


def group_for_type(ioc_type):
    return IP_GROUP if ioc_type == "IP" else DOMAIN_GROUP


# ============================================================
# REQUESTS
# ============================================================

def create_or_update_address(payload):
    """
    Creates the address object. If it already exists, updates it instead
    (FortiGate rejects a duplicate "name" on POST).
    """
    name = payload["name"]
    url = f"{FORTIGATE_HOST}{ADDRESS_PATH}"

    response = requests.post(
        url,
        headers=api_headers(),
        params={"vdom": VDOM},
        json=payload,
        verify=VERIFY_TLS,
        timeout=30,
    )

    if response.status_code == 200:
        return _result(True, response, payload, "created")

    # -5 = entry already exists -> fall back to PUT (update).
    if response.status_code == 500 and _is_duplicate(response):
        update_url = f"{url}/{name}"
        response = requests.put(
            update_url,
            headers=api_headers(),
            params={"vdom": VDOM},
            json=payload,
            verify=VERIFY_TLS,
            timeout=30,
        )
        return _result(response.status_code == 200, response, payload, "updated")

    return _result(False, response, payload, "failed")


def add_to_group(group_name, member_name):
    """
    Appends member_name to an existing address group's member list.
    Fetches the group first so existing members aren't clobbered.
    Works for both "ipmask" and "fqdn" members - a group just
    references member names.
    """
    url = f"{FORTIGATE_HOST}{GROUP_PATH}/{group_name}"

    response = requests.get(
        url,
        headers=api_headers(),
        params={"vdom": VDOM},
        verify=VERIFY_TLS,
        timeout=30,
    )

    if response.status_code != 200:
        return _result(False, response, {"group": group_name}, "group_lookup_failed")

    body = response.json()
    results = body.get("results", [])
    existing_members = [m["name"] for m in results[0].get("member", [])] if results else []

    if member_name in existing_members:
        return {"success": True, "action": "already_member", "group": group_name}

    payload = {"member": [{"name": m} for m in existing_members + [member_name]]}

    response = requests.put(
        url,
        headers=api_headers(),
        params={"vdom": VDOM},
        json=payload,
        verify=VERIFY_TLS,
        timeout=30,
    )

    return _result(response.status_code == 200, response, payload, "group_updated")


def _is_duplicate(response):
    try:
        return response.json().get("error") == -5
    except ValueError:
        return False


def _result(success, response, request_body, action):
    try:
        body = response.json()
    except ValueError:
        body = response.text

    return {
        "success": success,
        "action": action,
        "http_status": response.status_code,
        "response": body,
        "request": request_body,
    }


# ============================================================
# BULK INPUT
# ============================================================

def load_ioc_file(filename):
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("Input JSON must contain an array.")

    return data


# ============================================================
# PROCESSING
# ============================================================

def process_entry(entry, dry_run):
    """
    Validates one {type, value, description} entry, then creates the
    matching address object and adds it to the type's block group.
    Returns (status, ioc_type_or_None) where status is one of:
    "blocked", "skipped", "failed".
    """
    raw_type = entry.get("type", "")
    value = entry.get("value", "")
    comment = entry.get("description", "") or ""

    try:
        ioc_type = normalize_type(raw_type)
    except ValueError as error:
        print(f"[SKIPPED] {value or '(no value)'}: {error}")
        return "skipped", None

    if not value or not isinstance(value, str):
        print(f"[SKIPPED] entry missing 'value': {entry}")
        return "skipped", ioc_type

    try:
        payload = build_payload(ioc_type, value, comment)
    except ValueError as error:
        print(f"[SKIPPED] {value}: {error}")
        return "skipped", ioc_type

    group = group_for_type(ioc_type)

    if dry_run:
        print(f"[DRY RUN] {ioc_type} -> would create/update address:\n{json.dumps(payload, indent=2)}")
        print(f"[DRY RUN] would ensure '{payload['name']}' is a member of group '{group}'")
        return "blocked", ioc_type

    result = create_or_update_address(payload)
    status = "OK" if result["success"] else "FAILED"
    print(f"[{status}] {ioc_type} {payload['name']} -> {result['action']} (HTTP {result['http_status']})")

    if not result["success"]:
        print(f"  response: {result['response']}")
        return "failed", ioc_type

    group_result = add_to_group(group, payload["name"])
    group_status = "OK" if group_result["success"] else "FAILED"
    print(f"  [{group_status}] group '{group}' membership -> {group_result.get('action')}")

    if not group_result["success"]:
        return "failed", ioc_type

    return "blocked", ioc_type


def process_file(filename, dry_run):
    entries = load_ioc_file(filename)

    print()
    print("=" * 72)
    print("FORTIGATE IOC BLOCK")
    print("=" * 72)
    print(f"Input file : {filename}")
    print(f"IOC count  : {len(entries)}")
    print(f"IP group   : {IP_GROUP}")
    print(f"Domain group: {DOMAIN_GROUP}")

    counts = {"blocked": 0, "skipped": 0, "failed": 0}

    for index, entry in enumerate(entries, start=1):
        print()
        print("-" * 72)
        print(f"[{index}] {entry.get('type')}: {entry.get('value')}")

        status, _ = process_entry(entry, dry_run)
        counts[status] += 1

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Blocked : {counts['blocked']}")
    print(f"Skipped : {counts['skipped']}")
    print(f"Failed  : {counts['failed']}")

    return counts


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Block IOCs (IP/DOMAIN) on a FortiGate firewall from a JSON file."
    )
    parser.add_argument("--file", help="IOC JSON file ({type, value, description} entries)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be sent without calling the API")

    args = parser.parse_args()

    filename = args.file
    if not filename:
        filename = input("Enter IOC JSON file: ").strip()

    if not filename:
        print("No file specified.")
        sys.exit(1)

    if not args.dry_run:
        try:
            validate_configuration()
        except RuntimeError as error:
            print(f"ERROR: {error}")
            sys.exit(1)

    try:
        counts = process_file(filename, args.dry_run)
    except Exception as error:
        print(f"\nERROR: {error}")
        sys.exit(1)

    if counts["failed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
