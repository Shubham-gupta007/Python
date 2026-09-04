#!/usr/bin/env python3
"""
FortiGate Firewall - Add IP Address Object via REST API

Creates (or updates) a firewall address object on a FortiGate using the
FortiOS REST API, authenticating with an API key (Bearer token).

Docs: https://fndn.fortinet.net -> FortiOS REST API -> cmdb/firewall/address

Requirements:
    pip install requests

Environment variables:
    FORTIGATE_HOST     e.g. "https://192.168.1.1:443"  (no trailing slash)
    FORTIGATE_API_KEY  REST API admin's API key
    FORTIGATE_VDOM     optional, defaults to "root"

Usage:

    # Add a single IP (defaults to a /32 host address)
    python3 fortigate_add_address.py --ip 203.0.113.50 --name Malicious-IP-1

    # Add a subnet, with a comment, and place it in an address group
    python3 fortigate_add_address.py --ip 203.0.113.0/24 --name Bad-Net-1 \
        --comment "Blocklist feed" --group Blocked-IPs

    # Bulk add from a JSON file (see load_ioc_file() for the expected shape)
    python3 fortigate_add_address.py --file iocs.json --group Blocked-IPs

    # Preview the API calls without sending anything
    python3 fortigate_add_address.py --file iocs.json --dry-run

Bulk input JSON format:

    [
        {"name": "Malicious-IP-1", "ip": "203.0.113.50", "comment": "C2 server"},
        {"name": "Bad-Net-1", "ip": "203.0.113.0/24", "comment": "Scanner range"}
    ]
"""

import argparse
import ipaddress
import json
import os
import sys

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# ============================================================
# CONFIGURATION
# ============================================================

FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "")
API_KEY = os.environ.get("FORTIGATE_API_KEY", "")
VDOM = os.environ.get("FORTIGATE_VDOM", "root")

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
# VALIDATION
# ============================================================

def normalize_subnet(value):
    """
    Accepts a bare IP ("203.0.113.50") or CIDR ("203.0.113.0/24") and
    returns the FortiGate-style "subnet" string: "<ip> <netmask>".
    """
    value = value.strip()
    network = ipaddress.ip_network(value, strict=False)

    if network.version != 4:
        raise ValueError(f"Only IPv4 is supported here, got: {value}")

    return f"{network.network_address} {network.netmask}"


# ============================================================
# PAYLOAD / REQUESTS
# ============================================================

def build_payload(name, ip_value, comment):
    return {
        "name": name,
        "type": "ipmask",
        "subnet": normalize_subnet(ip_value),
        "comment": comment or "",
    }


def create_or_update_address(name, ip_value, comment):
    """
    Creates the address object. If it already exists, updates it instead
    (FortiGate rejects a duplicate "name" on POST).
    """
    payload = build_payload(name, ip_value, comment)
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
# MAIN
# ============================================================

def process_one(name, ip_value, comment, group, dry_run):
    if dry_run:
        payload = build_payload(name, ip_value, comment)
        print(f"[DRY RUN] Would create/update address:\n{json.dumps(payload, indent=2)}")
        if group:
            print(f"[DRY RUN] Would ensure '{name}' is a member of group '{group}'")
        return True

    result = create_or_update_address(name, ip_value, comment)
    status = "OK" if result["success"] else "FAILED"
    print(f"[{status}] {name} ({ip_value}) -> {result['action']} (HTTP {result['http_status']})")

    if not result["success"]:
        print(f"  response: {result['response']}")
        return False

    if group:
        group_result = add_to_group(group, name)
        group_status = "OK" if group_result["success"] else "FAILED"
        print(f"  [{group_status}] group '{group}' membership -> {group_result.get('action')}")
        if not group_result["success"]:
            return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Add IP address object(s) to a FortiGate firewall.")
    parser.add_argument("--ip", help="IP address or CIDR subnet, e.g. 203.0.113.50 or 203.0.113.0/24")
    parser.add_argument("--name", help="Firewall address object name")
    parser.add_argument("--comment", default="", help="Optional comment/note")
    parser.add_argument("--group", help="Optional address group to add the object to")
    parser.add_argument("--file", help="JSON file with a list of {name, ip, comment} objects for bulk add")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be sent without calling the API")

    args = parser.parse_args()

    if not args.file and not (args.ip and args.name):
        parser.error("Provide either --file for bulk add, or both --ip and --name for a single address.")

    if not args.dry_run:
        try:
            validate_configuration()
        except RuntimeError as error:
            print(f"ERROR: {error}")
            sys.exit(1)

    entries = []
    if args.file:
        try:
            entries = load_ioc_file(args.file)
        except Exception as error:
            print(f"ERROR: {error}")
            sys.exit(1)
    else:
        entries = [{"name": args.name, "ip": args.ip, "comment": args.comment}]

    failures = 0
    for entry in entries:
        try:
            name = entry["name"]
            ip_value = entry["ip"]
            comment = entry.get("comment", "")
        except KeyError as error:
            print(f"SKIPPED invalid entry (missing {error}): {entry}")
            failures += 1
            continue

        try:
            ok = process_one(name, ip_value, comment, args.group, args.dry_run)
        except (ValueError, requests.RequestException) as error:
            print(f"[FAILED] {name}: {error}")
            ok = False

        if not ok:
            failures += 1

    if failures:
        print(f"\n{failures} of {len(entries)} entries failed.")
        sys.exit(1)

    print(f"\nAll {len(entries)} entries processed successfully.")


if __name__ == "__main__":
    main()
