#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3b: Block one IP/DOMAIN on FortiGate DR

The DR counterpart to step3a_block_fortigate_dc.py - identical except
it reads FORTIGATE_DR_* credentials instead of FORTIGATE_DC_*. Kept as
a separate file/custom function so the playbook shows "Block on DC"
and "Block on DR" as distinct, individually retryable blocks that BOTH
run for every IP/DOMAIN (not either/or) - the same dual-site behavior
ioc_blocker.py's CLI tool has.

How to paste this into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it something like "block_fortigate_dr".
    2. Input parameters: ioc_type (string), value (string),
       comment (string)
    3. Output parameters: success (boolean), detail (string)
    4. Paste the body of block_fortigate_dr_custom_function() into the
       generated stub.
    5. In the playbook, wire this block to run in parallel with
       step3a (DC) for every IP/DOMAIN.

Credentials: reads FORTIGATE_DR_HOST / FORTIGATE_DR_API_KEY /
FORTIGATE_DR_VDOM / FORTIGATE_DR_IP_GROUP / FORTIGATE_DR_DOMAIN_GROUP
from environment variables by default. In SOAR, prefer pulling these
from a configured Asset - see the commented block near the bottom of
this file.
"""

import ipaddress
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

FORTIGATE_HOST = os.environ.get("FORTIGATE_DR_HOST", "")
FORTIGATE_API_KEY = os.environ.get("FORTIGATE_DR_API_KEY", "")
FORTIGATE_VDOM = os.environ.get("FORTIGATE_DR_VDOM", "root")
FORTIGATE_IP_GROUP = os.environ.get("FORTIGATE_DR_IP_GROUP", "Blocked-IPs")
FORTIGATE_DOMAIN_GROUP = os.environ.get("FORTIGATE_DR_DOMAIN_GROUP", "Blocked-Domains")
FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_DR_VERIFY_TLS", "false").lower() == "true"

FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

if not FORTIGATE_VERIFY_TLS:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


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


def block_via_fortigate_dr(ioc_type, value, comment):
    payload = build_fortigate_payload(ioc_type, value, comment)

    success, response = fortigate_create_or_update_address(payload)

    if not success:
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return False, f"[DR] HTTP {response.status_code} - address object failed: {body}"

    group = FORTIGATE_IP_GROUP if ioc_type == "IP" else FORTIGATE_DOMAIN_GROUP
    group_success, group_detail = fortigate_add_to_group(group, value)

    address_type = "ipmask" if ioc_type == "IP" else "fqdn"
    detail = f"[DR] HTTP {response.status_code} - {address_type} address created/updated, {group_detail}"

    return group_success, detail


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def block_fortigate_dr_custom_function(ioc_type=None, value=None, comment=None, **kwargs):
    """
    Paste into the SOAR custom function editor.
    Inputs:  ioc_type (string, "IP" or "DOMAIN"), value (string),
             comment (string)
    Outputs: success (boolean), detail (string)

    ---- SOAR-asset version of the credentials (recommended for
    production instead of environment variables) ----
    # asset_config = phantom.get_asset_config("fortigate_dr")
    # global FORTIGATE_HOST, FORTIGATE_API_KEY
    # FORTIGATE_HOST = asset_config["fortigate_host"]
    # FORTIGATE_API_KEY = asset_config["api_key"]
    """
    try:
        success, detail = block_via_fortigate_dr(ioc_type, value, comment or "")
    except Exception as error:
        return {"success": False, "detail": f"Exception: {error}"}

    return {"success": success, "detail": detail}


if __name__ == "__main__":
    print("This module expects live FortiGate DR credentials to actually run.")
    print("build_fortigate_payload('DOMAIN', 'evil.example.com', 'test') ->")
    print(build_fortigate_payload("DOMAIN", "evil.example.com", "test"))
