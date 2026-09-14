#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3: Block one IP/DOMAIN on FortiGate

Takes an already-validated IP or DOMAIN from step 2 (only call this
when step2's target_tool == "FORTIGATE") and creates the matching
address object, then adds it to the block address group.

--------------------------------------------------------------------
Before writing this as a custom function: Splunk's own FortiGate app
(Splunkbase app id 5898) has native "block ip" / "unblock ip" actions
- use those for plain IP blocking if your policy design fits how it
works. It does NOT use a shared address group the way this script
does - it creates a one-off "Phantom Addr [ip]_[bits]" object and
edits a specific policy's destination address directly. If you want
every blocked IOC visible in one reusable address group (for
auditing, or so one policy blocks everything), or you need DOMAIN
blocking (which the native app doesn't support at all), keep using
this custom function instead.
--------------------------------------------------------------------

How to paste this into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function.
    2. Input parameters: ioc_type (string), value (string),
       comment (string)
    3. Output parameters: success (boolean), detail (string)
    4. Paste the body of block_fortigate_custom_function() into the
       generated stub.

Credentials: reads FORTIGATE_HOST / FORTIGATE_API_KEY / FORTIGATE_VDOM
/ FORTIGATE_IP_GROUP / FORTIGATE_DOMAIN_GROUP from environment
variables by default (handy for local testing). In SOAR, prefer
pulling these from a configured Asset instead of hardcoding them in
the playbook - see the commented block near the bottom of this file
for the swap-in.
"""

import ipaddress
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "")
FORTIGATE_API_KEY = os.environ.get("FORTIGATE_API_KEY", "")
FORTIGATE_VDOM = os.environ.get("FORTIGATE_VDOM", "root")
FORTIGATE_IP_GROUP = os.environ.get("FORTIGATE_IP_GROUP", "Blocked-IPs")
FORTIGATE_DOMAIN_GROUP = os.environ.get("FORTIGATE_DOMAIN_GROUP", "Blocked-Domains")
FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_VERIFY_TLS", "false").lower() == "true"

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


def block_via_fortigate(ioc_type, value, comment):
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
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def block_fortigate_custom_function(ioc_type=None, value=None, comment=None, **kwargs):
    """
    Paste into the SOAR custom function editor.
    Inputs:  ioc_type (string, "IP" or "DOMAIN"), value (string),
             comment (string)
    Outputs: success (boolean), detail (string)

    ---- SOAR-asset version of the credentials (recommended for
    production instead of environment variables) ----
    # asset_config = phantom.get_asset_config("fortigate")
    # global FORTIGATE_HOST, FORTIGATE_API_KEY
    # FORTIGATE_HOST = asset_config["fortigate_host"]
    # FORTIGATE_API_KEY = asset_config["api_key"]
    """
    try:
        success, detail = block_via_fortigate(ioc_type, value, comment or "")
    except Exception as error:
        return {"success": False, "detail": f"Exception: {error}"}

    return {"success": success, "detail": detail}


if __name__ == "__main__":
    print("This module expects live FortiGate credentials to actually run.")
    print("build_fortigate_payload('IP', '203.0.113.50', 'test') ->")
    print(build_fortigate_payload("IP", "203.0.113.50", "test"))
    print(build_fortigate_payload("DOMAIN", "evil.example.com", "test"))
