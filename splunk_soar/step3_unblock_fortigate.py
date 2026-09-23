#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3 (undo): Unblock one IP/DOMAIN on FortiGate

Removes the address object from its block group, then deletes the
address object outright. An IOC that was never blocked (already
absent) counts as a success, since the desired end state already
holds.

Splunk's native FortiGate app (Splunkbase app id 5898) does have an
"unblock ip" action, but it's the mirror of its "block ip" action
(removes the one-off "Phantom Addr" it created from a policy's
destination) - it won't clean up objects this custom function's
block_fortigate_custom_function created via the address-group
approach, and it has no domain/FQDN support at all. Use this function
to unblock anything block_fortigate_custom_function blocked.

How to paste this into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function.
    2. Input parameters: ioc_type (string), value (string)
    3. Output parameters: success (boolean), detail (string)
    4. Paste the body of unblock_fortigate_custom_function() into the
       generated stub.

Credentials: same environment variables as step3_block_fortigate.py -
see that file's docstring for the SOAR-asset alternative.
"""

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

FORTIGATE_NOT_FOUND_ERROR_CODES = {-3}

if not FORTIGATE_VERIFY_TLS:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def fortigate_api_headers():
    return {
        "Authorization": f"Bearer {FORTIGATE_API_KEY}",
        "Content-Type": "application/json",
    }


def fortigate_is_not_found(response):
    try:
        return response.json().get("error") in FORTIGATE_NOT_FOUND_ERROR_CODES
    except ValueError:
        return False


def fortigate_remove_from_group(group_name, member_name):
    url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"

    response = requests.get(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code != 200:
        if fortigate_is_not_found(response):
            return True, f"group '{group_name}' does not exist (nothing to do)"
        return False, f"HTTP {response.status_code} - could not look up group '{group_name}'"

    body = response.json()
    results = body.get("results", [])
    existing_members = [m["name"] for m in results[0].get("member", [])] if results else []

    if member_name not in existing_members:
        return True, f"was not a member of group '{group_name}' (nothing to do)"

    remaining_members = [m for m in existing_members if m != member_name]
    payload = {"member": [{"name": m} for m in remaining_members]}

    response = requests.put(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        json=payload,
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code == 200:
        return True, f"removed from group '{group_name}'"

    return False, f"HTTP {response.status_code} - could not update group '{group_name}'"


def fortigate_delete_address(name):
    url = f"{FORTIGATE_HOST}{FORTIGATE_ADDRESS_PATH}/{name}"

    response = requests.delete(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code == 200:
        return True, "address object deleted"

    if response.status_code == 404 or fortigate_is_not_found(response):
        return True, "address object did not exist (nothing to do)"

    try:
        body = response.json()
    except ValueError:
        body = response.text

    return False, f"HTTP {response.status_code} - could not delete address object: {body}"


def unblock_via_fortigate(ioc_type, value):
    group = FORTIGATE_IP_GROUP if ioc_type == "IP" else FORTIGATE_DOMAIN_GROUP

    group_success, group_detail = fortigate_remove_from_group(group, value)

    if not group_success:
        return False, group_detail

    delete_success, delete_detail = fortigate_delete_address(value)

    return delete_success, f"{group_detail}, {delete_detail}"


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def unblock_fortigate_custom_function(ioc_type=None, value=None, **kwargs):
    """
    Paste into the SOAR custom function editor.
    Inputs:  ioc_type (string, "IP" or "DOMAIN"), value (string)
    Outputs: success (boolean), detail (string)
    """
    try:
        success, detail = unblock_via_fortigate(ioc_type, value)
    except Exception as error:
        return {"success": False, "detail": f"Exception: {error}"}

    return {"success": success, "detail": detail}


if __name__ == "__main__":
    print("This module expects live FortiGate credentials to actually run.")
