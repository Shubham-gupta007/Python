#!/usr/bin/env python3
"""
FortiGate Firewall - Get Address Group(s) via REST API

Reads one firewall address group (by name) or lists all of them, using
the FortiOS CMDB REST API:

    GET /api/v2/cmdb/firewall/addrgrp          -> list every address group
    GET /api/v2/cmdb/firewall/addrgrp/{name}   -> get one address group

This is the same "cmdb/firewall/addrgrp" endpoint and "member": [{"name":
...}] schema already used by this project's block/unblock scripts
(fortigate_add_address.py, ioc_blocker.py, the splunk_soar/ FortiGate
custom functions) - this script only reads, it never changes anything.

Schema note: the addrgrp object's own name field is "name" (the group's
mkey), and its "member" field is a list of objects, each keyed by "name"
(the member's own address/address-group name) - confirmed against
Fortinet's own fortinet.fortios Ansible collection (fortios_firewall_addrgrp
module, which Fortinet generates directly from FortiOS's internal API
schema), since this sandbox's network policy blocks direct access to
docs.fortinet.com / community.fortinet.com to check the REST API
reference page itself.

Authentication: API key via "Authorization: Bearer <key>" header.

Requirements:
    pip install requests

Environment variables:

    FORTIGATE_HOST       e.g. "https://192.168.1.1:443" (no trailing slash)
    FORTIGATE_API_KEY    REST API admin's API key
    FORTIGATE_VDOM        optional, defaults to "root"
    FORTIGATE_VERIFY_TLS  optional, "true"/"false", defaults to "false"

Run:
    python3 fortigate_get_addrgrp.py                  # list all address groups
    python3 fortigate_get_addrgrp.py Blocked-IPs       # get one address group
"""

import os
import sys

import requests

FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "")
FORTIGATE_API_KEY = os.environ.get("FORTIGATE_API_KEY", "")
FORTIGATE_VDOM = os.environ.get("FORTIGATE_VDOM", "root")
FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_VERIFY_TLS", "false").lower() == "true"

FORTIGATE_ADDRGRP_PATH = "/api/v2/cmdb/firewall/addrgrp"


def get_address_group(name=None):
    """
    Fetch one address group by name, or every address group if name is
    None.

    Returns the FortiGate API's parsed JSON response. On success it has
    a "results" list - one dict per address group, each with at least
    "name", "member" (list of {"name": ...}), and "comment".
    """
    if not FORTIGATE_HOST or not FORTIGATE_API_KEY:
        raise RuntimeError("FORTIGATE_HOST and FORTIGATE_API_KEY must both be set.")

    url = f"{FORTIGATE_HOST}{FORTIGATE_ADDRGRP_PATH}"
    if name:
        url = f"{url}/{name}"

    headers = {"Authorization": f"Bearer {FORTIGATE_API_KEY}"}
    params = {"vdom": FORTIGATE_VDOM}

    response = requests.get(url, headers=headers, params=params, verify=FORTIGATE_VERIFY_TLS, timeout=30)

    try:
        body = response.json()
    except ValueError:
        response.raise_for_status()
        raise RuntimeError(f"HTTP {response.status_code} - non-JSON response from FortiGate")

    if response.status_code != 200:
        error_code = body.get("error")
        raise RuntimeError(
            f"HTTP {response.status_code} - could not fetch address group "
            f"{'(' + name + ')' if name else '(list)'}: error={error_code} body={body}"
        )

    return body


def print_group(group):
    members = [m.get("name") for m in group.get("member", [])]
    print(f"- {group.get('name')}  (members: {len(members)}, comment: {group.get('comment') or ''})")
    for member_name in members:
        print(f"    * {member_name}")


def main():
    group_name = sys.argv[1] if len(sys.argv) > 1 else None

    body = get_address_group(group_name)
    results = body.get("results", [])

    # GET on a single named object returns one dict, not a list, in
    # some FortiOS versions - normalize so the rest of the script can
    # always iterate a list.
    if isinstance(results, dict):
        results = [results]

    if not results:
        print(f"No address group found for '{group_name}'." if group_name else "No address groups found.")
        return

    for group in results:
        print_group(group)


if __name__ == "__main__":
    main()
