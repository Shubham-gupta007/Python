#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3c (undo): Unblock one IP/DOMAIN on FortiGate DC

Removes the address object from its block group, then deletes the
address object outright. An IOC that was never blocked (already
absent) counts as a success, since the desired end state already
holds. The DC counterpart to step3d_unblock_fortigate_dr.py - unblock
anything step3a_block_fortigate_dc.py blocked.

No external libraries - uses urllib/ssl/json from the standard library
instead of the "requests" package.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "unblock_fortigate_dc".
    2. Input parameters: ioc_type (string), value (string)
    3. Output parameters: success (boolean), detail (string)
    4. Paste everything from "import json" below into the editor.

Credentials: same FORTIGATE_DC_* environment variables as
step3a_block_fortigate_dc.py.
"""


def unblock_fortigate_dc(ioc_type=None, value=None, **kwargs):
    """
    Args:
        ioc_type (CEF type: string) -- "IP" or "DOMAIN"
        value (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean)
        detail (CEF type: string)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import json
    import os
    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    FORTIGATE_HOST = os.environ.get("FORTIGATE_DC_HOST", "")
    FORTIGATE_API_KEY = os.environ.get("FORTIGATE_DC_API_KEY", "")
    FORTIGATE_VDOM = os.environ.get("FORTIGATE_DC_VDOM", "root")
    FORTIGATE_IP_GROUP = os.environ.get("FORTIGATE_DC_IP_GROUP", "Blocked-IPs")
    FORTIGATE_DOMAIN_GROUP = os.environ.get("FORTIGATE_DC_DOMAIN_GROUP", "Blocked-Domains")
    FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_DC_VERIFY_TLS", "false").lower() == "true"

    FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
    FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"
    FORTIGATE_NOT_FOUND_ERROR_CODES = {-3}

    class HttpResponse:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

        def json(self):
            return json.loads(self.text)

    def http_request(method, url, params=None, body=None, timeout=30):
        if params:
            url = url + "?" + urllib.parse.urlencode(params)

        data = json.dumps(body).encode("utf-8") if body is not None else None

        headers = {
            "Authorization": f"Bearer {FORTIGATE_API_KEY}",
            "Content-Type": "application/json",
        }

        request = urllib.request.Request(url, data=data, headers=headers, method=method)

        context = None
        if url.startswith("https://"):
            context = ssl.create_default_context()
            if not FORTIGATE_VERIFY_TLS:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return HttpResponse(response.status, response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as error:
            return HttpResponse(error.code, error.read().decode("utf-8", errors="replace"))
        except urllib.error.URLError as error:
            return HttpResponse(0, str(error.reason))

    def fortigate_is_not_found(response):
        try:
            return response.json().get("error") in FORTIGATE_NOT_FOUND_ERROR_CODES
        except ValueError:
            return False

    def fortigate_remove_from_group(group_name, member_name):
        url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"

        response = http_request("GET", url, params={"vdom": FORTIGATE_VDOM})

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

        response = http_request("PUT", url, params={"vdom": FORTIGATE_VDOM}, body=payload)

        if response.status_code == 200:
            return True, f"removed from group '{group_name}'"

        return False, f"HTTP {response.status_code} - could not update group '{group_name}'"

    def fortigate_delete_address(name):
        url = f"{FORTIGATE_HOST}{FORTIGATE_ADDRESS_PATH}/{name}"

        response = http_request("DELETE", url, params={"vdom": FORTIGATE_VDOM})

        if response.status_code == 200:
            return True, "address object deleted"

        if response.status_code == 404 or fortigate_is_not_found(response):
            return True, "address object did not exist (nothing to do)"

        try:
            body = response.json()
        except ValueError:
            body = response.text

        return False, f"HTTP {response.status_code} - could not delete address object: {body}"

    outputs = {"success": False, "detail": ""}

    try:
        group = FORTIGATE_IP_GROUP if ioc_type == "IP" else FORTIGATE_DOMAIN_GROUP
        group_success, group_detail = fortigate_remove_from_group(group, value)

        if not group_success:
            outputs["detail"] = f"[DC] {group_detail}"
        else:
            delete_success, delete_detail = fortigate_delete_address(value)
            outputs["success"] = delete_success
            outputs["detail"] = f"[DC] {group_detail}, {delete_detail}"

    except Exception as error:
        outputs["detail"] = f"Exception: {error}"

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
