#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3b: Block one IP/DOMAIN on FortiGate DR

The DR counterpart to step3a_block_fortigate_dc.py - identical except
it reads FORTIGATE_DR_* credentials instead of FORTIGATE_DC_*. Kept as
a separate file/custom function so the playbook shows "Block on DC"
and "Block on DR" as distinct, individually retryable blocks that BOTH
run for every IP/DOMAIN (not either/or) - the same dual-site behavior
ioc_blocker.py's CLI tool has.

No external libraries - uses urllib/ssl/json from the standard library
instead of the "requests" package.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "block_fortigate_dr".
    2. Input parameters: ioc_type (string), value (string),
       comment (string)
    3. Output parameters: success (boolean), detail (string)
    4. Paste everything from "import ipaddress" below into the editor.
    5. In the playbook, wire this block to run in parallel with
       step3a (DC) for every IP/DOMAIN.

Credentials: reads FORTIGATE_DR_HOST / FORTIGATE_DR_API_KEY /
FORTIGATE_DR_VDOM / FORTIGATE_DR_IP_GROUP / FORTIGATE_DR_DOMAIN_GROUP
from environment variables by default. In SOAR, prefer pulling these
from a configured Asset - see the commented block near the bottom of
the function.
"""


def block_fortigate_dr(ioc_type=None, value=None, comment=None, **kwargs):
    """
    Args:
        ioc_type (CEF type: string) -- "IP" or "DOMAIN"
        value (CEF type: string)
        comment (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean)
        detail (CEF type: string)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import ipaddress
    import json
    import os
    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    FORTIGATE_HOST = os.environ.get("FORTIGATE_DR_HOST", "")
    FORTIGATE_API_KEY = os.environ.get("FORTIGATE_DR_API_KEY", "")
    FORTIGATE_VDOM = os.environ.get("FORTIGATE_DR_VDOM", "root")
    FORTIGATE_IP_GROUP = os.environ.get("FORTIGATE_DR_IP_GROUP", "Blocked-IPs")
    FORTIGATE_DOMAIN_GROUP = os.environ.get("FORTIGATE_DR_DOMAIN_GROUP", "Blocked-Domains")
    FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_DR_VERIFY_TLS", "false").lower() == "true"

    # ---- SOAR-asset version of the credentials (recommended for
    # production instead of environment variables) ----
    # asset_config = phantom.get_asset_config("fortigate_dr")
    # FORTIGATE_HOST = asset_config["fortigate_host"]
    # FORTIGATE_API_KEY = asset_config["api_key"]

    FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
    FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

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

    def fortigate_normalize_subnet(ip_value):
        network = ipaddress.ip_network(ip_value, strict=False)
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

        response = http_request("POST", url, params={"vdom": FORTIGATE_VDOM}, body=payload)

        if response.status_code == 200:
            return True, response

        if response.status_code == 500 and fortigate_is_duplicate(response):
            response = http_request("PUT", f"{url}/{name}", params={"vdom": FORTIGATE_VDOM}, body=payload)
            return response.status_code == 200, response

        return False, response

    def fortigate_add_to_group(group_name, member_name):
        url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"

        response = http_request("GET", url, params={"vdom": FORTIGATE_VDOM})

        if response.status_code != 200:
            return False, f"HTTP {response.status_code} - could not look up group '{group_name}'"

        body = response.json()
        results = body.get("results", [])
        existing_members = [m["name"] for m in results[0].get("member", [])] if results else []

        if member_name in existing_members:
            return True, f"already a member of group '{group_name}'"

        payload = {"member": [{"name": m} for m in existing_members + [member_name]]}

        response = http_request("PUT", url, params={"vdom": FORTIGATE_VDOM}, body=payload)

        if response.status_code == 200:
            return True, f"added to group '{group_name}'"

        return False, f"HTTP {response.status_code} - could not update group '{group_name}'"

    outputs = {"success": False, "detail": ""}

    try:
        payload = build_fortigate_payload(ioc_type, value, comment or "")
        success, response = fortigate_create_or_update_address(payload)

        if not success:
            try:
                body = response.json()
            except ValueError:
                body = response.text
            outputs["detail"] = f"[DR] HTTP {response.status_code} - address object failed: {body}"
        else:
            group = FORTIGATE_IP_GROUP if ioc_type == "IP" else FORTIGATE_DOMAIN_GROUP
            group_success, group_detail = fortigate_add_to_group(group, value)
            address_type = "ipmask" if ioc_type == "IP" else "fqdn"

            outputs["success"] = group_success
            outputs["detail"] = f"[DR] HTTP {response.status_code} - {address_type} address created/updated, {group_detail}"

    except Exception as error:
        outputs["detail"] = f"Exception: {error}"

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
