#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3d (undo): Unblock IP(s)/DOMAIN(s)
on FortiGate DR

The DR counterpart to step3c_unblock_fortigate_dc.py - identical
except it reads FORTIGATE_DR_* credentials. Unblock anything
step3b1_block_fortigate_dr_ip.py / step3b2_block_fortigate_dr_domain.py blocked.

Accepts EITHER a single value OR a list of values in "value" - a
single value is just treated as a batch of one. ioc_type ("IP" or
"DOMAIN") applies to the whole batch - call this once for your list of
IPs, and separately for your list of domains.

The group-membership removal is batched into a single GET + a single
PUT covering every value in the call, instead of one GET+PUT per
value. Deleting the address objects still takes one DELETE per value
(FortiGate has no bulk delete for this).

No external libraries - uses urllib/ssl/json from the standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "unblock_fortigate_dr".
    2. Input parameters: ioc_type (string), value (string - accepts a
       list too)
    3. Output parameters: success (boolean), detail (string),
       results_json (string), success_count (numeric),
       failed_count (numeric)
    4. Paste everything from "import json" below into the editor.

Credentials: same FORTIGATE_DR_* environment variables as
step3b1_block_fortigate_dr_ip.py / step3b2_block_fortigate_dr_domain.py.
"""


def unblock_fortigate_dr(ioc_type=None, value=None, **kwargs):
    """
    Args:
        ioc_type (CEF type: string) -- "IP" or "DOMAIN", applies to the whole batch
        value (CEF type: string) -- one value, or a list of them

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean) -- True only if every value in this call succeeded
        detail (CEF type: string) -- one-line summary
        results_json (CEF type: string) -- JSON array of {value, success, detail}
        success_count (CEF type: numeric)
        failed_count (CEF type: numeric)
    """
    ########################## Custom Code Goes Below This Line ##########################
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

    FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
    FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"
    FORTIGATE_NOT_FOUND_ERROR_CODES = {-3}

    outputs = {
        "success": False,
        "detail": "",
        "results_json": "[]",
        "success_count": 0,
        "failed_count": 0,
    }

    def _scalar(v):
        if isinstance(v, list):
            return v[0] if v else None
        return v

    def _to_list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    ioc_type = _scalar(ioc_type)
    values = [v for v in _to_list(value) if v]

    TAG = "[DR]"

    if not FORTIGATE_HOST or not FORTIGATE_API_KEY:
        outputs["detail"] = (
            f"{TAG} Not configured: FORTIGATE_DR_HOST and/or FORTIGATE_DR_API_KEY "
            "is empty."
        )
        assert json.dumps(outputs)
        return outputs

    if not values:
        outputs["detail"] = f"{TAG} No 'value' provided."
        assert json.dumps(outputs)
        return outputs

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

    def fortigate_get_group_members(group_name):
        url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"
        response = http_request("GET", url, params={"vdom": FORTIGATE_VDOM})

        if response.status_code != 200:
            if fortigate_is_not_found(response):
                return [], None
            return None, f"HTTP {response.status_code} - could not look up group '{group_name}'"

        body = response.json()
        results = body.get("results", [])
        existing = [m["name"] for m in results[0].get("member", [])] if results else []
        return existing, None

    def fortigate_set_group_members(group_name, members):
        url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"
        payload = {"member": [{"name": m} for m in members]}
        response = http_request("PUT", url, params={"vdom": FORTIGATE_VDOM}, body=payload)

        if response.status_code == 200:
            return True, None

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

    item_results = [{"value": v, "success": None, "detail": ""} for v in values]

    try:
        group = FORTIGATE_IP_GROUP if ioc_type == "IP" else FORTIGATE_DOMAIN_GROUP

        existing_members, group_error = fortigate_get_group_members(group)

        if existing_members is None:
            for result in item_results:
                result["success"] = False
                result["detail"] = group_error
        else:
            to_remove = [v for v in values if v in existing_members]

            if to_remove:
                remaining = [m for m in existing_members if m not in values]
                group_success, group_set_error = fortigate_set_group_members(group, remaining)
            else:
                group_success, group_set_error = True, None

            for result in item_results:
                v = result["value"]
                if not group_success:
                    result["success"] = False
                    result["detail"] = f"group update failed: {group_set_error}"
                elif v in existing_members:
                    result["detail"] = f"removed from group '{group}'"
                else:
                    result["detail"] = f"was not a member of group '{group}' (nothing to do)"

        for result in item_results:
            if result["success"] is False:
                continue
            try:
                delete_success, delete_detail = fortigate_delete_address(result["value"])
                result["success"] = delete_success
                result["detail"] = f"{result['detail']}, {delete_detail}"
            except Exception as item_error:
                result["success"] = False
                result["detail"] = f"{result['detail']}, Exception ({type(item_error).__name__}): {item_error}"

    except Exception as error:
        outputs["detail"] = f"{TAG} {FORTIGATE_HOST}: Exception ({type(error).__name__}): {error}"
        assert json.dumps(outputs)
        return outputs

    for result in item_results:
        result["detail"] = f"{TAG} {FORTIGATE_HOST}: {result['detail']}"

    success_count = sum(1 for r in item_results if r["success"])
    failed_count = len(item_results) - success_count

    outputs["results_json"] = json.dumps(item_results)
    outputs["success_count"] = success_count
    outputs["failed_count"] = failed_count
    outputs["success"] = failed_count == 0 and success_count > 0
    outputs["detail"] = (
        f"{TAG} {FORTIGATE_HOST}: {success_count}/{len(item_results)} unblocked"
        + ("" if failed_count == 0 else f", {failed_count} failed (see results_json)")
    )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
