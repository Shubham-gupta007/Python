#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3b1: Block IP(s) on FortiGate DR

IP-only counterpart to step3b2_block_fortigate_dr_domain.py. Accepts
EITHER a single IP string OR a list of IPs in "value" - a single value
is just treated as a batch of one, so you can wire this to one
indicator or to an entire list straight from a CSV/advisory without
changing anything.

Every IP gets its own address object (unavoidable), but the
address-group membership update is batched into a single GET + a
single PUT covering every IP in the call, instead of one GET+PUT per IP.

Every return path is tagged "[DR-IP]", including per-item failures
inside a batch and the catch-all exception handler.

No external libraries - uses urllib/ssl/json from the standard library
instead of the "requests" package.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "block_fortigate_dr_ip".
    2. Input parameters: value (string - accepts a list too),
       comment (string - accepts a list too)
    3. Output parameters: success (boolean), detail (string),
       results_json (string), success_count (numeric),
       failed_count (numeric)
    4. Paste everything from "import json" below into the editor.
    5. Wire only IP-typed indicators into this block; wire DOMAIN ones
       to step3b2_block_fortigate_dr_domain.py instead.

Credentials: reads FORTIGATE_DR_HOST / FORTIGATE_DR_API_KEY /
FORTIGATE_DR_VDOM / FORTIGATE_DR_IP_GROUP / FORTIGATE_DR_VERIFY_TLS
from environment variables by default. In SOAR, prefer pulling these
from a configured Asset - see the commented block near the bottom of
the function.
"""


def block_fortigate_dr_ip(value=None, comment=None, **kwargs):
    """
    Args:
        value (CEF type: ip) -- one IPv4 address, or a list of them
        comment (CEF type: string) -- one comment applied to every IP,
            or a list of per-IP comments matching value's length

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean) -- True only if every IP in this call succeeded
        detail (CEF type: string) -- one-line summary
        results_json (CEF type: string) -- JSON array of {value, success, detail}
        success_count (CEF type: numeric)
        failed_count (CEF type: numeric)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import ast
    import ipaddress
    import json
    import os
    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    TAG = "[DR-IP]"

    FORTIGATE_HOST = os.environ.get("FORTIGATE_DR_HOST", "")
    FORTIGATE_API_KEY = os.environ.get("FORTIGATE_DR_API_KEY", "")
    FORTIGATE_VDOM = os.environ.get("FORTIGATE_DR_VDOM", "root")
    FORTIGATE_IP_GROUP = os.environ.get("FORTIGATE_DR_IP_GROUP", "Blocked-IPs")
    FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_DR_VERIFY_TLS", "false").lower() == "true"

    # ---- SOAR-asset version of the credentials (recommended for
    # production instead of environment variables) ----
    # asset_config = phantom.get_asset_config("fortigate_dr")
    # FORTIGATE_HOST = asset_config["fortigate_host"]
    # FORTIGATE_API_KEY = asset_config["api_key"]

    FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
    FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

    outputs = {
        "success": False,
        "detail": "",
        "results_json": "[]",
        "success_count": 0,
        "failed_count": 0,
    }

    def _item_scalar(v):
        # SOAR sometimes wraps each item of a multi-item list in its
        # own one-item list (e.g. value=[['1.2.3.4'], ['5.6.7.8']]).
        # Unwrap any level of that nesting down to a plain scalar so
        # it's safe to use as a dict key / set member below.
        while isinstance(v, list):
            v = v[0] if v else None
        return v

    def _to_list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    def _split_multi(v):
        # A single SOAR data path sometimes resolves to one string
        # instead of a true list. Two shapes show up in practice:
        #   1. a stringified Python list, e.g.
        #      "['77.91.118.10', '80.75.212.113', '87.251.64.13']"
        #      (a static/"Format" field stringified an actual list) -
        #      ast.literal_eval parses that back into real items.
        #   2. a plain comma/newline-joined string, e.g.
        #      "193.8.186.33, 45.227.254.210".
        # Either way, split it apart so each indicator still gets its
        # own address object instead of one failed lookup for the
        # whole joined/bracketed string.
        if not isinstance(v, str):
            return [v]

        stripped = v.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = ast.literal_eval(stripped)
                if isinstance(parsed, (list, tuple)):
                    return [str(p).strip() for p in parsed if str(p).strip()]
            except (ValueError, SyntaxError):
                pass

        if "," in v or "\n" in v:
            parts = [p.strip().strip("[]'\" ") for p in v.replace("\n", ",").split(",")]
            return [p for p in parts if p]

        return [v]

    values = []
    for raw in _to_list(value):
        for item in _split_multi(_item_scalar(raw)):
            if item:
                values.append(item)

    comments = [_item_scalar(c) for c in _to_list(comment)]

    def comment_for(index):
        if not comments:
            return ""
        if len(comments) == len(values):
            return comments[index] or ""
        return comments[0] or ""

    if not FORTIGATE_HOST or not FORTIGATE_API_KEY:
        outputs["detail"] = (
            f"{TAG} Not configured: FORTIGATE_DR_HOST and/or FORTIGATE_DR_API_KEY "
            "is empty. Set both before blocking IPs on the DR firewall."
        )
        assert json.dumps(outputs)
        return outputs

    if not values:
        outputs["detail"] = f"{TAG} No 'value' (IP address) provided."
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

    def fortigate_normalize_subnet(ip_value):
        network = ipaddress.ip_network(ip_value, strict=False)
        return f"{network.network_address} {network.netmask}"

    def build_address_payload(ip_value, item_comment):
        return {
            "name": ip_value,
            "type": "ipmask",
            "subnet": fortigate_normalize_subnet(ip_value),
            "comment": item_comment or "",
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

    def fortigate_get_group_members(group_name):
        url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"
        response = http_request("GET", url, params={"vdom": FORTIGATE_VDOM})

        if response.status_code != 200:
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

    item_results = []

    try:
        address_ok = {}

        for index, ip_value in enumerate(values):
            try:
                payload = build_address_payload(ip_value, comment_for(index))
                success, response = fortigate_create_or_update_address(payload)

                if success:
                    address_ok[ip_value] = True
                    item_results.append({
                        "value": ip_value,
                        "success": None,
                        "detail": f"HTTP {response.status_code} - ipmask address created/updated",
                    })
                else:
                    try:
                        body = response.json()
                    except ValueError:
                        body = response.text
                    address_ok[ip_value] = False
                    item_results.append({
                        "value": ip_value,
                        "success": False,
                        "detail": f"HTTP {response.status_code} - address object failed: {body}",
                    })

            except Exception as item_error:
                address_ok[ip_value] = False
                item_results.append({
                    "value": ip_value,
                    "success": False,
                    "detail": f"Exception ({type(item_error).__name__}): {item_error}",
                })

        to_add = [v for v in values if address_ok.get(v)]

        if to_add:
            existing_members, group_error = fortigate_get_group_members(FORTIGATE_IP_GROUP)

            if existing_members is None:
                for result in item_results:
                    if address_ok.get(result["value"]):
                        result["success"] = False
                        result["detail"] += f", {group_error}"
            else:
                new_members = existing_members + [v for v in to_add if v not in existing_members]

                if set(new_members) != set(existing_members):
                    group_success, group_set_error = fortigate_set_group_members(FORTIGATE_IP_GROUP, new_members)
                else:
                    group_success, group_set_error = True, None

                for result in item_results:
                    v = result["value"]
                    if not address_ok.get(v):
                        continue
                    if group_success:
                        already = v in existing_members
                        result["success"] = True
                        result["detail"] += (
                            f", already a member of group '{FORTIGATE_IP_GROUP}'"
                            if already
                            else f", added to group '{FORTIGATE_IP_GROUP}'"
                        )
                    else:
                        result["success"] = False
                        result["detail"] += f", group update failed: {group_set_error}"

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
        f"{TAG} {FORTIGATE_HOST}: {success_count}/{len(item_results)} IP(s) blocked"
        + ("" if failed_count == 0 else f", {failed_count} failed (see results_json)")
    )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
