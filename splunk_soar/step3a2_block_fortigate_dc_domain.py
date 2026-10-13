#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 3a2: Block DOMAIN(s) on FortiGate DC

DOMAIN-only counterpart to step3a1_block_fortigate_dc_ip.py. Accepts
EITHER a single domain string OR a list of domains in "value" - a
single value is just treated as a batch of one, so you can wire this
to one indicator or to an entire list straight from a CSV/advisory
without changing anything.

Every domain gets its own address object (unavoidable), but the
address-group membership update is batched into a single GET + a
single PUT covering every domain in the call, instead of one GET+PUT
per domain.

Every return path is tagged "[DC-DOMAIN]", including per-item
failures inside a batch and the catch-all exception handler.

No external libraries - uses urllib/ssl/json from the standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "block_fortigate_dc_domain".
    2. Input parameters: value (string - accepts a list too),
       comment (string - accepts a list too)
    3. Output parameters: success (boolean), detail (string),
       results_json (string), success_count (numeric),
       failed_count (numeric)
    4. Paste everything from "import json" below into the editor.
    5. Wire only DOMAIN-typed indicators into this block; wire IP ones
       to step3a1_block_fortigate_dc_ip.py instead.

Credentials: reads FORTIGATE_DC_HOST / FORTIGATE_DC_API_KEY /
FORTIGATE_DC_VDOM / FORTIGATE_DC_DOMAIN_GROUP / FORTIGATE_DC_VERIFY_TLS
from environment variables by default. In SOAR, prefer pulling these
from a configured Asset - see the commented block near the bottom of
the function.
"""


def block_fortigate_dc_domain(value=None, comment=None, **kwargs):
    """
    Args:
        value (CEF type: domain) -- one domain/FQDN, or a list of them
        comment (CEF type: string) -- one comment applied to every
            domain, or a list of per-domain comments matching value's length

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean) -- True only if every domain in this call succeeded
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

    TAG = "[DC-DOMAIN]"

    FORTIGATE_HOST = os.environ.get("FORTIGATE_DC_HOST", "")
    FORTIGATE_API_KEY = os.environ.get("FORTIGATE_DC_API_KEY", "")
    FORTIGATE_VDOM = os.environ.get("FORTIGATE_DC_VDOM", "root")
    FORTIGATE_DOMAIN_GROUP = os.environ.get("FORTIGATE_DC_DOMAIN_GROUP", "Blocked-Domains")
    FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_DC_VERIFY_TLS", "false").lower() == "true"

    # ---- SOAR-asset version of the credentials ----
    # asset_config = phantom.get_asset_config("fortigate_dc")
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
        # own one-item list (e.g. value=[['a.example'], ['b.example']]).
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
        # holding several comma/newline-separated indicators (e.g. an
        # advisory field "a.example, b.example") instead of a true
        # list - split those apart too, so each one still gets its
        # own address object instead of one failed lookup for the
        # whole joined string.
        if isinstance(v, str) and ("," in v or "\n" in v):
            return [p.strip() for p in v.replace("\n", ",").split(",") if p.strip()]
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
            f"{TAG} Not configured: FORTIGATE_DC_HOST and/or FORTIGATE_DC_API_KEY "
            "is empty. Set both before blocking domains on the DC firewall."
        )
        assert json.dumps(outputs)
        return outputs

    if not values:
        outputs["detail"] = f"{TAG} No 'value' (domain) provided."
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

    def build_address_payload(domain_value, item_comment):
        return {
            "name": domain_value,
            "type": "fqdn",
            "fqdn": domain_value,
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

        for index, domain_value in enumerate(values):
            try:
                payload = build_address_payload(domain_value, comment_for(index))
                success, response = fortigate_create_or_update_address(payload)

                if success:
                    address_ok[domain_value] = True
                    item_results.append({
                        "value": domain_value,
                        "success": None,
                        "detail": f"HTTP {response.status_code} - fqdn address created/updated",
                    })
                else:
                    try:
                        body = response.json()
                    except ValueError:
                        body = response.text
                    address_ok[domain_value] = False
                    item_results.append({
                        "value": domain_value,
                        "success": False,
                        "detail": f"HTTP {response.status_code} - address object failed: {body}",
                    })

            except Exception as item_error:
                address_ok[domain_value] = False
                item_results.append({
                    "value": domain_value,
                    "success": False,
                    "detail": f"Exception ({type(item_error).__name__}): {item_error}",
                })

        to_add = [v for v in values if address_ok.get(v)]

        if to_add:
            existing_members, group_error = fortigate_get_group_members(FORTIGATE_DOMAIN_GROUP)

            if existing_members is None:
                for result in item_results:
                    if address_ok.get(result["value"]):
                        result["success"] = False
                        result["detail"] += f", {group_error}"
            else:
                new_members = existing_members + [v for v in to_add if v not in existing_members]

                if set(new_members) != set(existing_members):
                    group_success, group_set_error = fortigate_set_group_members(FORTIGATE_DOMAIN_GROUP, new_members)
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
                            f", already a member of group '{FORTIGATE_DOMAIN_GROUP}'"
                            if already
                            else f", added to group '{FORTIGATE_DOMAIN_GROUP}'"
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
        f"{TAG} {FORTIGATE_HOST}: {success_count}/{len(item_results)} domain(s) blocked"
        + ("" if failed_count == 0 else f", {failed_count} failed (see results_json)")
    )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
