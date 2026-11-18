#!/usr/bin/env python3
"""
Splunk SOAR Custom Function: Get FortiGate DC address-group members

Given an address group name, fetches that group from FortiGate DC and
returns every IP/domain currently listed as a member - a read-only
lookup, it never blocks or unblocks anything.

Uses the same GET /api/v2/cmdb/firewall/addrgrp/{name} endpoint and
member schema ("member": [{"name": ...}]) as the block/unblock
functions in this folder (step3a1/a2, step3c, etc.) and as the
standalone fortigate_get_addrgrp.py script in the project root.

No external libraries - uses urllib/ssl/json from the standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "lookup_fortigate_addrgrp_dc".
    2. Input parameters: group_name (string)
    3. Output parameters: success (boolean), detail (string),
       member_count (numeric), members_json (string)
    4. Paste everything from "import json" below into the editor.

    The screenshot you're working from still has the input/output
    Data Paths for a different, unrelated function (rule_name /
    team_name / matched_keyword / error) - delete those and add the
    group_name input plus the 4 outputs above before pasting this in,
    or the code will run but nothing will show up in the data paths.

Credentials: reads FORTIGATE_DC_HOST / FORTIGATE_DC_API_KEY /
FORTIGATE_DC_VDOM / FORTIGATE_DC_VERIFY_TLS from environment variables,
same as step3a1_block_fortigate_dc_ip.py.
"""


def lookup_fortigate_addrgrp_dc(group_name=None, **kwargs):
    """
    Args:
        group_name (CEF type: string) -- FortiGate address group name to look up

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean) -- True if the group was found and read
        detail (CEF type: string) -- one-line summary
        member_count (CEF type: numeric) -- number of members in the group
        members_json (CEF type: string) -- JSON array of member names (IPs/domains)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import json
    import os
    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    TAG = "[DC]"

    FORTIGATE_HOST = os.environ.get("FORTIGATE_DC_HOST", "")
    FORTIGATE_API_KEY = os.environ.get("FORTIGATE_DC_API_KEY", "")
    FORTIGATE_VDOM = os.environ.get("FORTIGATE_DC_VDOM", "root")
    FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_DC_VERIFY_TLS", "false").lower() == "true"

    FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

    outputs = {
        "success": False,
        "detail": "",
        "member_count": 0,
        "members_json": "[]",
    }

    def _scalar(v):
        # SOAR sometimes wraps a value in a list, and can even wrap
        # each item of a multi-item list in its own one-item list.
        # Unwrap any level of that nesting down to a plain scalar.
        while isinstance(v, list):
            v = v[0] if v else None
        return v

    group_name = _scalar(group_name)

    if not FORTIGATE_HOST or not FORTIGATE_API_KEY:
        outputs["detail"] = (
            f"{TAG} Not configured: FORTIGATE_DC_HOST and/or FORTIGATE_DC_API_KEY is empty."
        )
        assert json.dumps(outputs)
        return outputs

    if not group_name:
        outputs["detail"] = f"{TAG} No 'group_name' provided."
        assert json.dumps(outputs)
        return outputs

    def http_get(url, params, timeout=30):
        if params:
            url = url + "?" + urllib.parse.urlencode(params)

        headers = {"Authorization": f"Bearer {FORTIGATE_API_KEY}"}
        request = urllib.request.Request(url, headers=headers, method="GET")

        context = None
        if url.startswith("https://"):
            context = ssl.create_default_context()
            if not FORTIGATE_VERIFY_TLS:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return response.status, response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as error:
            return 0, str(error.reason)

    try:
        url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"
        status_code, response_text = http_get(url, {"vdom": FORTIGATE_VDOM})

        try:
            body = json.loads(response_text)
        except ValueError:
            outputs["detail"] = f"{TAG} {FORTIGATE_HOST}: HTTP {status_code} - non-JSON response"
            assert json.dumps(outputs)
            return outputs

        if status_code != 200:
            outputs["detail"] = (
                f"{TAG} {FORTIGATE_HOST}: HTTP {status_code} - could not fetch group "
                f"'{group_name}' (error={body.get('error')})"
            )
            assert json.dumps(outputs)
            return outputs

        results = body.get("results", [])
        # GET on a single named object returns one dict, not a list,
        # in some FortiOS versions - normalize to a list either way.
        if isinstance(results, dict):
            results = [results]

        if not results:
            outputs["detail"] = f"{TAG} {FORTIGATE_HOST}: group '{group_name}' not found"
            assert json.dumps(outputs)
            return outputs

        members = [m.get("name") for m in results[0].get("member", []) if m.get("name")]

        outputs["success"] = True
        outputs["member_count"] = len(members)
        outputs["members_json"] = json.dumps(members)
        outputs["detail"] = (
            f"{TAG} {FORTIGATE_HOST}: group '{group_name}' has {len(members)} member(s)"
            + (f": {', '.join(members)}" if members else "")
        )

    except Exception as error:
        outputs["detail"] = f"{TAG} {FORTIGATE_HOST}: Exception ({type(error).__name__}): {error}"

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
