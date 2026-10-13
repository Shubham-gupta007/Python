#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 4: Block URL(s)/SHA1(s)/SHA256(s) on
Trend Micro Apex Central

Takes already-validated URL, SHA1 or SHA256 value(s) (only call this
when step2's target_tool == "APEX") and adds each as a blocked
User-Defined Suspicious Object (UDSO). Accepts EITHER a single value
OR a list of values in "value" - a single value is just treated as a
batch of one. ioc_type applies to the whole batch (it's one Apex
Central content type per call - URL, SHA1 or SHA256).

Every value needs its own signed JWT (the checksum covers that exact
request body) and its own PUT call - Apex Central's UDSO API has no
bulk endpoint, so a batch here is still N independent calls, just
issued from one custom function invocation instead of N playbook
blocks.

There is no native Splunk SOAR app for Apex Central UDSO blocking -
the official "Trend Micro Apex One" app (Splunkbase app id 5976) only
covers endpoint quarantine actions, a different use case.

No external libraries - base64/hashlib/hmac/time/json build the JWT,
and urllib/ssl make the HTTPS call, all standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "block_apex".
    2. Input parameters: ioc_type (string), value (string - accepts a
       list too), note (string - accepts a list too)
    3. Output parameters: success (boolean), detail (string),
       results_json (string), success_count (numeric),
       failed_count (numeric)
    4. Paste everything from "import base64" below into the editor.

Credentials: reads APEX_CENTRAL_URL / APEX_APPLICATION_ID /
APEX_API_KEY from environment variables by default. In SOAR, prefer
pulling these from a configured Asset - see the commented block near
the bottom of the function.
"""


def block_apex(ioc_type=None, value=None, note=None, **kwargs):
    """
    Args:
        ioc_type (CEF type: string) -- "URL", "SHA1" or "SHA256", applies to the whole batch
        value (CEF type: string) -- one value, or a list of them
        note (CEF type: string) -- one note applied to every value, or
            a list of per-value notes matching value's length

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean) -- True only if every value in this call succeeded
        detail (CEF type: string) -- one-line summary
        results_json (CEF type: string) -- JSON array of {value, success, detail}
        success_count (CEF type: numeric)
        failed_count (CEF type: numeric)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import base64
    import hashlib
    import hmac
    import json
    import os
    import ssl
    import time
    import urllib.error
    import urllib.request

    APEX_CENTRAL_URL = os.environ.get("APEX_CENTRAL_URL", "")
    APEX_APPLICATION_ID = os.environ.get("APEX_APPLICATION_ID", "")
    APEX_API_KEY = os.environ.get("APEX_API_KEY", "")
    APEX_VERIFY_TLS = os.environ.get("APEX_VERIFY_TLS", "false").lower() == "true"

    # ---- SOAR-asset version of the credentials ----
    # asset_config = phantom.get_asset_config("apex_central")
    # APEX_CENTRAL_URL = asset_config["url"]
    # APEX_APPLICATION_ID = asset_config["application_id"]
    # APEX_API_KEY = asset_config["api_key"]

    APEX_API_PATH = "/WebApp/api/SuspiciousObjects/UserDefinedSO/"
    SCAN_ACTION = "block"

    APEX_TYPE_MAP = {"URL": "url", "SHA1": "file_sha1", "SHA256": "file_sha256"}

    def compact_json(data):
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)

    def base64url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def apex_create_checksum(http_method, raw_url, canonical_headers, request_body):
        checksum_input = (
            http_method.upper() + "|" + raw_url.lower() + "|" + canonical_headers + "|" + request_body
        )
        digest = hashlib.sha256(checksum_input.encode("utf-8")).digest()
        return base64.b64encode(digest).decode("ascii")

    def apex_create_jwt(http_method, raw_url, request_body):
        header = {"alg": "HS256", "typ": "JWT"}
        canonical_headers = ""

        checksum = apex_create_checksum(http_method, raw_url, canonical_headers, request_body)

        payload = {
            "appid": APEX_APPLICATION_ID,
            "iat": time.time(),
            "version": "V1",
            "checksum": checksum,
        }

        encoded_header = base64url_encode(compact_json(header).encode("utf-8"))
        encoded_payload = base64url_encode(compact_json(payload).encode("utf-8"))
        signing_input = encoded_header + "." + encoded_payload

        signature = hmac.new(
            APEX_API_KEY.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
        ).digest()

        return signing_input + "." + base64url_encode(signature)

    def build_apex_payload(ioc_type, value, item_note):
        return {
            "param": {
                "type": APEX_TYPE_MAP[ioc_type],
                "content": value,
                "notes": item_note,
                "scan_action": SCAN_ACTION,
            }
        }

    def http_put(url, headers, body_text, verify_tls, timeout=30):
        request = urllib.request.Request(url, data=body_text.encode("utf-8"), headers=headers, method="PUT")

        context = None
        if url.startswith("https://"):
            context = ssl.create_default_context()
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return response.status, response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as error:
            return 0, str(error.reason)

    def block_one(value, item_note):
        payload = build_apex_payload(ioc_type, value, item_note or "Blocked via SOAR playbook")
        request_body = compact_json(payload)

        token = apex_create_jwt("PUT", APEX_API_PATH, request_body)

        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json;charset=utf-8",
        }

        url = APEX_CENTRAL_URL + APEX_API_PATH

        status_code, response_text = http_put(url, headers, request_body, APEX_VERIFY_TLS)

        try:
            response_json = json.loads(response_text)
        except ValueError:
            return False, f"HTTP {status_code} - non-JSON response from Apex Central"

        meta = response_json.get("Meta", {})
        result = str(meta.get("Result", ""))
        error_code = meta.get("ErrorCode")
        error_message = meta.get("ErrorMsg")

        if status_code == 200 and result == "1":
            return True, f"HTTP {status_code} - added to Apex Central UDSO (block)"

        return False, f"HTTP {status_code} - ErrorCode={error_code} ErrorMsg={error_message}"

    outputs = {
        "success": False,
        "detail": "",
        "results_json": "[]",
        "success_count": 0,
        "failed_count": 0,
    }

    def _scalar(v):
        # SOAR sometimes wraps a value in a list, and can even wrap
        # each item of a multi-item list in its own one-item list
        # (e.g. value=[['AAA111'], ['BBB222']]). Unwrap any level of
        # that nesting down to a plain scalar.
        while isinstance(v, list):
            v = v[0] if v else None
        return v

    def _to_list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    def _split_multi(v, allow_split):
        # A single SOAR data path sometimes resolves to one string
        # holding several comma/newline-separated indicators (e.g. an
        # advisory field "AAA111, BBB222") instead of a true list -
        # split those apart too. Only done for SHA1/SHA256 (hex
        # digests never contain a comma); URLs are left alone since a
        # comma can legitimately appear inside a URL's query string.
        if allow_split and isinstance(v, str) and ("," in v or "\n" in v):
            return [p.strip() for p in v.replace("\n", ",").split(",") if p.strip()]
        return [v]

    ioc_type = _scalar(ioc_type)
    allow_split = ioc_type in ("SHA1", "SHA256")

    values = []
    for raw in _to_list(value):
        for item in _split_multi(_scalar(raw), allow_split):
            if item:
                values.append(item)
    notes = [_scalar(n) for n in _to_list(note)]

    def note_for(index):
        if not notes:
            return ""
        if len(notes) == len(values):
            return notes[index] or ""
        return notes[0] or ""

    if not APEX_CENTRAL_URL or not APEX_APPLICATION_ID or not APEX_API_KEY:
        outputs["detail"] = (
            "Not configured: APEX_CENTRAL_URL / APEX_APPLICATION_ID / "
            "APEX_API_KEY must all be set."
        )
        assert json.dumps(outputs)
        return outputs

    if not values:
        outputs["detail"] = "No 'value' provided."
        assert json.dumps(outputs)
        return outputs

    if ioc_type not in APEX_TYPE_MAP:
        outputs["detail"] = f"Unsupported ioc_type '{ioc_type}'. Expected URL, SHA1 or SHA256."
        assert json.dumps(outputs)
        return outputs

    item_results = []

    for index, item_value in enumerate(values):
        try:
            success, detail = block_one(item_value, note_for(index))
            item_results.append({"value": item_value, "success": success, "detail": detail})
        except Exception as item_error:
            item_results.append({
                "value": item_value,
                "success": False,
                "detail": f"Exception ({type(item_error).__name__}): {item_error}",
            })

    success_count = sum(1 for r in item_results if r["success"])
    failed_count = len(item_results) - success_count

    outputs["results_json"] = json.dumps(item_results)
    outputs["success_count"] = success_count
    outputs["failed_count"] = failed_count
    outputs["success"] = failed_count == 0 and success_count > 0
    outputs["detail"] = (
        f"{success_count}/{len(item_results)} {ioc_type} value(s) blocked on Apex Central"
        + ("" if failed_count == 0 else f", {failed_count} failed (see results_json)")
    )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
