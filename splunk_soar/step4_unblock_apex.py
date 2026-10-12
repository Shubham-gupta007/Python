#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 4 (undo): Unblock URL(s)/SHA1(s)/
SHA256(s) on Trend Micro Apex Central

Deletes each User-Defined Suspicious Object (UDSO). An IOC that was
never blocked (already absent) counts as a success, since the desired
end state already holds. Accepts EITHER a single value OR a list of
values in "value" - a single value is just treated as a batch of one.
ioc_type applies to the whole batch (one Apex Central content type per
call - URL, SHA1 or SHA256).

Every value needs its own signed JWT and its own DELETE call - Apex
Central's UDSO API has no bulk endpoint, so a batch here is still N
independent calls, just issued from one custom function invocation
instead of N playbook blocks.

No external libraries - base64/hashlib/hmac/time/json build the JWT,
and urllib/ssl make the HTTPS call, all standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "unblock_apex".
    2. Input parameters: ioc_type (string), value (string - accepts a
       list too)
    3. Output parameters: success (boolean), detail (string),
       results_json (string), success_count (numeric),
       failed_count (numeric)
    4. Paste everything from "import base64" below into the editor.

Credentials: same environment variables as step4_block_apex.py.
"""


def unblock_apex(ioc_type=None, value=None, **kwargs):
    """
    Args:
        ioc_type (CEF type: string) -- "URL", "SHA1" or "SHA256", applies to the whole batch
        value (CEF type: string) -- one value, or a list of them

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

    APEX_API_PATH = "/WebApp/api/SuspiciousObjects/UserDefinedSO/"
    APEX_TYPE_MAP = {"URL": "url", "SHA1": "file_sha1", "SHA256": "file_sha256"}

    # Error codes commonly returned for "no such object" - an unblock
    # hitting one of these means the end state we want already holds.
    APEX_NOT_FOUND_ERROR_CODES = {-1, -2}

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

    def build_apex_unblock_payload(ioc_type, value):
        return {"param": {"type": APEX_TYPE_MAP[ioc_type], "content": value}}

    def http_delete(url, headers, body_text, verify_tls, timeout=30):
        request = urllib.request.Request(url, data=body_text.encode("utf-8"), headers=headers, method="DELETE")

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

    def unblock_one(value):
        payload = build_apex_unblock_payload(ioc_type, value)
        request_body = compact_json(payload)

        token = apex_create_jwt("DELETE", APEX_API_PATH, request_body)

        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json;charset=utf-8",
        }

        url = APEX_CENTRAL_URL + APEX_API_PATH

        status_code, response_text = http_delete(url, headers, request_body, APEX_VERIFY_TLS)

        try:
            response_json = json.loads(response_text)
        except ValueError:
            return False, f"HTTP {status_code} - non-JSON response from Apex Central"

        meta = response_json.get("Meta", {})
        result = str(meta.get("Result", ""))
        error_code = meta.get("ErrorCode")
        error_message = meta.get("ErrorMsg")

        if status_code == 200 and result == "1":
            return True, f"HTTP {status_code} - removed from Apex Central UDSO"

        if error_code in APEX_NOT_FOUND_ERROR_CODES:
            return True, f"HTTP {status_code} - was not blocked in Apex Central (nothing to do)"

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
        # (e.g. value=[['https://a.example'], ['https://b.example']]).
        # Unwrap any level of that nesting down to a plain scalar.
        while isinstance(v, list):
            v = v[0] if v else None
        return v

    def _to_list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    ioc_type = _scalar(ioc_type)
    values = [v for v in (_scalar(x) for x in _to_list(value)) if v]

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

    for item_value in values:
        try:
            success, detail = unblock_one(item_value)
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
        f"{success_count}/{len(item_results)} {ioc_type} value(s) unblocked on Apex Central"
        + ("" if failed_count == 0 else f", {failed_count} failed (see results_json)")
    )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
