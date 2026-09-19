#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 4 (undo): Unblock one URL/SHA1/SHA256
on Trend Micro Apex Central

Deletes the User-Defined Suspicious Object (UDSO). An IOC that was
never blocked (already absent) counts as a success, since the desired
end state already holds.

No external libraries - base64/hashlib/hmac/time/json build the JWT,
and urllib/ssl make the HTTPS call, all standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "unblock_apex".
    2. Input parameters: ioc_type (string), value (string)
    3. Output parameters: success (boolean), detail (string)
    4. Paste everything from "import base64" below into the editor.

Credentials: same environment variables as step4_block_apex.py.
"""


def unblock_apex(ioc_type=None, value=None, **kwargs):
    """
    Args:
        ioc_type (CEF type: string) -- "URL", "SHA1" or "SHA256"
        value (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean)
        detail (CEF type: string)
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

    outputs = {"success": False, "detail": ""}

    try:
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
            outputs["detail"] = f"HTTP {status_code} - non-JSON response from Apex Central"
            assert json.dumps(outputs)
            return outputs

        meta = response_json.get("Meta", {})
        result = str(meta.get("Result", ""))
        error_code = meta.get("ErrorCode")
        error_message = meta.get("ErrorMsg")

        if status_code == 200 and result == "1":
            outputs["success"] = True
            outputs["detail"] = f"HTTP {status_code} - removed from Apex Central UDSO"
        elif error_code in APEX_NOT_FOUND_ERROR_CODES:
            outputs["success"] = True
            outputs["detail"] = f"HTTP {status_code} - was not blocked in Apex Central (nothing to do)"
        else:
            outputs["detail"] = f"HTTP {status_code} - ErrorCode={error_code} ErrorMsg={error_message}"

    except Exception as error:
        outputs["detail"] = f"Exception: {error}"

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
