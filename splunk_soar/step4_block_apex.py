#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 4: Block one URL/SHA1/SHA256 on
Trend Micro Apex Central

Takes an already-validated URL, SHA1 or SHA256 from step 2 (only call
this when step2's target_tool == "APEX") and adds it as a blocked
User-Defined Suspicious Object (UDSO).

There is no native Splunk SOAR app for Apex Central UDSO blocking -
the official "Trend Micro Apex One" app (Splunkbase app id 5976) only
covers endpoint quarantine actions, a different use case. This custom
function's signed-JWT REST call is the way to do it.

How to paste this into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function.
    2. Input parameters: ioc_type (string), value (string),
       note (string)
    3. Output parameters: success (boolean), detail (string)
    4. Paste the body of block_apex_custom_function() into the
       generated stub.

Credentials: reads APEX_CENTRAL_URL / APEX_APPLICATION_ID /
APEX_API_KEY from environment variables by default. In SOAR, prefer
pulling these from a configured Asset - see the commented block near
the bottom of this file.
"""

import base64
import hashlib
import hmac
import json
import os
import time

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

APEX_CENTRAL_URL = os.environ.get("APEX_CENTRAL_URL", "")
APEX_APPLICATION_ID = os.environ.get("APEX_APPLICATION_ID", "")
APEX_API_KEY = os.environ.get("APEX_API_KEY", "")
APEX_VERIFY_TLS = os.environ.get("APEX_VERIFY_TLS", "false").lower() == "true"

APEX_API_PATH = "/WebApp/api/SuspiciousObjects/UserDefinedSO/"
SCAN_ACTION = "block"

APEX_TYPE_MAP = {
    "URL": "url",
    "SHA1": "file_sha1",
    "SHA256": "file_sha256",
}

if not APEX_VERIFY_TLS:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


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


def build_apex_payload(ioc_type, value, note):
    return {
        "param": {
            "type": APEX_TYPE_MAP[ioc_type],
            "content": value,
            "notes": note,
            "scan_action": SCAN_ACTION,
        }
    }


def block_via_apex(ioc_type, value, note):
    payload = build_apex_payload(ioc_type, value, note)
    request_body = compact_json(payload)

    token = apex_create_jwt("PUT", APEX_API_PATH, request_body)

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json;charset=utf-8",
    }

    url = APEX_CENTRAL_URL + APEX_API_PATH

    response = requests.put(
        url,
        headers=headers,
        data=request_body.encode("utf-8"),
        verify=APEX_VERIFY_TLS,
        timeout=30,
    )

    try:
        response_json = response.json()
    except ValueError:
        return False, f"HTTP {response.status_code} - non-JSON response from Apex Central"

    meta = response_json.get("Meta", {})
    result = str(meta.get("Result", ""))
    error_code = meta.get("ErrorCode")
    error_message = meta.get("ErrorMsg")

    if response.status_code == 200 and result == "1":
        return True, f"HTTP {response.status_code} - added to Apex Central UDSO (block)"

    return False, f"HTTP {response.status_code} - ErrorCode={error_code} ErrorMsg={error_message}"


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def block_apex_custom_function(ioc_type=None, value=None, note=None, **kwargs):
    """
    Paste into the SOAR custom function editor.
    Inputs:  ioc_type (string, "URL"/"SHA1"/"SHA256"), value (string),
             note (string)
    Outputs: success (boolean), detail (string)

    ---- SOAR-asset version of the credentials ----
    # asset_config = phantom.get_asset_config("apex_central")
    # global APEX_CENTRAL_URL, APEX_APPLICATION_ID, APEX_API_KEY
    # APEX_CENTRAL_URL = asset_config["url"]
    # APEX_APPLICATION_ID = asset_config["application_id"]
    # APEX_API_KEY = asset_config["api_key"]
    """
    try:
        success, detail = block_via_apex(ioc_type, value, note or "Blocked via SOAR playbook")
    except Exception as error:
        return {"success": False, "detail": f"Exception: {error}"}

    return {"success": success, "detail": detail}


if __name__ == "__main__":
    print("This module expects live Apex Central credentials to actually run.")
    print("build_apex_payload('URL', 'https://evil.example.com/x', 'test') ->")
    print(build_apex_payload("URL", "https://evil.example.com/x", "test"))
