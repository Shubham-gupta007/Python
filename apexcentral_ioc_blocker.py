#!/usr/bin/env python3

"""
Trend Micro Apex Central - IOC Blocker

Supported IOC types:

    IP
    URL
    DOMAIN
    SHA1
    SHA256

Input JSON:

[
    {
        "type": "IP",
        "value": "192.168.1.100",
        "description": "C2 server for campaign X"
    },
    {
        "type": "URL",
        "value": "https://evil.example.com/malware.exe",
        "description": "Malware download URL"
    },
    {
        "type": "DOMAIN",
        "value": "evil.example.com",
        "description": "Phishing domain"
    },
    {
        "type": "SHA1",
        "value": "0123456789ABCDEF0123456789ABCDEF01234567",
        "description": "Dropper hash"
    },
    {
        "type": "SHA256",
        "value": "C71DDFA376B2A86BAE93D46D997742502D127979A8774402C936EC6832BB91D0",
        "description": "Ransomware payload hash"
    }
]

Every IOC is submitted with:

    scan_action = block
    notes       = the IOC's own "description" field from the input JSON
                  (falls back to the DEFAULT_NOTE constant below if a
                  block omits "description" or leaves it blank)

CSV to JSON conversion (menu option 3):

    A CSV file with "type", "indicator" and (optional) "description"
    columns can be converted into the input JSON shown above. Defanged
    indicators (hxxp://, hxxps://, "[.]") are re-fanged automatically,
    and every row is validated the same way a block request is
    (IP/URL/DOMAIN/SHA1/SHA256 format checks) before it is written to
    the output JSON - rows that fail validation are reported and
    skipped rather than being silently written out.

JWT:
    Created manually using Python standard library.
    No PyJWT / python-jose required.

Requirements:
    Python 3
    requests

Install:
    pip install requests


Environment:

    export APEX_CENTRAL_URL="https://10.10.10.10:443"
    export APEX_APPLICATION_ID="YOUR_APPLICATION_ID"
    export APEX_API_KEY="YOUR_API_KEY"


Run:

    python3 apexcentral_ioc_blocker.py

The program will display a menu.
"""


import base64
import csv
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

import requests


# ============================================================
# CONFIGURATION
# ============================================================

#APEX_CENTRAL_URL = os.environ.get("APEX_CENTRAL_URL")
#APPLICATION_ID = os.environ.get("APEX_APPLICATION_ID")
#API_KEY = os.environ.get("APEX_API_KEY")

APEX_CENTRAL_URL = ""
APPLICATION_ID = ""
API_KEY = ""

# Change to False only if your Apex Central certificate
# cannot be validated and you understand the risk.
VERIFY_TLS = False

# Official latest UDSO API endpoint.
API_PATH = "/WebApp/api/SuspiciousObjects/UserDefinedSO/"

# Fallback note used only when an IOC block does not supply
# its own "description" field.
DEFAULT_NOTE = "WO0000000208886-WO0000000208904"

# Always block.
SCAN_ACTION = "block"


# ============================================================
# CONFIGURATION VALIDATION
# ============================================================

def validate_configuration():

    missing = []

    if not APEX_CENTRAL_URL:
        missing.append("APEX_CENTRAL_URL")

    if not APPLICATION_ID:
        missing.append("APEX_APPLICATION_ID")

    if not API_KEY:
        missing.append("APEX_API_KEY")

    if missing:
        raise RuntimeError(
            "Missing environment variable(s): "
            + ", ".join(missing)
        )

    #global APEX_CENTRAL_URL

   # APEX_CENTRAL_URL = APEX_CENTRAL_URL.rstrip("/")


# ============================================================
# JSON SERIALIZATION
# ============================================================

def compact_json(data):
    """
    Serialize request body.

    The exact same JSON string is:
        1. Used in checksum calculation
        2. Sent to Apex Central
    """

    return json.dumps(
        data,
        separators=(",", ":"),
        ensure_ascii=False
    )


# ============================================================
# BASE64URL
# ============================================================

def base64url_encode(data):
    """
    JWT Base64URL encoding without padding.
    """

    return (
        base64.urlsafe_b64encode(data)
        .rstrip(b"=")
        .decode("ascii")
    )


# ============================================================
# CHECKSUM
# ============================================================

def create_checksum(
    http_method,
    raw_url,
    canonical_headers,
    request_body
):
    """
    Apex Central checksum.

    SHA256(
        HTTP-METHOD
        |
        RAW-URL
        |
        CANONICAL-REQUEST-HEADERS
        |
        REQUEST-BODY
    )

    Result:
        Base64 encoded SHA-256 digest
    """

    checksum_input = (
        http_method.upper()
        + "|"
        + raw_url.lower()
        + "|"
        + canonical_headers
        + "|"
        + request_body
    )

    digest = hashlib.sha256(
        checksum_input.encode("utf-8")
    ).digest()

    return base64.b64encode(
        digest
    ).decode("ascii")


# ============================================================
# JWT
# ============================================================

def create_jwt(
    http_method,
    raw_url,
    request_body
):
    """
    Create Apex Central JWT manually.

    JWT Header:

        {
            "alg": "HS256",
            "typ": "JWT"
        }

    JWT Payload:

        {
            "appid": "...",
            "iat": ...,
            "version": "V1",
            "checksum": "..."
        }

    Signature:

        HMAC-SHA256(
            encoded_header + "." + encoded_payload,
            API_KEY
        )
    """

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    # --------------------------------------------------------
    # Canonical request headers
    # --------------------------------------------------------
    #
    # We are not sending any custom headers beginning with
    # "API", therefore this is empty.
    # --------------------------------------------------------

    canonical_headers = ""

    # --------------------------------------------------------
    # Checksum
    # --------------------------------------------------------

    checksum = create_checksum(
        http_method=http_method,
        raw_url=raw_url,
        canonical_headers=canonical_headers,
        request_body=request_body
    )

    # --------------------------------------------------------
    # Payload
    # --------------------------------------------------------

    payload = {
        "appid": APPLICATION_ID,
        "iat": time.time(),
        "version": "V1",
        "checksum": checksum
    }

    # --------------------------------------------------------
    # Encode JWT header
    # --------------------------------------------------------

    encoded_header = base64url_encode(
        compact_json(header).encode("utf-8")
    )

    # --------------------------------------------------------
    # Encode JWT payload
    # --------------------------------------------------------

    encoded_payload = base64url_encode(
        compact_json(payload).encode("utf-8")
    )

    # --------------------------------------------------------
    # Signing input
    # --------------------------------------------------------

    signing_input = (
        encoded_header
        + "."
        + encoded_payload
    )

    # --------------------------------------------------------
    # HMAC-SHA256 signature
    # --------------------------------------------------------

    signature = hmac.new(
        API_KEY.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256
    ).digest()

    encoded_signature = base64url_encode(
        signature
    )

    # --------------------------------------------------------
    # Final JWT
    # --------------------------------------------------------

    return (
        encoded_header
        + "."
        + encoded_payload
        + "."
        + encoded_signature
    )


# ============================================================
# IP VALIDATION
# ============================================================

def validate_ip(value):

    value = value.strip()

    try:
        address = ipaddress.ip_address(value)

    except ValueError:
        raise ValueError(
            f"Invalid IP address: {value}"
        )

    # Apex Central UDSO API documentation specifies IPv4
    # for type "ip".
    if address.version != 4:
        raise ValueError(
            "Apex Central UDSO API documentation "
            "specifies IPv4 for type 'ip'. "
            f"Received IPv{address.version}: {value}"
        )

    return str(address)


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(value):

    value = value.strip()

    if not (
        value.startswith("http://")
        or value.startswith("https://")
    ):
        raise ValueError(
            "URL must start with http:// or https://"
        )

    if len(value) > 2047:
        raise ValueError(
            "URL exceeds 2047 characters."
        )

    parsed = urlparse(value)

    if not parsed.netloc:
        raise ValueError(
            "URL does not contain a valid hostname."
        )

    return value


# ============================================================
# DOMAIN VALIDATION
# ============================================================

def validate_domain(value):

    value = value.strip().lower()

    if not value:
        raise ValueError(
            "Domain cannot be empty."
        )

    # Remove trailing dot.
    if value.endswith("."):
        value = value[:-1]

    if len(value) > 253:
        raise ValueError(
            "Domain is too long."
        )

    # Basic DNS domain validation.
    pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if not pattern.fullmatch(value):
        raise ValueError(
            f"Invalid domain: {value}"
        )

    return value


# ============================================================
# SHA-1 VALIDATION
# ============================================================

def validate_sha1(value):

    value = value.strip().upper()

    if not re.fullmatch(
        r"[0-9A-F]{40}",
        value
    ):
        raise ValueError(
            "SHA-1 must contain exactly "
            "40 hexadecimal characters."
        )

    return value


# ============================================================
# SHA-256 VALIDATION
# ============================================================

def validate_sha256(value):

    value = value.strip().upper()

    if not re.fullmatch(
        r"[0-9A-F]{64}",
        value
    ):
        raise ValueError(
            "SHA-256 must contain exactly "
            "64 hexadecimal characters."
        )

    return value


# ============================================================
# NORMALIZE IOC TYPE
# ============================================================

def normalize_type(value):

    if not isinstance(value, str):
        raise ValueError(
            "IOC type must be a string."
        )

    value = value.strip().upper()

    aliases = {

        "IP": "IP",
        "IP_ADDRESS": "IP",
        "IP ADDRESS": "IP",

        "URL": "URL",

        "DOMAIN": "DOMAIN",

        "SHA1": "SHA1",
        "SHA-1": "SHA1",

        "SHA256": "SHA256",
        "SHA-256": "SHA256"
    }

    if value not in aliases:
        raise ValueError(
            "Unsupported IOC type: "
            + value
        )

    return aliases[value]


# ============================================================
# VALIDATE VALUE BY TYPE
# ============================================================

def validate_value_for_type(ioc_type, value):
    """
    Runs the type-specific format check (IP/URL/DOMAIN/SHA1/SHA256)
    for a single IOC value and returns its normalized form.

    Shared by validate_ioc() (JSON input) and csv_to_json()
    (CSV input) so both paths enforce the exact same rules -
    an IP must look like an IP, a URL like a URL, a hash like a
    hash, before it is ever written out or submitted.
    """

    if ioc_type == "IP":
        return validate_ip(value)

    if ioc_type == "URL":
        return validate_url(value)

    if ioc_type == "DOMAIN":
        return validate_domain(value)

    if ioc_type == "SHA1":
        return validate_sha1(value)

    if ioc_type == "SHA256":
        return validate_sha256(value)

    raise ValueError(
        "Unsupported IOC type: "
        + str(ioc_type)
    )


# ============================================================
# NORMALIZE NOTE
# ============================================================

def normalize_note(item):
    """
    Pull the note for one IOC block from its own "description"
    field in the input JSON. Falls back to DEFAULT_NOTE when the
    block does not supply a non-empty "description".
    """

    description = item.get("description")

    if description is None:
        return DEFAULT_NOTE

    if not isinstance(description, str):
        raise ValueError(
            "IOC 'description' must be a string."
        )

    description = description.strip()

    if not description:
        return DEFAULT_NOTE

    return description


# ============================================================
# VALIDATE IOC
# ============================================================

def validate_ioc(item):

    if not isinstance(item, dict):
        raise ValueError(
            "IOC must be a JSON object."
        )

    if "type" not in item:
        raise ValueError(
            "IOC is missing 'type'."
        )

    if "value" not in item:
        raise ValueError(
            "IOC is missing 'value'."
        )

    ioc_type = normalize_type(
        item["type"]
    )

    value = item["value"]

    if not isinstance(value, str):
        raise ValueError(
            "IOC value must be a string."
        )

    value = validate_value_for_type(
        ioc_type,
        value
    )

    note = normalize_note(item)

    return ioc_type, value, note


# ============================================================
# APEX CENTRAL OBJECT TYPE
# ============================================================

def get_apex_type(ioc_type):

    mapping = {

        "IP": "ip",

        "URL": "url",

        "DOMAIN": "domain",

        "SHA1": "file_sha1",

        "SHA256": "file_sha256"
    }

    return mapping[ioc_type]


# ============================================================
# BUILD UDSO PAYLOAD
# ============================================================

def build_payload(
    ioc_type,
    value,
    note
):
    """
    Build Apex Central UDSO request.

    All IOCs requested by the user are sent with:

        scan_action = block

    and:

        notes = the IOC's own "description" from the input JSON
    """

    return {
        "param": {
            "type": get_apex_type(ioc_type),
            "content": value,
            "notes": note,
            "scan_action": SCAN_ACTION
        }
    }


# ============================================================
# SEND TO APEX CENTRAL
# ============================================================

def send_ioc(
    ioc_type,
    value,
    note
):
    """
    Submit one IOC.
    """

    payload = build_payload(
        ioc_type,
        value,
        note
    )

    # IMPORTANT:
    # This exact JSON string is used for both checksum
    # and HTTP request body.
    request_body = compact_json(
        payload
    )

    # --------------------------------------------------------
    # JWT
    # --------------------------------------------------------

    token = create_jwt(
        http_method="PUT",
        raw_url=API_PATH,
        request_body=request_body
    )

    # --------------------------------------------------------
    # HTTP headers
    # --------------------------------------------------------

    headers = {
        "Authorization": (
            "Bearer " + token
        ),
        "Content-Type": (
            "application/json;charset=utf-8"
        )
    }

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    url = (
        APEX_CENTRAL_URL
        + API_PATH
    )

    # --------------------------------------------------------
    # Request
    # --------------------------------------------------------

    response = requests.put(
        url,
        headers=headers,
        data=request_body.encode("utf-8"),
        verify=VERIFY_TLS,
        timeout=30
    )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    try:

        response_json = response.json()

    except ValueError:

        return {
            "success": False,
            "http_status": response.status_code,
            "error_code": None,
            "error_message": (
                "Apex Central returned "
                "non-JSON response"
            ),
            "response": response.text,
            "request": payload
        }

    meta = response_json.get(
        "Meta",
        {}
    )

    result = str(
        meta.get(
            "Result",
            ""
        )
    )

    error_code = meta.get(
        "ErrorCode"
    )

    error_message = meta.get(
        "ErrorMsg"
    )

    success = (
        response.status_code == 200
        and result == "1"
    )

    return {
        "success": success,
        "http_status": response.status_code,
        "result": result,
        "error_code": error_code,
        "error_message": error_message,
        "response": response_json,
        "request": payload
    }


# ============================================================
# DEFANG NORMALIZATION (CSV INPUT)
# ============================================================

def normalize_indicator(value):
    """
    Convert defanged IOC indicators to their normal form.

    e.g. "hxxps://evil[.]example.com" -> "https://evil.example.com"
    """

    if not value:
        return value

    value = value.strip()

    # Convert defanged protocols.
    value = value.replace("hxxps://", "https://")
    value = value.replace("hxxp://", "http://")

    # Convert defanged dots.
    value = value.replace("[.]", ".")

    return value


# ============================================================
# CSV TO JSON CONVERSION
# ============================================================

def csv_to_json(input_file, output_file):
    """
    Convert an IOC CSV file into the JSON array format consumed by
    process_ioc_file() / dry_run().

    Required CSV columns:
        type
        indicator

    Optional CSV column:
        description

    Every row's "type" is normalized (see normalize_type()) and its
    "indicator" is re-fanged and then validated against that type
    (IP/URL/DOMAIN/SHA1/SHA256 format checks) - a row is written to
    the output JSON only if it passes. Rows that fail are printed as
    warnings and skipped rather than being carried into the JSON.
    """

    data = []

    invalid_count = 0
    blank_count = 0

    with open(
        input_file,
        mode="r",
        encoding="utf-8-sig",
        newline=""
    ) as csv_file:

        # Detect CSV delimiter.
        sample = csv_file.read(4096)
        csv_file.seek(0)

        try:
            dialect = csv.Sniffer().sniff(
                sample,
                delimiters=",;|\t"
            )
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(
            csv_file,
            dialect=dialect
        )

        # Clean column names.
        if reader.fieldnames:
            reader.fieldnames = [
                field.strip().lower() if field else field
                for field in reader.fieldnames
            ]

        print(
            "CSV columns found:",
            reader.fieldnames
        )

        # Validate required columns.
        required_columns = {"type", "indicator"}

        if not required_columns.issubset(
            set(reader.fieldnames or [])
        ):
            raise ValueError(
                f"CSV must contain columns: {required_columns}. "
                f"Found: {reader.fieldnames}"
            )

        has_description_column = "description" in (
            reader.fieldnames or []
        )

        # Row 1 is the header, so data rows start at 2.
        for row_number, row in enumerate(reader, start=2):

            raw_type = (row.get("type") or "").strip()
            raw_indicator = (row.get("indicator") or "").strip()

            # Skip fully empty rows.
            if not raw_type and not raw_indicator:
                blank_count += 1
                continue

            description = ""

            if has_description_column:
                description = (row.get("description") or "").strip()

            try:

                ioc_type = normalize_type(raw_type)

                indicator = normalize_indicator(raw_indicator)

                # Confirms the value actually looks like the IOC
                # type it claims to be (a proper IP, URL, domain,
                # SHA1 or SHA256) before it is written out.
                value = validate_value_for_type(
                    ioc_type,
                    indicator
                )

            except ValueError as error:

                invalid_count += 1

                print(
                    f"  [Row {row_number}] SKIPPED - {error} "
                    f"(type={raw_type!r}, indicator={raw_indicator!r})"
                )

                continue

            data.append({
                "type": ioc_type,
                "value": value,
                "description": description
            })

    with open(
        output_file,
        mode="w",
        encoding="utf-8"
    ) as json_file:

        json.dump(
            data,
            json_file,
            indent=4,
            ensure_ascii=False
        )

    print()

    print(
        f"Converted {len(data)} valid record(s)."
    )

    if invalid_count:
        print(
            f"Skipped {invalid_count} invalid record(s) "
            "(type/value failed validation)."
        )

    if blank_count:
        print(
            f"Skipped {blank_count} blank row(s)."
        )

    print(
        f"JSON saved to: {output_file}"
    )

    return len(data), invalid_count, blank_count


# ============================================================
# LOAD JSON
# ============================================================

def load_ioc_file(filename):

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    if not isinstance(data, list):

        raise ValueError(
            "IOC JSON must contain an array."
        )

    return data


# ============================================================
# DRY RUN
# ============================================================

def dry_run(filename):

    try:

        iocs = load_ioc_file(
            filename
        )

    except Exception as error:

        print(
            f"\nERROR: {error}"
        )

        return

    print()
    print("=" * 72)
    print("DRY RUN")
    print("=" * 72)

    print(
        f"Input file: {filename}"
    )

    print(
        f"IOC count : {len(iocs)}"
    )

    for index, item in enumerate(
        iocs,
        start=1
    ):

        print()
        print(
            f"[{index}]"
        )

        try:

            ioc_type, value, note = validate_ioc(
                item
            )

            payload = build_payload(
                ioc_type,
                value,
                note
            )

            print(
                f"Type       : {ioc_type}"
            )

            print(
                f"Value      : {value}"
            )

            print(
                f"Apex type  : "
                f"{get_apex_type(ioc_type)}"
            )

            print(
                f"Action     : {SCAN_ACTION}"
            )

            print(
                f"Note       : {note}"
            )

            print(
                "Request:"
            )

            print(
                json.dumps(
                    payload,
                    indent=4,
                    ensure_ascii=False
                )
            )

        except ValueError as error:

            print(
                "INVALID:",
                error
            )


# ============================================================
# PROCESS IOC FILE
# ============================================================

def process_ioc_file(filename):

    try:

        iocs = load_ioc_file(
            filename
        )

    except Exception as error:

        print(
            f"\nERROR: {error}"
        )

        return

    results = []

    counters = {
        "IP": [0, 0, 0],
        "URL": [0, 0, 0],
        "DOMAIN": [0, 0, 0],
        "SHA1": [0, 0, 0],
        "SHA256": [0, 0, 0]
    }

    print()
    print("=" * 72)
    print("APEX CENTRAL IOC BLOCK")
    print("=" * 72)

    print(
        f"Input file: {filename}"
    )

    print(
        f"IOC count : {len(iocs)}"
    )

    print(
        f"Action    : {SCAN_ACTION}"
    )

    print(
        "Notes     : per-IOC 'description' field "
        f"(default: {DEFAULT_NOTE})"
    )

    for index, item in enumerate(
        iocs,
        start=1
    ):

        print()
        print("-" * 72)

        try:

            ioc_type, value, note = validate_ioc(
                item
            )

        except ValueError as error:

            print(
                f"[{index}] INVALID"
            )

            print(
                f"Error: {error}"
            )

            results.append({
                "index": index,
                "status": "invalid",
                "error": str(error),
                "input": item
            })

            continue

        counters[ioc_type][0] += 1

        print(
            f"[{index}] {ioc_type}"
        )

        print(
            f"Value     : {value}"
        )

        print(
            f"Apex type : "
            f"{get_apex_type(ioc_type)}"
        )

        print(
            f"Action    : {SCAN_ACTION}"
        )

        print(
            f"Note      : {note}"
        )

        try:

            result = send_ioc(
                ioc_type,
                value,
                note
            )

        except requests.RequestException as error:

            print(
                "HTTP ERROR:",
                error
            )

            counters[ioc_type][2] += 1

            results.append({
                "index": index,
                "type": ioc_type,
                "value": value,
                "status": "connection_error",
                "error": str(error)
            })

            continue

        except Exception as error:

            print(
                "ERROR:",
                error
            )

            counters[ioc_type][2] += 1

            results.append({
                "index": index,
                "type": ioc_type,
                "value": value,
                "status": "error",
                "error": str(error)
            })

            continue

        # ----------------------------------------------------
        # Success
        # ----------------------------------------------------

        if result["success"]:

            counters[ioc_type][1] += 1

            print()
            print(
                "SUCCESS - IOC added/blocked"
            )

            print(
                f"HTTP status: "
                f"{result['http_status']}"
            )

            print(
                f"Result     : "
                f"{result['result']}"
            )

            results.append({
                "index": index,
                "type": ioc_type,
                "value": value,
                "note": note,
                "status": "blocked",
                "http_status": result[
                    "http_status"
                ],
                "result": result[
                    "result"
                ]
            })

        # ----------------------------------------------------
        # Failure
        # ----------------------------------------------------

        else:

            counters[ioc_type][2] += 1

            print()
            print(
                "FAILED"
            )

            print(
                f"HTTP status: "
                f"{result.get('http_status')}"
            )

            print(
                f"Result     : "
                f"{result.get('result')}"
            )

            print(
                f"ErrorCode  : "
                f"{result.get('error_code')}"
            )

            print(
                f"ErrorMsg   : "
                f"{result.get('error_message')}"
            )

            print()
            print(
                "Request body sent:"
            )

            print(
                json.dumps(
                    result.get(
                        "request"
                    ),
                    indent=4
                )
            )

            results.append({
                "index": index,
                "type": ioc_type,
                "value": value,
                "note": note,
                "status": "failed",
                "http_status": result.get(
                    "http_status"
                ),
                "result": result.get(
                    "result"
                ),
                "error_code": result.get(
                    "error_code"
                ),
                "error_message": result.get(
                    "error_message"
                ),
                "request": result.get(
                    "request"
                )
            })

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    for ioc_type in (
        "IP",
        "URL",
        "DOMAIN",
        "SHA1",
        "SHA256"
    ):

        total, success, failed = counters[
            ioc_type
        ]

        print(
            f"{ioc_type:<8} "
            f"Total={total:<5} "
            f"Blocked={success:<5} "
            f"Failed={failed}"
        )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    output_file = (
        os.path.splitext(filename)[0]
        + "_results.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print(
        f"Results saved: {output_file}"
    )


# ============================================================
# MENU
# ============================================================

def show_menu():

    while True:

        print()
        print("=" * 72)
        print("TREND MICRO APEX CENTRAL IOC MANAGER")
        print("=" * 72)

        print()
        print("1. Block IOCs from JSON file")
        print("2. Dry-run / validate JSON file")
        print("3. Convert CSV to JSON")
        print("4. Show supported IOC types")
        print("5. Show configuration")
        print("6. Exit")

        print()

        choice = input(
            "Select option [1-6]: "
        ).strip()

        # ----------------------------------------------------
        # Option 1
        # ----------------------------------------------------

        if choice == "1":

            filename = input(
                "\nEnter IOC JSON file: "
            ).strip()

            if not filename:

                print(
                    "No file specified."
                )

                continue

            try:

                validate_configuration()

                process_ioc_file(
                    filename
                )

            except Exception as error:

                print()
                print(
                    "ERROR:",
                    error
                )

        # ----------------------------------------------------
        # Option 2
        # ----------------------------------------------------

        elif choice == "2":

            filename = input(
                "\nEnter IOC JSON file: "
            ).strip()

            if not filename:

                print(
                    "No file specified."
                )

                continue

            dry_run(
                filename
            )

        # ----------------------------------------------------
        # Option 3
        # ----------------------------------------------------

        elif choice == "3":

            input_csv = input(
                "\nEnter input CSV file: "
            ).strip()

            if not input_csv:

                print(
                    "No file specified."
                )

                continue

            default_output = (
                os.path.splitext(input_csv)[0]
                + ".json"
            )

            output_json = input(
                f"Enter output JSON file "
                f"[{default_output}]: "
            ).strip()

            if not output_json:
                output_json = default_output

            print()
            print("=" * 72)
            print("CSV TO JSON CONVERSION")
            print("=" * 72)

            print(
                f"Input file : {input_csv}"
            )

            print(
                f"Output file: {output_json}"
            )

            print()

            try:

                csv_to_json(
                    input_csv,
                    output_json
                )

            except Exception as error:

                print()
                print(
                    "ERROR:",
                    error
                )

        # ----------------------------------------------------
        # Option 4
        # ----------------------------------------------------

        elif choice == "4":

            print()
            print(
                "Supported IOC types:"
            )

            print()
            print(
                "  IP"
            )

            print(
                "      Apex Central type: ip"
            )

            print()

            print(
                "  URL"
            )

            print(
                "      Apex Central type: url"
            )

            print()

            print(
                "  DOMAIN"
            )

            print(
                "      Apex Central type: domain"
            )

            print()

            print(
                "  SHA1 / SHA-1"
            )

            print(
                "      Apex Central type: file_sha1"
            )

            print()

            print(
                "  SHA256 / SHA-256"
            )

            print(
                "      Apex Central type: file_sha256"
            )

            print()
            print(
                "All are configured with:"
            )

            print(
                "      scan_action = block"
            )

            print(
                "      notes = each IOC's own "
                "\"description\" field "
                f"(default: \"{DEFAULT_NOTE}\")"
            )

        # ----------------------------------------------------
        # Option 5
        # ----------------------------------------------------

        elif choice == "5":

            print()
            print(
                "Configuration"
            )

            print("-" * 40)

            print(
                "Apex Central URL:"
            )

            print(
                APEX_CENTRAL_URL
                if APEX_CENTRAL_URL
                else "NOT SET"
            )

            print()

            print(
                "Application ID:"
            )

            if APPLICATION_ID:

                # Don't display complete credential.
                if len(APPLICATION_ID) > 8:

                    print(
                        APPLICATION_ID[:4]
                        + "..."
                        + APPLICATION_ID[-4:]
                    )

                else:

                    print(
                        "********"
                    )

            else:

                print(
                    "NOT SET"
                )

            print()

            print(
                "API Key:"
            )

            if API_KEY:

                print(
                    "********"
                )

            else:

                print(
                    "NOT SET"
                )

            print()

            print(
                "API endpoint:"
            )

            print(
                API_PATH
            )

            print()

            print(
                "TLS verification:",
                VERIFY_TLS
            )

            print()

            print(
                "Scan action:",
                SCAN_ACTION
            )

            print(
                "Default note (fallback):",
                DEFAULT_NOTE
            )

        # ----------------------------------------------------
        # Option 6
        # ----------------------------------------------------

        elif choice == "6":

            print(
                "\nExiting."
            )

            break

        else:

            print(
                "\nInvalid option."
            )


# ============================================================
# MAIN
# ============================================================

def main():

    try:

        show_menu()

    except KeyboardInterrupt:

        print(
            "\n\nExiting."
        )

        sys.exit(0)


if __name__ == "__main__":
    main()
