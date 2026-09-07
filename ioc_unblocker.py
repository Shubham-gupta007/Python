#!/usr/bin/env python3
"""
Threat Intel IOC Unblocker - Trend Micro Apex Central + FortiGate

The undo counterpart to ioc_blocker.py, for when an IOC turns out to be
a false positive (or an incident closes) and needs to come back off
both tools. Same workflow, run in reverse:

    1. Read a raw CSV (columns: type, indicator/value, description) -
       normally the earlier block run's own *_results.csv, or a fresh
       list from the threat intel team of IOCs to release.
    2. Auto-correct/validate every indicator exactly like the blocker
       does (defanged values, stray whitespace, wrong case, missing
       URL schemes) - an unblock request has to name the exact value
       that was blocked, so it goes through the same repair pass
       before anything is removed.
    3. Route the now-valid indicator to the right tool and undo the
       block:

           IP, DOMAIN              -> FortiGate firewall
                                      (remove from the address group,
                                       then delete the address object)

           URL, SHA1, SHA256       -> Trend Micro Apex Central
                                      (delete the User-Defined
                                       Suspicious Object)

       An IOC that was never blocked (already absent) is treated as a
       success - the end state you asked for already holds.
    4. Write one results CSV: original value, auto-corrected value,
       which tool it was removed from, and whether the unblock
       succeeded - so you can filter and confirm every entry cleanly.

Requirements:
    pip install requests

Environment variables: identical to ioc_blocker.py.

    Trend Micro Apex Central:
        APEX_CENTRAL_URL        e.g. "https://10.10.10.10:443"
        APEX_APPLICATION_ID
        APEX_API_KEY
        APEX_VERIFY_TLS          optional, "true"/"false", default "false"

    FortiGate:
        FORTIGATE_HOST           e.g. "https://192.168.1.1:443"
        FORTIGATE_API_KEY
        FORTIGATE_VDOM           optional, default "root"
        FORTIGATE_IP_GROUP       optional, default "Blocked-IPs"
        FORTIGATE_DOMAIN_GROUP   optional, default "Blocked-Domains"
        FORTIGATE_VERIFY_TLS     optional, "true"/"false", default "false"

    Only the variables for the tool(s) actually needed by the CSV's
    IOC types are required.

Run:

    python3 ioc_unblocker.py

    The program will display a menu.

Input CSV format (column names are case-insensitive) - same shape as
ioc_blocker.py's input/output, so its *_results.csv can be fed straight
back in to release everything that was blocked:

    type,indicator,description
    IP,192.168.1.100,False positive - internal scanner
    DOMAIN,evil.example.com,Incident closed
    URL,https://evil.example.com/malware.exe,Incident closed
    SHA1,0123456789abcdef0123456789abcdef01234567,False positive
    SHA256,c71ddfa376b2a86bae93d46d997742502d127979a8774402c936ec6832bb91d0,Incident closed

Output: <input file name>_unblock_results.csv, with columns:

    Row, Type, Original_Value, Fixed_Value, Auto_Fixed, Description,
    Target_Tool, Status, Detail, Processed_At
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
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# ============================================================
# CONFIGURATION - TREND MICRO APEX CENTRAL
# ============================================================

APEX_CENTRAL_URL = os.environ.get("APEX_CENTRAL_URL", "")
APEX_APPLICATION_ID = os.environ.get("APEX_APPLICATION_ID", "")
APEX_API_KEY = os.environ.get("APEX_API_KEY", "")
APEX_VERIFY_TLS = os.environ.get("APEX_VERIFY_TLS", "false").lower() == "true"

APEX_API_PATH = "/WebApp/api/SuspiciousObjects/UserDefinedSO/"

APEX_TYPE_MAP = {
    "URL": "url",
    "SHA1": "file_sha1",
    "SHA256": "file_sha256",
}

# FortiOS/Apex error codes commonly returned for "no such object" -
# an unblock hitting one of these means the end state we want already
# holds, so it's reported as a success, not a failure.
APEX_NOT_FOUND_ERROR_CODES = {-1, -2}
FORTIGATE_NOT_FOUND_ERROR_CODES = {-3}


# ============================================================
# CONFIGURATION - FORTIGATE
# ============================================================

FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "")
FORTIGATE_API_KEY = os.environ.get("FORTIGATE_API_KEY", "")
FORTIGATE_VDOM = os.environ.get("FORTIGATE_VDOM", "root")
FORTIGATE_IP_GROUP = os.environ.get("FORTIGATE_IP_GROUP", "Blocked-IPs")
FORTIGATE_DOMAIN_GROUP = os.environ.get("FORTIGATE_DOMAIN_GROUP", "Blocked-Domains")
FORTIGATE_VERIFY_TLS = os.environ.get("FORTIGATE_VERIFY_TLS", "false").lower() == "true"

FORTIGATE_ADDRESS_PATH = "/api/v2/cmdb/firewall/address"
FORTIGATE_GROUP_PATH = "/api/v2/cmdb/firewall/addrgrp"

if not APEX_VERIFY_TLS or not FORTIGATE_VERIFY_TLS:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ============================================================
# ROUTING - WHICH TOOL HANDLES WHICH IOC TYPE
# ============================================================

ROUTE_TO_FORTIGATE = {"IP", "DOMAIN"}
ROUTE_TO_APEX = {"URL", "SHA1", "SHA256"}

TARGET_LABEL = {
    "FORTIGATE": "FortiGate",
    "APEX": "Trend Micro Apex Central",
}


def target_for_type(ioc_type):
    if ioc_type in ROUTE_TO_FORTIGATE:
        return "FORTIGATE"
    if ioc_type in ROUTE_TO_APEX:
        return "APEX"
    return None


def validate_apex_configuration():
    missing = [
        name
        for name, value in (
            ("APEX_CENTRAL_URL", APEX_CENTRAL_URL),
            ("APEX_APPLICATION_ID", APEX_APPLICATION_ID),
            ("APEX_API_KEY", APEX_API_KEY),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing Apex Central environment variable(s): " + ", ".join(missing)
        )


def validate_fortigate_configuration():
    missing = [
        name
        for name, value in (
            ("FORTIGATE_HOST", FORTIGATE_HOST),
            ("FORTIGATE_API_KEY", FORTIGATE_API_KEY),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing FortiGate environment variable(s): " + ", ".join(missing)
        )


# ============================================================
# IOC TYPE NORMALIZATION
# ============================================================

TYPE_ALIASES = {
    "IP": "IP",
    "IP_ADDRESS": "IP",
    "IP ADDRESS": "IP",
    "URL": "URL",
    "DOMAIN": "DOMAIN",
    "FQDN": "DOMAIN",
    "SHA1": "SHA1",
    "SHA-1": "SHA1",
    "SHA256": "SHA256",
    "SHA-256": "SHA256",
}


def normalize_type(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("IOC 'type' is missing or empty.")

    key = value.strip().upper()

    if key not in TYPE_ALIASES:
        raise ValueError(
            f"Unsupported IOC type '{value}'. Supported: IP, DOMAIN "
            "(unblocked on FortiGate), URL, SHA1, SHA256 (unblocked on "
            "Trend Micro Apex Central)."
        )

    return TYPE_ALIASES[key]


# ============================================================
# AUTO-FIX (DEFANG / FORMAT REPAIR) + VALIDATION
# ============================================================
# Identical to ioc_blocker.py - an unblock request has to name the
# exact value that was blocked, so the same repair pass runs here.

def strip_wrapping(value):
    """Removes surrounding quotes/angle-brackets/whitespace a feed may add."""
    return value.strip().strip("\"'<>").strip()


def defang_fix(value):
    """
    Reverses the common ways threat-intel feeds "defang" an indicator so
    it can't be clicked/resolved by accident.
    """
    value = strip_wrapping(value)

    value = re.sub(r"hxxps://", "https://", value, flags=re.IGNORECASE)
    value = re.sub(r"hxxp://", "http://", value, flags=re.IGNORECASE)

    for pattern in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        value = re.sub(re.escape(pattern), ".", value, flags=re.IGNORECASE)

    for pattern in ("[:]", "(:)"):
        value = value.replace(pattern, ":")

    value = value.replace("[at]", "@").replace("(at)", "@")

    return value.strip()


def fix_ip(raw_value):
    return defang_fix(raw_value)


def fix_domain(raw_value):
    value = defang_fix(raw_value).rstrip(".").lower()
    return value


def fix_url(raw_value):
    value = defang_fix(raw_value)

    if not re.match(r"^https?://", value, flags=re.IGNORECASE):
        # Feed dropped the scheme (e.g. "evil.example.com/malware.exe").
        value = "http://" + value

    return value


def fix_hash(raw_value):
    value = defang_fix(raw_value)
    # Some feeds separate hash bytes with spaces, dashes or colons.
    value = re.sub(r"[\s:-]", "", value)
    return value.upper()


def validate_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"Invalid IP address: {value}")

    if address.version != 4:
        raise ValueError(
            f"Apex/FortiGate here expects IPv4, got IPv{address.version}: {value}"
        )

    return str(address)


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def validate_domain(value):
    if not DOMAIN_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid domain: {value}")

    return value


def validate_url(value):
    if not (value.startswith("http://") or value.startswith("https://")):
        raise ValueError("URL must start with http:// or https://")

    if len(value) > 2047:
        raise ValueError("URL exceeds 2047 characters.")

    if not urlparse(value).netloc:
        raise ValueError("URL does not contain a valid hostname.")

    return value


def validate_sha1(value):
    if not re.fullmatch(r"[0-9A-F]{40}", value):
        raise ValueError("SHA-1 must contain exactly 40 hexadecimal characters.")

    return value


def validate_sha256(value):
    if not re.fullmatch(r"[0-9A-F]{64}", value):
        raise ValueError("SHA-256 must contain exactly 64 hexadecimal characters.")

    return value


FIXERS = {
    "IP": fix_ip,
    "DOMAIN": fix_domain,
    "URL": fix_url,
    "SHA1": fix_hash,
    "SHA256": fix_hash,
}

VALIDATORS = {
    "IP": validate_ip,
    "DOMAIN": validate_domain,
    "URL": validate_url,
    "SHA1": validate_sha1,
    "SHA256": validate_sha256,
}


def normalize_and_validate(ioc_type, raw_value):
    """
    Auto-corrects a raw indicator for its declared type and validates
    the result. Returns (fixed_value, was_auto_fixed). Raises
    ValueError if the value still doesn't look right even after the
    fix-up pass - such a value is never sent to either tool.
    """
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise ValueError("Indicator value is missing or empty.")

    original = raw_value.strip()

    fixed = FIXERS[ioc_type](raw_value)
    fixed = VALIDATORS[ioc_type](fixed)

    was_fixed = fixed != original

    return fixed, was_fixed


# ============================================================
# TREND MICRO APEX CENTRAL - JWT SIGNING
# ============================================================

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


# ============================================================
# TREND MICRO APEX CENTRAL - UNBLOCK
# ============================================================

def build_apex_unblock_payload(ioc_type, value):
    return {
        "param": {
            "type": APEX_TYPE_MAP[ioc_type],
            "content": value,
        }
    }


def apex_is_not_found(response):
    try:
        return response.json().get("Meta", {}).get("ErrorCode") in APEX_NOT_FOUND_ERROR_CODES
    except ValueError:
        return False


def unblock_via_apex(ioc_type, value):
    """Returns (success, detail_text) - detail_text is plain English for the results CSV."""
    payload = build_apex_unblock_payload(ioc_type, value)
    request_body = compact_json(payload)

    token = apex_create_jwt("DELETE", APEX_API_PATH, request_body)

    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json;charset=utf-8",
    }

    url = APEX_CENTRAL_URL + APEX_API_PATH

    response = requests.delete(
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
        return True, f"HTTP {response.status_code} - removed from Apex Central UDSO"

    if apex_is_not_found(response):
        return True, f"HTTP {response.status_code} - was not blocked in Apex Central (nothing to do)"

    return False, f"HTTP {response.status_code} - ErrorCode={error_code} ErrorMsg={error_message}"


# ============================================================
# FORTIGATE - UNBLOCK
# ============================================================

def fortigate_api_headers():
    return {
        "Authorization": f"Bearer {FORTIGATE_API_KEY}",
        "Content-Type": "application/json",
    }


def fortigate_is_not_found(response):
    try:
        return response.json().get("error") in FORTIGATE_NOT_FOUND_ERROR_CODES
    except ValueError:
        return False


def fortigate_remove_from_group(group_name, member_name):
    """Removes member_name from a group's member list, if present."""
    url = f"{FORTIGATE_HOST}{FORTIGATE_GROUP_PATH}/{group_name}"

    response = requests.get(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code != 200:
        if fortigate_is_not_found(response):
            return True, f"group '{group_name}' does not exist (nothing to do)"
        return False, f"HTTP {response.status_code} - could not look up group '{group_name}'"

    body = response.json()
    results = body.get("results", [])
    existing_members = [m["name"] for m in results[0].get("member", [])] if results else []

    if member_name not in existing_members:
        return True, f"was not a member of group '{group_name}' (nothing to do)"

    remaining_members = [m for m in existing_members if m != member_name]
    payload = {"member": [{"name": m} for m in remaining_members]}

    response = requests.put(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        json=payload,
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code == 200:
        return True, f"removed from group '{group_name}'"

    return False, f"HTTP {response.status_code} - could not update group '{group_name}'"


def fortigate_delete_address(name):
    """Deletes the address object outright. Treats "already gone" as success."""
    url = f"{FORTIGATE_HOST}{FORTIGATE_ADDRESS_PATH}/{name}"

    response = requests.delete(
        url,
        headers=fortigate_api_headers(),
        params={"vdom": FORTIGATE_VDOM},
        verify=FORTIGATE_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code == 200:
        return True, "address object deleted"

    if response.status_code == 404 or fortigate_is_not_found(response):
        return True, "address object did not exist (nothing to do)"

    try:
        body = response.json()
    except ValueError:
        body = response.text

    return False, f"HTTP {response.status_code} - could not delete address object: {body}"


def unblock_via_fortigate(ioc_type, value):
    """Returns (success, detail_text)."""
    group = FORTIGATE_IP_GROUP if ioc_type == "IP" else FORTIGATE_DOMAIN_GROUP

    group_success, group_detail = fortigate_remove_from_group(group, value)

    if not group_success:
        return False, group_detail

    delete_success, delete_detail = fortigate_delete_address(value)

    detail = f"{group_detail}, {delete_detail}"

    return delete_success, detail


# ============================================================
# CSV INPUT
# ============================================================

def load_csv_rows(input_file):
    with open(input_file, mode="r", encoding="utf-8-sig", newline="") as csv_file:
        sample = csv_file.read(4096)
        csv_file.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(csv_file, dialect=dialect)

        if reader.fieldnames:
            reader.fieldnames = [
                field.strip().lower() if field else field for field in reader.fieldnames
            ]

        fieldnames = reader.fieldnames or []

        if "type" not in fieldnames:
            raise ValueError(f"CSV must contain a 'type' column. Found: {fieldnames}")

        # Accepts "indicator"/"value" (fresh IOC lists) as well as
        # "original_value"/"fixed_value" so ioc_blocker.py's own
        # *_results.csv can be fed straight back in.
        for candidate in ("indicator", "value", "fixed_value", "original_value"):
            if candidate in fieldnames:
                value_column = candidate
                break
        else:
            raise ValueError(
                "CSV must contain an 'indicator', 'value' or 'fixed_value' column. "
                f"Found: {fieldnames}"
            )

        rows = list(reader)

    return rows, value_column


# ============================================================
# ROW PROCESSING
# ============================================================

def process_row(row_number, raw_type, raw_value, description):
    """
    Validates/auto-fixes one row and returns a result dict ready for
    the results CSV, plus (ioc_type, fixed_value, target) to unblock -
    or None as the second item if the row can't be processed at all.
    """
    result = {
        "Row": row_number,
        "Type": raw_type,
        "Original_Value": raw_value,
        "Fixed_Value": "",
        "Auto_Fixed": "No",
        "Description": description,
        "Target_Tool": "",
        "Status": "",
        "Detail": "",
        "Processed_At": "",
    }

    try:
        ioc_type = normalize_type(raw_type)
    except ValueError as error:
        result["Status"] = "Invalid"
        result["Detail"] = str(error)
        return result, None

    result["Type"] = ioc_type

    try:
        fixed_value, was_fixed = normalize_and_validate(ioc_type, raw_value)
    except ValueError as error:
        result["Status"] = "Invalid"
        result["Detail"] = f"Could not validate/auto-correct: {error}"
        return result, None

    result["Fixed_Value"] = fixed_value
    result["Auto_Fixed"] = "Yes" if was_fixed else "No"

    target = target_for_type(ioc_type)
    result["Target_Tool"] = TARGET_LABEL[target]

    return result, (ioc_type, fixed_value, target)


# ============================================================
# FULL RUN
# ============================================================

def write_results_csv(output_file, results):
    fieldnames = [
        "Row",
        "Type",
        "Original_Value",
        "Fixed_Value",
        "Auto_Fixed",
        "Description",
        "Target_Tool",
        "Status",
        "Detail",
        "Processed_At",
    ]

    with open(output_file, mode="w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_summary(results):
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    by_status = {}
    by_type = {}

    for row in results:
        by_status[row["Status"]] = by_status.get(row["Status"], 0) + 1
        by_type.setdefault(
            row["Type"], {"Unblocked": 0, "Failed": 0, "Invalid": 0, "Would Unblock": 0}
        )
        status = row["Status"]
        if status in by_type[row["Type"]]:
            by_type[row["Type"]][status] += 1

    print(f"Total rows processed: {len(results)}")
    for status, count in sorted(by_status.items()):
        print(f"  {status:<14}: {count}")

    print()
    print(f"{'Type':<10} {'Unblocked':<11} {'Failed':<10} {'Invalid':<10} {'Would Unblock':<14}")
    for ioc_type, counts in sorted(by_type.items()):
        print(
            f"{ioc_type:<10} {counts['Unblocked']:<11} {counts['Failed']:<10} "
            f"{counts['Invalid']:<10} {counts['Would Unblock']:<14}"
        )


def process_file(input_file, dry_run):
    rows, value_column = load_csv_rows(input_file)

    print()
    print("=" * 72)
    print("DRY RUN - VALIDATE & AUTO-FIX ONLY" if dry_run else "IOC UNBLOCK RUN")
    print("=" * 72)
    print(f"Input file : {input_file}")
    print(f"Row count  : {len(rows)}")

    # Pre-scan: which tool(s) will actually be needed, so we only ask
    # for credentials the CSV's IOC types actually require.
    needed_targets = set()
    for row in rows:
        try:
            ioc_type = normalize_type(row.get("type", ""))
            target = target_for_type(ioc_type)
            if target:
                needed_targets.add(target)
        except ValueError:
            continue

    if not dry_run:
        if "APEX" in needed_targets:
            validate_apex_configuration()
        if "FORTIGATE" in needed_targets:
            validate_fortigate_configuration()

    results = []

    for row_number, row in enumerate(rows, start=2):
        raw_type = (row.get("type") or "").strip()
        raw_value = (row.get(value_column) or "").strip()
        description = (row.get("description") or "").strip()

        if not raw_type and not raw_value:
            continue

        print()
        print("-" * 72)
        print(f"[Row {row_number}] type={raw_type!r} value={raw_value!r}")

        result, route = process_row(row_number, raw_type, raw_value, description)
        result["Processed_At"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

        if route is None:
            print(f"  INVALID - {result['Detail']}")
            results.append(result)
            continue

        ioc_type, fixed_value, target = route

        if result["Auto_Fixed"] == "Yes":
            print(f"  Auto-fixed: {raw_value!r} -> {fixed_value!r}")

        if dry_run:
            result["Status"] = "Would Unblock"
            result["Detail"] = f"Would remove from {result['Target_Tool']}"
            print(f"  {result['Detail']}")
            results.append(result)
            continue

        if target == "APEX":
            success, detail = unblock_via_apex(ioc_type, fixed_value)
        else:
            success, detail = unblock_via_fortigate(ioc_type, fixed_value)

        result["Status"] = "Unblocked" if success else "Failed"
        result["Detail"] = detail

        print(f"  [{'UNBLOCKED' if success else 'FAILED'}] {detail}")

        results.append(result)

    output_file = os.path.splitext(input_file)[0] + "_unblock_results.csv"
    write_results_csv(output_file, results)

    print_summary(results)

    print()
    print(f"Results saved: {output_file}")

    return results


# ============================================================
# MENU
# ============================================================

def show_configuration():
    print()
    print("Trend Micro Apex Central")
    print("-" * 40)
    print("URL:", APEX_CENTRAL_URL or "NOT SET")
    print("Application ID:", "SET" if APEX_APPLICATION_ID else "NOT SET")
    print("API Key:", "SET" if APEX_API_KEY else "NOT SET")
    print("TLS verification:", APEX_VERIFY_TLS)

    print()
    print("FortiGate")
    print("-" * 40)
    print("Host:", FORTIGATE_HOST or "NOT SET")
    print("API Key:", "SET" if FORTIGATE_API_KEY else "NOT SET")
    print("VDOM:", FORTIGATE_VDOM)
    print("IP block group:", FORTIGATE_IP_GROUP)
    print("Domain block group:", FORTIGATE_DOMAIN_GROUP)
    print("TLS verification:", FORTIGATE_VERIFY_TLS)

    print()
    print("Routing")
    print("-" * 40)
    print("IP, DOMAIN            -> FortiGate (remove from group + delete address)")
    print("URL, SHA1, SHA256     -> Trend Micro Apex Central (delete UDSO)")


def show_menu():
    while True:
        print()
        print("=" * 72)
        print("THREAT INTEL IOC UNBLOCKER - APEX CENTRAL + FORTIGATE")
        print("=" * 72)

        print()
        print("1. Process CSV file (validate, auto-fix, unblock, save results CSV)")
        print("2. Dry-run CSV file (validate & auto-fix only, no unblocking)")
        print("3. Show configuration")
        print("4. Exit")

        print()
        choice = input("Select option [1-4]: ").strip()

        if choice == "1":
            filename = input("\nEnter IOC CSV file: ").strip()
            if not filename:
                print("No file specified.")
                continue

            try:
                process_file(filename, dry_run=False)
            except Exception as error:
                print(f"\nERROR: {error}")

        elif choice == "2":
            filename = input("\nEnter IOC CSV file: ").strip()
            if not filename:
                print("No file specified.")
                continue

            try:
                process_file(filename, dry_run=True)
            except Exception as error:
                print(f"\nERROR: {error}")

        elif choice == "3":
            show_configuration()

        elif choice == "4":
            print("\nExiting.")
            break

        else:
            print("\nInvalid option.")


# ============================================================
# MAIN
# ============================================================

def main():
    try:
        show_menu()
    except KeyboardInterrupt:
        print("\n\nExiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()
