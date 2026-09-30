#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 5: Build one result row / save the
final results CSV

Two small, independent pieces:

    build_result_row_custom_function() runs once per IOC (right after
    its step3/step4 block or unblock call) and shapes that outcome
    into the same column layout the CLI tools' results CSVs use, so
    anyone used to those files can read a SOAR-produced one the same
    way.

    save_results_csv_custom_function() runs once at the very end of
    the playbook, after a Join/Format block has collected every
    per-IOC row into a list, and writes them out as one CSV attached
    to the container's vault - the SOAR equivalent of ioc_blocker.py's
    "<input>_results.csv" / ioc_unblocker.py's
    "<input>_unblock_results.csv".

How to paste build_result_row_custom_function into SOAR:

    1. Input parameters: row_number (number), ioc_type (string),
       original_value (string), fixed_value (string),
       auto_fixed (boolean), description (string), target_tool (string),
       status (string), detail (string)
    2. Output parameter: result_row_json (string)
    3. Paste the body of build_result_row_custom_function().

How to paste save_results_csv_custom_function into SOAR (call this
AFTER a Join block has gathered every result_row_json into a list):

    1. Input parameters: result_rows_json (string - a JSON array,
       or SOAR will hand you a list under the hood if you feed it a
       list output directly; json.dumps it first if not), filename (string)
    2. Output parameters: success (boolean), vault_id (string)
    3. Paste the body of save_results_csv_custom_function(). It uses
       phantom.vault_add() when running inside SOAR, and falls back to
       a plain local file write when run standalone for testing.
"""

import csv
import io
import json
from datetime import datetime, timezone


RESULT_FIELDNAMES = [
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


def build_result_row(
    row_number,
    ioc_type,
    original_value,
    fixed_value,
    auto_fixed,
    description,
    target_tool,
    status,
    detail,
):
    return {
        "Row": row_number,
        "Type": ioc_type,
        "Original_Value": original_value,
        "Fixed_Value": fixed_value,
        "Auto_Fixed": "Yes" if auto_fixed else "No",
        "Description": description or "",
        "Target_Tool": target_tool or "",
        "Status": status,
        "Detail": detail,
        "Processed_At": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def rows_to_csv_text(rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=RESULT_FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPERS
# ============================================================

def build_result_row_custom_function(
    row_number=None,
    ioc_type=None,
    original_value=None,
    fixed_value=None,
    auto_fixed=None,
    description=None,
    target_tool=None,
    status=None,
    detail=None,
    **kwargs,
):
    row = build_result_row(
        row_number,
        ioc_type,
        original_value,
        fixed_value,
        bool(auto_fixed),
        description,
        target_tool,
        status,
        detail,
    )

    return {"result_row_json": json.dumps(row)}


def save_results_csv_custom_function(result_rows_json=None, filename=None, **kwargs):
    """
    result_rows_json: a JSON array of the dicts produced by
    build_result_row_custom_function (SOAR will hand you a list of
    result_row_json strings if that output was fed in as a list -
    json.dumps/normalize it into one array first in a small Format
    block if needed).
    """
    try:
        rows = json.loads(result_rows_json) if isinstance(result_rows_json, str) else result_rows_json
        # Each element may itself still be a JSON string (one per IOC)
        # rather than already a dict, depending on how the Join block
        # assembled them - handle both.
        rows = [json.loads(r) if isinstance(r, str) else r for r in rows]
    except (TypeError, ValueError) as error:
        return {"success": False, "vault_id": "", "error": f"Could not parse result_rows_json: {error}"}

    csv_text = rows_to_csv_text(rows)
    output_name = filename or "ioc_results.csv"

    try:
        import phantom.rules as phantom  # noqa: F401  (only available inside SOAR)

        local_path = f"/opt/phantom/vault/tmp/{output_name}"
        with open(local_path, "w", encoding="utf-8", newline="") as csv_file:
            csv_file.write(csv_text)

        success, message, vault_id = phantom.vault_add(
            file_location=local_path,
            file_name=output_name,
        )

        return {"success": success, "vault_id": vault_id or ""}

    except ImportError:
        # Not running inside SOAR - fall back to a plain local file so
        # this is still testable outside the platform.
        with open(output_name, "w", encoding="utf-8", newline="") as csv_file:
            csv_file.write(csv_text)

        return {"success": True, "vault_id": "", "note": f"Saved locally to {output_name} (no phantom module found)"}


if __name__ == "__main__":
    sample_rows = [
        build_result_row(2, "IP", "192.168.1[.]100", "192.168.1.100", True, "C2 server", "FortiGate", "Blocked", "ok"),
        build_result_row(3, "IP", "999.999.999.999", "", False, "Bad IP", "", "Invalid", "Invalid IP address"),
    ]

    print(rows_to_csv_text(sample_rows))
