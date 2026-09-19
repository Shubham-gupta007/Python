#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 5b: Save the final results CSV

Runs once at the very end of the playbook, after a Join block has
collected every step5a result_row_json into a list, and writes them
out as one CSV attached to the container's vault - the SOAR equivalent
of ioc_blocker.py's "<input>_results_<timestamp>.xlsx" /
ioc_unblocker.py's "<input>_unblock_results.csv".

No external libraries - csv/io/json are standard library, and
phantom.rules is SOAR's own built-in module.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "save_results_csv".
    2. Input parameters: result_rows_json (string - a JSON array; if
       your Join block instead hands you a real list, wrap it in
       json.dumps(...) first in a small Format block), filename (string)
    3. Output parameters: success (boolean), vault_id (string),
       error (string)
    4. Paste everything from "import csv" below into the editor.
"""


def save_results_csv(result_rows_json=None, filename=None, **kwargs):
    """
    Args:
        result_rows_json (CEF type: string) -- JSON array of row dicts
        filename (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean)
        vault_id (CEF type: string)
        error (CEF type: string)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import csv
    import io
    import json
    import phantom.rules as phantom

    result_fieldnames = [
        "Row", "Type", "Original_Value", "Fixed_Value", "Auto_Fixed",
        "Description", "Target_Tool", "Status", "Detail", "Processed_At",
    ]

    outputs = {"success": False, "vault_id": "", "error": ""}

    try:
        rows = json.loads(result_rows_json) if isinstance(result_rows_json, str) else result_rows_json
        # Each element may itself still be a JSON string (one per IOC)
        # rather than already a dict, depending on how the Join block
        # assembled them - handle both.
        rows = [json.loads(r) if isinstance(r, str) else r for r in rows]

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=result_fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        csv_text = buffer.getvalue()

        output_name = filename or "ioc_results.csv"
        local_path = f"/opt/phantom/vault/tmp/{output_name}"

        with open(local_path, "w", encoding="utf-8", newline="") as csv_file:
            csv_file.write(csv_text)

        success, message, vault_id = phantom.vault_add(file_location=local_path, file_name=output_name)

        outputs["success"] = bool(success)
        outputs["vault_id"] = vault_id or ""
        if not success:
            outputs["error"] = str(message)

    except Exception as error:
        outputs["error"] = f"Exception: {error}"

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
