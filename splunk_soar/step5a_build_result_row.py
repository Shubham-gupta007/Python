#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 5a: Build one result row

Runs once per IOC (right after its step3a/step3b/step4 block or
unblock call) and shapes that outcome into the same column layout the
CLI tools' results files use, so anyone used to those is at home
reading a SOAR-produced one.

No external libraries - csv/json/datetime are all standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "build_result_row".
    2. Input parameters: row_number (number), ioc_type (string),
       original_value (string), fixed_value (string),
       auto_fixed (boolean), description (string),
       target_tool (string), status (string), detail (string)
    3. Output parameter: result_row_json (string)
    4. Paste everything from "import json" below into the editor.
    5. After the loop, a Join block collects every result_row_json
       into a list - feed that into step5b_save_results_csv.py.
"""


def build_result_row(
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
    """
    Args:
        row_number (CEF type: numeric)
        ioc_type (CEF type: string)
        original_value (CEF type: string)
        fixed_value (CEF type: string)
        auto_fixed (CEF type: boolean)
        description (CEF type: string)
        target_tool (CEF type: string)
        status (CEF type: string)
        detail (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        result_row_json (CEF type: string)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import json
    from datetime import datetime, timezone

    row = {
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

    outputs = {"result_row_json": json.dumps(row)}

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
