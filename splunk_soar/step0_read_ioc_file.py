#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 0: Read the IOC CSV out of the vault

This is the very first step of the playbook: the advisory has already
arrived as a SOAR container (an email with a CSV attachment, a REST
API ingest, or a file uploaded onto an Event) and the CSV is sitting
in that container's vault. This function reads the vault file and
parses it into the same {type, value, description} shape every other
step in this pipeline expects - the same columns ioc_blocker.py's CLI
tool reads (type, indicator/value, description; column names
case-insensitive).

Use this instead of step1_extract_iocs.py when the advisory attachment
IS the structured CSV (type/indicator/description columns) rather than
a prose report you'd need to regex IOCs out of.

No external libraries - csv/json/io are all standard library, and
phantom.rules is SOAR's own built-in module (not a pip package).

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "read_ioc_file".
    2. Input parameter: vault_id (string) - wire this to the vault ID
       of the CSV artifact/attachment.
    3. Output parameters: iocs_json (string), ioc_count (number),
       error (string)
    4. SOAR generates a locked def/docstring block down to the
       "Custom Code Goes Below This Line" marker. Paste everything
       from "import csv" below into the editor in place of its
       placeholder outputs = {} / "Write your custom code here" lines.
    5. Feed iocs_json into a small Format/Filter block that does
       json.loads(iocs_json) so the playbook has a real list to loop
       over (see step2's docstring for the loop wiring).
"""


def read_ioc_file(vault_id=None, **kwargs):
    """
    Args:
        vault_id (CEF type: vault id) -- the CSV attachment's vault ID

    Returns a JSON-serializable object that implements the configured data paths:
        iocs_json (CEF type: string)
        ioc_count (CEF type: numeric)
        error (CEF type: string)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import csv
    import io
    import json
    import phantom.rules as phantom

    outputs = {"iocs_json": "[]", "ioc_count": 0, "error": ""}

    if not vault_id:
        outputs["error"] = "No vault_id provided."
        assert json.dumps(outputs)
        return outputs

    try:
        success, message, vault_info_list = phantom.vault_info(vault_id=vault_id)

        if not success or not vault_info_list:
            outputs["error"] = f"Could not read vault file: {message}"
            assert json.dumps(outputs)
            return outputs

        file_path = vault_info_list[0]["path"]

        with open(file_path, "r", encoding="utf-8-sig") as csv_file:
            csv_text = csv_file.read()

        sample = csv_text[:4096]

        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(io.StringIO(csv_text), dialect=dialect)

        if reader.fieldnames:
            reader.fieldnames = [field.strip().lower() if field else field for field in reader.fieldnames]

        fieldnames = reader.fieldnames or []

        if "type" not in fieldnames:
            outputs["error"] = f"CSV must contain a 'type' column. Found: {fieldnames}"
            assert json.dumps(outputs)
            return outputs

        value_column = "indicator" if "indicator" in fieldnames else ("value" if "value" in fieldnames else None)

        if value_column is None:
            outputs["error"] = f"CSV must contain an 'indicator' (or 'value') column. Found: {fieldnames}"
            assert json.dumps(outputs)
            return outputs

        iocs = []

        for row in reader:
            raw_type = (row.get("type") or "").strip()
            raw_value = (row.get(value_column) or "").strip()
            description = (row.get("description") or "").strip()

            if not raw_type and not raw_value:
                continue

            iocs.append({"type": raw_type, "value": raw_value, "description": description})

        outputs["iocs_json"] = json.dumps(iocs)
        outputs["ioc_count"] = len(iocs)

    except Exception as error:
        outputs["error"] = f"Exception: {error}"

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
