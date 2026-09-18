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
a prose report you'd need to regex IOCs out of. If the advisory is a
PDF/email body/report, use step1_extract_iocs.py (or Splunk's own
"Parser" app - Splunkbase id 5832 - which has a built-in "extract ioc"
action) instead of this file.

How to paste this into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function.
    2. Input parameter: vault_id (string) - wire this to the vault ID
       of the CSV artifact/attachment (e.g. the container's
       "vault_id" CEF field, or an "Add Output" -> Data Path pointing
       at the attachment artifact).
    3. Output parameters: iocs_json (string), ioc_count (number),
       error (string)
    4. Paste the body of read_ioc_file_custom_function() into the
       generated stub.
    5. Feed iocs_json into a small Format/Filter block that does
       json.loads(iocs_json) so the playbook has a real list to loop
       over (see the "wiring the loop" notes in step2's docstring).
"""

import csv
import io


def detect_value_column(fieldnames):
    for candidate in ("indicator", "value"):
        if candidate in fieldnames:
            return candidate
    return None


def parse_ioc_csv_text(csv_text):
    """
    Core parsing logic - same column rules as ioc_blocker.py's
    load_csv_rows(): requires "type" plus "indicator" or "value",
    "description" optional. Returns a list of
    {"type": ..., "value": ..., "description": ...} dicts.
    """
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
        raise ValueError(f"CSV must contain a 'type' column. Found: {fieldnames}")

    value_column = detect_value_column(fieldnames)
    if value_column is None:
        raise ValueError(f"CSV must contain an 'indicator' (or 'value') column. Found: {fieldnames}")

    iocs = []

    for row in reader:
        raw_type = (row.get("type") or "").strip()
        raw_value = (row.get(value_column) or "").strip()
        description = (row.get("description") or "").strip()

        if not raw_type and not raw_value:
            continue

        iocs.append({"type": raw_type, "value": raw_value, "description": description})

    return iocs


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def read_ioc_file_custom_function(vault_id=None, **kwargs):
    """
    Paste into the SOAR custom function editor.
    Input:   vault_id (string)
    Outputs: iocs_json (string), ioc_count (number), error (string)
    """
    import json

    if not vault_id:
        return {"iocs_json": "[]", "ioc_count": 0, "error": "No vault_id provided."}

    try:
        import phantom.rules as phantom

        success, message, vault_info_list = phantom.vault_info(vault_id=vault_id)

        if not success or not vault_info_list:
            return {"iocs_json": "[]", "ioc_count": 0, "error": f"Could not read vault file: {message}"}

        file_path = vault_info_list[0]["path"]

        with open(file_path, "r", encoding="utf-8-sig") as csv_file:
            csv_text = csv_file.read()

    except ImportError:
        # Not running inside SOAR - lets this file be unit tested standalone.
        with open(vault_id, "r", encoding="utf-8-sig") as csv_file:
            csv_text = csv_file.read()

    try:
        iocs = parse_ioc_csv_text(csv_text)
    except ValueError as error:
        return {"iocs_json": "[]", "ioc_count": 0, "error": str(error)}

    return {"iocs_json": json.dumps(iocs), "ioc_count": len(iocs), "error": ""}


if __name__ == "__main__":
    sample_csv = (
        "type,indicator,description\n"
        "IP,192.168.1[.]100,C2 server\n"
        "DOMAIN,evil[.]example[.]com,Phishing domain\n"
        "URL,hxxps://evil.example.com/malware.exe,Malware URL\n"
    )
    print(parse_ioc_csv_text(sample_csv))
