"""
Parse a raw (often defanged, markdown-formatted) WAF alert email/notable text
into clean CEF fields for Splunk SOAR, so a playbook can consume structured
values instead of re-parsing free text itself.

Three ways to use this module:

1. Pure parsing (no SOAR dependency) - call `build_cef_fields(raw_text)` to
   get back a dict of clean CEF fields (IPs refanged, "hXXp" -> "http",
   markdown bullets/line-breaks stripped, one clean "Detailed_Decription"
   narrative field).

2. As a Splunk SOAR "Custom Function" playbook block - paste the
   `custom_function()` definition below into the block's code editor.
   Define a single input parameter named `raw_alert_text` (string) on the
   block, and output parameters matching the keys of the `outputs` dict
   returned (output_source_ip, output_description, output_cef_json, ...).
   Downstream blocks then reference e.g.
   `custom_function_1:custom_function_result.data.*.output_source_ip`
   instead of touching the raw alert text.

3. End-to-end ingestion - call `ingest_waf_alert(raw_text)` to create a SOAR
   container/artifact with these CEF fields already populated (reuses the
   SoarClient from splunk_soar_incident_ingest.py).

Configuration for ingestion is via environment variables:
  SOAR_BASE_URL      e.g. https://soar.example.com
  SOAR_AUTH_TOKEN    ph-auth-token for a SOAR automation user
  SOAR_VERIFY_SSL    "true"/"false" (default: true)
"""

import hashlib
import json
import os
import re
from typing import Any, Dict, Optional

try:
    import phantom.rules as phantom  # available only inside SOAR's playbook runtime
except ImportError:
    phantom = None

from splunk_soar_incident_ingest import SoarClient


def refang(text: str) -> str:
    """Undo common IOC defanging: [.] -> ., [:] -> :, hXXp -> http, [at] -> @."""
    if not text:
        return text
    text = re.sub(r"\[\.\]", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    text = re.sub(r"(?i)h[x]{2}p", "http", text)
    text = re.sub(r"(?i)\[at\]", "@", text)
    return text


def clean_narrative(raw_text: str) -> str:
    """Refang + strip markdown artifacts (escaped bullets, hard line-breaks, extra blank lines)."""
    text = refang(raw_text)
    text = re.sub(r"\\-", "-", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


_FIELD_PATTERNS = {
    "use_case": r"UC\s*:\s*\n\s*([^\n]+)",
    "incident_overview": r"Incident Overview\s*:\s*(.*?)\n\s*\n",
    "source_ip": r"^Source IP\s*:\s*(.+)$",
    "destination_ip": r"^Destination\s*:\s*(.+)$",
    "destination_port": r"^Destination Port\s*:\s*(.+)$",
    "destination_host": r"^Destination Host\s*:\s*(.+)$",
    "url": r"^URL\s*:\s*(.+)$",
    "method": r"^Method\s*:\s*(.+)$",
    "request_status": r"^Request Status\s*:\s*(.+)$",
    "response_code": r"^Response Code\s*:\s*(.+)$",
    "uploaded_file": r"^Uploaded PDF\s*:\s*(.+)$",
    "file_creator": r"^Creator\s*:\s*(.+)$",
    "file_producer": r"^Producer\s*:\s*(.+)$",
    "file_author": r"^Author\s*:\s*(.+)$",
}


def parse_waf_alert(raw_text: str) -> Dict[str, Optional[str]]:
    """Extract structured fields from the alert text (already refanged internally)."""
    text = refang(raw_text or "")
    fields: Dict[str, Optional[str]] = {}
    for key, pattern in _FIELD_PATTERNS.items():
        flags = re.MULTILINE | (re.DOTALL if key == "incident_overview" else 0)
        match = re.search(pattern, text, flags)
        fields[key] = re.sub(r"\s+", " ", match.group(1)).strip() if match else None
    return fields


def build_cef_fields(raw_text: str) -> Dict[str, Any]:
    """Build the clean CEF dict a SOAR artifact/playbook should consume."""
    fields = parse_waf_alert(raw_text)
    narrative = clean_narrative(raw_text)

    use_case = fields.get("use_case") or "WAF Critical/High Allowed Event"
    source_ip = fields.get("source_ip")
    description = fields.get("incident_overview") or f"WAF alert {use_case} from source {source_ip}"

    cef: Dict[str, Any] = {
        "useCase": use_case,
        "sourceAddress": source_ip,
        "destinationAddress": fields.get("destination_ip"),
        "destinationPort": fields.get("destination_port"),
        "destinationHostName": fields.get("destination_host"),
        "requestUrl": fields.get("url"),
        "requestMethod": fields.get("method"),
        "requestStatus": fields.get("request_status"),
        "responseCode": fields.get("response_code"),
        "fileName": fields.get("uploaded_file"),
        "fileCreator": fields.get("file_creator"),
        "fileProducer": fields.get("file_producer"),
        "fileAuthor": fields.get("file_author"),
        "Description": description,
        "Detailed_Decription": narrative,
    }
    return cef


def _source_data_identifier(cef: Dict[str, Any]) -> str:
    basis = "|".join(str(cef.get(k) or "") for k in ("useCase", "sourceAddress", "destinationHostName", "requestUrl"))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def ingest_waf_alert(
    raw_text: str,
    base_url: Optional[str] = None,
    auth_token: Optional[str] = None,
    verify_ssl: bool = True,
) -> int:
    """Create/update a SOAR container+artifact populated with the parsed CEF fields."""
    base_url = base_url or os.environ["SOAR_BASE_URL"]
    auth_token = auth_token or os.environ["SOAR_AUTH_TOKEN"]
    client = SoarClient(base_url=base_url, auth_token=auth_token, verify_ssl=verify_ssl)

    cef = build_cef_fields(raw_text)
    source_data_identifier = _source_data_identifier(cef)

    container_id = client.find_container_by_sdi(source_data_identifier)
    if container_id is None:
        container_id = client.create_container(
            name=f"{cef['useCase']} - {cef['sourceAddress']}",
            description=cef["Description"],
            label="events",
            severity="medium",
            source_data_identifier=source_data_identifier,
        )

    client.add_artifact(
        container_id=container_id,
        cef=cef,
        name=cef["useCase"],
        label="event",
        severity="medium",
        source_data_identifier=source_data_identifier,
        cef_types={
            "sourceAddress": ["ip"],
            "destinationAddress": ["ip"],
            "destinationHostName": ["host name"],
            "fileName": ["file name"],
        },
        run_automation=True,
    )
    return container_id


def custom_function(container=None, raw_alert_text=None, **kwargs):
    """
    SOAR Custom Function block entry point.

    Block setup:
      Input parameters  : raw_alert_text (string)
      Output parameters : output_use_case, output_source_ip, output_destination_ip,
                           output_destination_port, output_destination_host, output_url,
                           output_method, output_request_status, output_response_code,
                           output_file_name, output_file_creator, output_file_producer,
                           output_file_author, output_description,
                           output_detailed_description, output_cef_json
    """
    if phantom:
        phantom.debug("waf_alert_text_parser custom_function() called")

    cef = build_cef_fields(raw_alert_text or "")

    outputs = {
        "output_use_case": cef.get("useCase"),
        "output_source_ip": cef.get("sourceAddress"),
        "output_destination_ip": cef.get("destinationAddress"),
        "output_destination_port": cef.get("destinationPort"),
        "output_destination_host": cef.get("destinationHostName"),
        "output_url": cef.get("requestUrl"),
        "output_method": cef.get("requestMethod"),
        "output_request_status": cef.get("requestStatus"),
        "output_response_code": cef.get("responseCode"),
        "output_file_name": cef.get("fileName"),
        "output_file_creator": cef.get("fileCreator"),
        "output_file_producer": cef.get("fileProducer"),
        "output_file_author": cef.get("fileAuthor"),
        "output_description": cef.get("Description"),
        "output_detailed_description": cef.get("Detailed_Decription"),
        "output_cef_json": json.dumps(cef),
    }

    if phantom:
        phantom.custom_function.set_output(**outputs)

    return outputs


SAMPLE_ALERT_TEXT = """Hi Team,

SOC has observed an alert for the UC :
9725_waf_critical_or_high_allowed_events_detected

Details :

Incident Overview : An hXXp POST request was initiated from public IP
94[.]204[.]125[.]24 (AE) against abc[.]def[.]ghi[.]ae. The request involved
the upload of a PDF document.

Source IP : 94[.]204[.]125[.]24
Destination : 1[.]2[.]3[.]4
Destination Port : 443
Destination Host : a[.]b[.]c[.]d
URL : /en/file-upload

Method : POST
Request Status : passed
Response Code : 200

Uploaded PDF : URBAN OAK FURNITURE TRADING - L[.]L[.]C - S[.]P[.]C (2).pdf
Creator : Oracle12c AS Reports Services
Producer : Oracle PDF Driver
Author : Oracle Reports

\\- The PDF appears to be a business document associated with a certificate
request process.
\\- The uploaded PDF contains text patterns that matched staged ASM signatures,
which might have triggered the alert.
\\- Verification of WAF logs for the past 24 hours identified additional staged
signature matches against the uploaded PDF content, including signatures
related to:
SQL Injection expressions
Windows PowerShell execution patterns
Unix special variable patterns
Other generic attack detection signatures

\\- Subsequent user activity from the same session included:
Upload of Memorandum of Association (MOA) documents.
Submission of a TRC certificate request through /en/certificate-
requests/treaty/juridical.
"""


if __name__ == "__main__":
    cef_fields = build_cef_fields(SAMPLE_ALERT_TEXT)
    print(json.dumps(cef_fields, indent=2))

    if os.environ.get("SOAR_BASE_URL") and os.environ.get("SOAR_AUTH_TOKEN"):
        created_container_id = ingest_waf_alert(SAMPLE_ALERT_TEXT)
        print(f"Ingested into SOAR container_id={created_container_id}")
