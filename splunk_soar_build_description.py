"""
Generic Splunk SOAR Custom Function: combine every input you provide into one
formatted description string, so a single output can be wired straight into a
"Description" / "Detailed_Decription" field on a downstream ticket (e.g. BMC
Remedy) without hardcoding or re-listing field names in code.

Block setup:
  Input parameters  : one input per field you want included in the text -
                       any names you like (e.g. use_case, source_ip,
                       destination_ip, url, First_Name, Impact, Urgency,
                       "CRM SR Number", ...). This function does not hardcode
                       any field names, so adding/removing an input parameter
                       on the block automatically adds/removes it from the
                       output text - no code changes needed.
  Output parameters : output_description (string) - all inputs rendered as
                       "Label : value" lines, one per field, empty ones
                       skipped
                       output_cef_json (string) - the same inputs as a JSON
                       object, useful if a later block needs them individually

Optional inputs (do not become part of the description text themselves):
  field_order  : comma-separated string, or list, naming the field order
                 to render in (defaults to the order the inputs were passed)
  field_labels : JSON string, or dict, mapping field name -> display label
                 (defaults to the field name with underscores turned into
                 spaces)
"""

import json
from typing import Any, Dict, List, Optional

try:
    import phantom.rules as phantom  # available only inside SOAR's playbook runtime
except ImportError:
    phantom = None


def _default_label(field_name: str) -> str:
    return field_name.replace("_", " ").strip()


def build_description(
    fields: Dict[str, Any],
    field_labels: Optional[Dict[str, str]] = None,
    order: Optional[List[str]] = None,
) -> str:
    """Render every non-empty field into one "Label : value" text block."""
    field_labels = field_labels or {}
    keys = order if order else list(fields.keys())

    lines = []
    for key in keys:
        value = fields.get(key)
        if value in (None, ""):
            continue
        label = field_labels.get(key, _default_label(key))
        lines.append(f"{label} : {value}")
    return "\n".join(lines)


def custom_function(container=None, field_order=None, field_labels=None, **kwargs):
    """
    SOAR Custom Function entry point.

    Every input parameter you define on the block (other than `container`,
    `field_order`, and `field_labels`) is captured via **kwargs and rendered
    into the output description in the order it was passed.
    """
    if phantom:
        phantom.debug("build_description custom_function() called")

    fields = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    order = None
    if field_order:
        order = [f.strip() for f in field_order.split(",")] if isinstance(field_order, str) else list(field_order)

    labels = None
    if field_labels:
        labels = json.loads(field_labels) if isinstance(field_labels, str) else field_labels

    description = build_description(fields, field_labels=labels, order=order)

    outputs = {
        "output_description": description,
        "output_cef_json": json.dumps(fields),
    }

    if phantom:
        phantom.custom_function.set_output(**outputs)

    return outputs


if __name__ == "__main__":
    # Example 1: the WAF alert fields from splunk_soar_waf_alert_ingest.py
    waf_result = custom_function(
        use_case="9725_waf_critical_or_high_allowed_events_detected",
        source_ip="94.204.125.24",
        destination_ip="1.2.3.4",
        destination_port="443",
        destination_host="a.b.c.d",
        url="/en/file-upload",
        method="POST",
        request_status="passed",
        response_code="200",
    )
    print("WAF example:\n" + waf_result["output_description"] + "\n")

    # Example 2: the BMC Remedy CRM incident fields, with field_order/labels
    # so keys with spaces (which can't be Python keyword arguments) still work
    remedy_fields = {
        "First_Name": "svc",
        "Last_Name": "soaritsmuat",
        "Internet E-mail": "svc.soaritsmuat@tax.gov.ae",
        "Impact": "3-Moderate/Limited",
        "Urgency": "3-Medium",
        "Status": "Assigned",
        "CRM SR Number": "SR_123",
        "z1D_Action": "CREATE",
    }
    remedy_result = custom_function(field_order=list(remedy_fields.keys()), **remedy_fields)
    print("Remedy example:\n" + remedy_result["output_description"])
