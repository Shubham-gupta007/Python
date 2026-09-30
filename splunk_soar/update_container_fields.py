#!/usr/bin/env python3
"""
Splunk SOAR Utility (Custom Function) - Update Container Custom Fields

Takes whatever field values are available from upstream blocks (a BMC
ticket ID, a resolution note, a resolution type, a confirmed-incident
flag) and pushes them into the container's custom fields via the
container automation API (phantom.update()).

Two different rules apply depending on the field:

    - bmc_ticket_id / resolution_note: skipped entirely when they have
      no value (None, missing, or blank/whitespace-only). They are
      NEVER sent as an empty string, so a missing upstream value can
      never overwrite/blank a value the container already has.

    - resolution_type / confirmed_incident: these are required BMC
      picklists, so a missing value falls back to a safe default
      ("False Positive" / "No" respectively) instead of being skipped
      - see FIELD_DEFAULTS below.

Everything lives inside update_container_fields() itself - this whole
file is exactly what you paste into the Custom Function code editor.
The if __name__ == "__main__" block at the bottom is ONLY for local
testing on this machine - it is never pasted into SOAR.

Wiring in the Playbook Editor:

    1. Input parameters:
         bmc_ticket_id (string)        - e.g. from a BMC create-ticket action
         resolution_note (string)      - free text
         resolution_type (string)      - True Positive / False Positive /
                                          Indeterminate / Maintenance / Non-Issue
         confirmed_incident (string)   - Yes / No / Unknown
         container_id (phantom container id) - reserved data type, SOAR
                                          auto-injects it, nothing to wire
    2. Output parameters: success (boolean), message (string)
    3. Wire each input straight to whatever upstream block produced it.
       Leave an input unwired only if that field genuinely never
       applies for this playbook - resolution_type/confirmed_incident
       will still get their default value even then.
"""


def update_container_fields(
    bmc_ticket_id=None,
    resolution_note=None,
    resolution_type=None,
    confirmed_incident=None,
    container_id=None,
    **kwargs,
):
    """
    Args:
        bmc_ticket_id (CEF type: string)
        resolution_note (CEF type: string)
        resolution_type (CEF type: string)
        confirmed_incident (CEF type: string)
        container_id (CEF type: phantom container id)

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean)
        message (CEF type: string)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    outputs = {}
    outputs["success"] = False
    outputs["message"] = ""

    container_id = container_id[0] if isinstance(container_id, list) and container_id else container_id
    phantom.debug(f"BMC Ticket ID container_id found: {container_id}")

    # Fields listed here fall back to this value when nothing was
    # provided, instead of being skipped - both are required BMC
    # picklists so they can never be left unset.
    field_defaults = {
        "Resolution Type": "False Positive",
        "Confirmed Incident": "No",
    }

    candidate_fields = {
        "BMC Ticket ID": bmc_ticket_id,
        "Resolution Note": resolution_note,
        "Resolution Type": resolution_type,
        "Confirmed Incident": confirmed_incident,
    }

    phantom.debug(f"INPUT candidate_fields = {candidate_fields}")

    custom_fields = {}

    for field_name, field_value in candidate_fields.items():
        phantom.debug(
            f"Processing field={field_name}, "
            f"value={field_value}, "
            f"type={type(field_value)}"
        )

        if isinstance(field_value, str):
            value = field_value.strip()
        elif isinstance(field_value, list) and field_value:
            value = (
                field_value[0].strip()
                if isinstance(field_value[0], str)
                else None
            )
        else:
            value = None

        if not value and field_name in field_defaults:
            value = field_defaults[field_name]

        if value:
            custom_fields[field_name] = value

    phantom.debug(f"FINAL custom_fields = {custom_fields}")

    if not custom_fields:
        outputs["message"] = "No field values were provided - nothing to update."
    elif not container_id:
        outputs["message"] = "No container id available - cannot update."
    else:
        success, message = phantom.update(
            {"id": container_id},
            {"custom_fields": custom_fields}
        )

        outputs["success"] = success
        outputs["message"] = message
        phantom.debug(
            f"phantom.update: success={success}, message={message}"
        )

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    ############################ Custom Code Goes Above This Line #################################


if __name__ == "__main__":
    # phantom.rules only exists inside SOAR - stub it out here so this
    # file can still be smoke-tested locally the same way SOAR calls it.
    import sys
    import types

    def _fake_update(container_ref, update):
        print(f"[phantom.update] container={container_ref} update={update}")
        return True, "ok"

    phantom_pkg = types.ModuleType("phantom")
    phantom_rules_mod = types.ModuleType("phantom.rules")
    phantom_rules_mod.debug = lambda message: print("[phantom.debug]", message)
    phantom_rules_mod.update = _fake_update
    phantom_pkg.rules = phantom_rules_mod
    sys.modules["phantom"] = phantom_pkg
    sys.modules["phantom.rules"] = phantom_rules_mod

    samples = [
        # Everything provided explicitly.
        {
            "bmc_ticket_id": "INC0012345",
            "resolution_note": "Blocked at firewall",
            "resolution_type": "True Positive",
            "confirmed_incident": "Yes",
        },
        # resolution_type/confirmed_incident missing -> defaults kick in;
        # resolution_note missing -> stays out of the update entirely.
        {
            "bmc_ticket_id": "INC0099999",
            "resolution_note": None,
            "resolution_type": None,
            "confirmed_incident": None,
        },
        # Nothing at all -> defaults still populate the two required
        # picklists, so the update still goes through.
        {
            "bmc_ticket_id": None,
            "resolution_note": "   ",
            "resolution_type": "",
            "confirmed_incident": "",
        },
    ]

    for sample in samples:
        result = update_container_fields(container_id=1234, **sample)
        print(sample, "->", result)
        print()
