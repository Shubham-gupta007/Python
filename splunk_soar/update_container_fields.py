#!/usr/bin/env python3
"""
Splunk SOAR Utility (Custom Function) - Update Container Custom Fields

Takes whatever field values are available from upstream blocks (a BMC
ticket ID, a resolution note, a resolution comment) and pushes only
the ones that actually have a value into the container's custom
fields via the container automation API (phantom.update()) - the
built-in "Update Container" utility block's input_json is skipped
entirely in favor of doing the update directly in code, so the "only
update fields that have a value" rule is explicit and testable rather
than something the JSON template has to get right.

Rule: a field with no value (None, missing, or blank/whitespace-only
string) is left out of the update entirely - it is NOT sent as an
empty string, so it never overwrites/blanks a value the container
already has. Only fields that actually contain a value get updated.

Everything lives inside update_container_fields() itself - this whole
file is exactly what you paste into the Custom Function code editor.
Rename `update_container_fields` to match whatever name you give the
custom function in the UI - SOAR derives the def name from that.

Wiring in the Playbook Editor:

    1. Input parameters:
         bmc_ticket_id (string)     - e.g. from a BMC create-ticket action
         resolution_note (string)   - e.g. from a prior custom function/block
         resolution_comment (string)
         container (container)      - reserved name, SOAR auto-injects the
                                       running container dict, nothing to wire
    2. Output parameters: success (boolean), message (string),
       updated_fields (string)
    3. Wire each input straight to whatever upstream block produced it.
       Leave an input unwired only if that field genuinely never
       applies for this playbook.
"""


def update_container_fields(
    bmc_ticket_id=None,
    resolution_note=None,
    resolution_comment=None,
    container=None,
    **kwargs,
):
    """
    Args:
        bmc_ticket_id (CEF type: string)
        resolution_note (CEF type: string)
        resolution_comment (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: boolean)
        message (CEF type: string)
        updated_fields (CEF type: string)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    outputs = {}

    # Write your custom code here...
    candidate_fields = {
        "bmc_ticket_id": bmc_ticket_id,
        "resolution_note": resolution_note,
        "resolution_comment": resolution_comment,
    }

    # Only fields that actually contain a value get sent in the
    # update - a None/missing/blank value is skipped, not overwritten
    # as empty.
    custom_fields = {
        field_name: field_value.strip()
        for field_name, field_value in candidate_fields.items()
        if isinstance(field_value, str) and field_value.strip()
    }

    outputs["updated_fields"] = ", ".join(sorted(custom_fields))
    outputs["success"] = False
    outputs["message"] = ""

    if not custom_fields:
        outputs["message"] = "No field values were provided - nothing to update."
        phantom.debug(f"update_container_fields: {outputs['message']}")
        assert json.dumps(outputs)
        return outputs

    if not container or not container.get("id"):
        outputs["message"] = "No container id available - cannot update."
        phantom.debug(f"update_container_fields: {outputs['message']}")
        assert json.dumps(outputs)
        return outputs

    success, message = phantom.update({"id": container["id"]}, {"custom_fields": custom_fields})

    outputs["success"] = success
    outputs["message"] = message
    phantom.debug(
        f"update_container_fields: container={container['id']} "
        f"fields={list(custom_fields)} -> success={success} message={message}"
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

    fake_container = {"id": 1234}

    samples = [
        # All three fields available.
        {"bmc_ticket_id": "INC0012345", "resolution_note": "Blocked at firewall", "resolution_comment": "Closed"},
        # Only the ticket id is available - notes stay untouched.
        {"bmc_ticket_id": "INC0099999", "resolution_note": None, "resolution_comment": ""},
        # Nothing available at all.
        {"bmc_ticket_id": None, "resolution_note": "   ", "resolution_comment": None},
    ]

    for sample in samples:
        result = update_container_fields(container=fake_container, **sample)
        print(sample, "->", result)
        print()
