#!/usr/bin/env python3
"""
Splunk SOAR Utility (Custom Function) - Update BMC Ticket ID

Pushes bmc_ticket_id into the container's custom fields via the
container automation API (phantom.update()), but only when
bmc_ticket_id actually has a value - a missing/empty value is left
alone rather than being pushed as blank, so it never overwrites a
ticket ID the container already has.

Everything lives inside update_bmc_ticket_id() itself - this whole
file is exactly what you paste into the Custom Function code editor.
"""


def update_bmc_ticket_id(bmc_ticket_id=None, container=None, **kwargs):
    """
    Args:
        bmc_ticket_id (CEF type: string)
        container (CEF type: phantom container id)

    Returns a JSON-serializable object that implements the configured data paths:
        success (CEF type: string)
        message (CEF type: string)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    outputs = {}

    # Write your custom code here...
    if isinstance(bmc_ticket_id, str) and bmc_ticket_id.strip():
        update = {"custom_fields": {"bmc_ticket_id": bmc_ticket_id.strip()}}
        success, message = phantom.update({"id": container["id"]}, update)
    else:
        success = False
        message = "bmc_ticket_id has no value - nothing to update."

    outputs["success"] = success
    outputs["message"] = message
    phantom.debug(
        f"update_bmc_ticket_id: container={container['id']} -> "
        f"success={success} message={message}"
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

    for sample_ticket_id in ["INC0012345", None, "   "]:
        result = update_bmc_ticket_id(bmc_ticket_id=sample_ticket_id, container=fake_container)
        print(repr(sample_ticket_id), "->", result)
