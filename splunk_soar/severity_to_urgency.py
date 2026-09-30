#!/usr/bin/env python3
"""
Splunk SOAR Utility (Custom Function) - Severity to BMC Urgency Mapping

Takes whatever severity label the triggering source used (e.g. "High",
"critical", "Low") and maps it to the exact BMC Urgency dropdown value
("1-Critical", "2-High", "3-Medium", "4-Low") so a playbook can fill
that required field on ticket creation without a chain of Decision
blocks.

Matching is exact (after trimming/lowercasing), not substring - unlike
rule_team_mapping, a severity value is a clean enum from the source
tool, not a free-text rule name, so exact matching avoids something
like "Not High Priority" accidentally matching "high".

Urgency is a required BMC field, so an unrecognized severity still
gets a safe default ("3-Medium") rather than being left blank - but
`matched`/`error` tell you when that happened so you can branch on it
(e.g. route to an analyst for review instead of silently ticketing
everything as Medium).

Everything lives inside severity_to_urgency() itself - this whole
file is exactly what you paste into the Custom Function code editor.
The if __name__ == "__main__" block at the bottom is ONLY for local
testing on this machine (`python3 splunk_soar/severity_to_urgency.py`)
- it is never pasted into SOAR.

Wiring in the Playbook Editor:

    1. Input parameters: severity (string)
    2. Output parameters: urgency (string), matched (boolean), error (string)
    3. Wire severity to whatever upstream block/artifact field carries
       the source tool's severity label.
    4. Wire urgency to the ticket-creation block's Urgency field.
"""


def severity_to_urgency(severity=None, **kwargs):
    """
    Args:
        severity (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        urgency (CEF type: string)
        matched (CEF type: boolean)
        error (CEF type: string)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    outputs = {}

    # Add/adjust aliases here as new source tools send different labels.
    severity_to_urgency_map = {
        "critical": "1-Critical",
        "high": "2-High",
        "medium": "3-Medium",
        "moderate": "3-Medium",
        "low": "4-Low",
        "minor": "4-Low",
    }
    default_urgency = "3-Medium"

    key = severity.strip().lower() if isinstance(severity, str) else ""
    urgency = severity_to_urgency_map.get(key)

    outputs["matched"] = urgency is not None
    outputs["urgency"] = urgency or default_urgency
    outputs["error"] = (
        ""
        if urgency
        else f"Unrecognized severity '{severity}' - defaulted to {default_urgency}."
    )

    phantom.debug(
        f"severity_to_urgency: severity='{severity}' -> "
        f"urgency='{outputs['urgency']}' matched={outputs['matched']}"
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

    phantom_pkg = types.ModuleType("phantom")
    phantom_rules_mod = types.ModuleType("phantom.rules")
    phantom_rules_mod.debug = lambda message: print("[phantom.debug]", message)
    phantom_pkg.rules = phantom_rules_mod
    sys.modules["phantom"] = phantom_pkg
    sys.modules["phantom.rules"] = phantom_rules_mod

    samples = ["High", "critical", " Low ", "Medium", "Moderate", "Unknown", None, ""]

    for severity in samples:
        print(repr(severity), "->", severity_to_urgency(severity))
