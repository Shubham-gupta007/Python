#!/usr/bin/env python3
"""
Splunk SOAR Utility (Custom Function) - Rule Name to Team Mapping

Takes the name of a triggered detection rule (e.g. "WAF - Block SQLi",
"Linux - Suspicious Cron Job", "Windows - Failed Logon Spike") and
figures out which team should own the resulting case, so a playbook
can route/assign it without a big chain of Decision blocks.

Matching is keyword-based and case-insensitive: the rule name just
needs to CONTAIN one of the known keywords anywhere in it, since real
rule names rarely match a team name exactly.

rule_team_mapping() below is written in the exact shape SOAR generates
for a Utility custom function block (a plain function that takes its
Input Parameters as keyword arguments and returns a dict whose keys
are the Output Parameter names) - see the bottom of this file / the
chat explanation for the step-by-step of wiring it up in the UI.
"""

# ============================================================
# TEAM -> KEYWORDS MAPPING
#
# Add new rule keywords here as new detection rules come online -
# no other code needs to change.
# ============================================================

TEAM_KEYWORDS = {
    "Network": ["waf", "firewall", "ids", "ips", "network"],
    "Computer": ["linux", "unix", "endpoint", "server"],
    "Windows": ["windows", "win", "active directory", "ad "],
    "Information Security": [
        "information security",
        "infosec",
        "malware",
        "phishing",
        "threat intel",
        "vulnerability",
    ],
}

DEFAULT_TEAM = "Unassigned"

# ============================================================
# TEAM -> ASSIGNED GROUP MAPPING
#
# A team not listed here (e.g. Computer, Windows, Unassigned) gets an
# empty assigned_group until its group is added below.
# ============================================================

TEAM_ASSIGNED_GROUP = {
    "Network": "Managed Service",
    "Information Security": "Security",
}

# Flatten to keyword -> team, longest keyword first so a more specific
# match (e.g. "active directory") wins over a shorter, looser one.
_KEYWORD_TO_TEAM = {
    keyword: team for team, keywords in TEAM_KEYWORDS.items() for keyword in keywords
}
_KEYWORDS_BY_LENGTH = sorted(_KEYWORD_TO_TEAM, key=len, reverse=True)


def get_team_for_rule(rule_name):
    """Pure lookup logic, kept separate so it's unit-testable outside SOAR."""
    if not isinstance(rule_name, str) or not rule_name.strip():
        raise ValueError("rule_name is missing or empty.")

    name = rule_name.lower()

    for keyword in _KEYWORDS_BY_LENGTH:
        if keyword in name:
            return _KEYWORD_TO_TEAM[keyword], keyword

    return DEFAULT_TEAM, ""


def get_assigned_group(team_name):
    return TEAM_ASSIGNED_GROUP.get(team_name, "")


# ============================================================
# SOAR UTILITY FUNCTION ENTRY POINT
#
# This is the part you paste into the Custom Function code editor.
# Rename `rule_team_mapping` to match whatever name you give the
# custom function in the UI - SOAR derives the def name from that.
# ============================================================

def rule_team_mapping(rule_name=None, **kwargs):
    """
    Args:
        rule_name (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        team_name (CEF type: string)
        matched_keyword (CEF type: string)
        assigned_group (CEF type: string)
        error (CEF type: string)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    outputs = {}

    # Write your custom code here...
    outputs["team_name"] = DEFAULT_TEAM
    outputs["matched_keyword"] = ""
    outputs["assigned_group"] = ""
    outputs["error"] = ""

    try:
        team_name, matched_keyword = get_team_for_rule(rule_name)
        outputs["team_name"] = team_name
        outputs["matched_keyword"] = matched_keyword
        outputs["assigned_group"] = get_assigned_group(team_name)
        phantom.debug(
            f"rule_team_mapping: rule_name='{rule_name}' -> "
            f"team='{team_name}' matched_keyword='{matched_keyword}' "
            f"assigned_group='{outputs['assigned_group']}'"
        )
    except ValueError as error:
        outputs["error"] = str(error)
        phantom.debug(f"rule_team_mapping: error - {error}")

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

    samples = [
        "WAF - Block SQL Injection Attempt",
        "Linux - Suspicious Cron Job Created",
        "Windows - Failed Logon Spike",
        "Active Directory - Kerberoasting Detected",
        "Malware - Ransomware Behavior Detected",
        "Phishing - Suspicious Email Reported",
        "Unknown Rule - No Keyword Match",
        "",
    ]

    for rule_name in samples:
        print(rule_name, "->", rule_team_mapping(rule_name))
