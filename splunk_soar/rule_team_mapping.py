#!/usr/bin/env python3
"""
Splunk SOAR Utility (Custom Function) - Rule Name to Team Mapping

Takes the name of a triggered detection rule (e.g. "WAF - Block SQLi",
"Linux - Suspicious Cron Job", "Windows - Failed Logon Spike") and
figures out which team - and which assigned group - should own the
resulting case, so a playbook can route/assign it without a big chain
of Decision blocks.

Matching is keyword-based and case-insensitive: the rule name just
needs to CONTAIN one of the known keywords anywhere in it, since real
rule names rarely match a team name exactly.

Everything lives inside rule_team_mapping() itself - this whole file
is exactly what you paste into the Custom Function code editor.
Rename `rule_team_mapping` to match whatever name you give the custom
function in the UI - SOAR derives the def name from that.
"""


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

    # Team -> keywords that identify it in a rule name. Add new rule
    # keywords here as new detection rules come online.
    team_keywords = {
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
    default_team = "Unassigned"

    # Team -> assigned group. A team not listed here (Computer,
    # Windows, Unassigned) gets an empty assigned_group until its
    # group is added below.
    team_assigned_group = {
        "Network": "Managed Service",
        "Information Security": "Security",
    }

    outputs["team_name"] = default_team
    outputs["matched_keyword"] = ""
    outputs["assigned_group"] = ""
    outputs["error"] = ""

    if not isinstance(rule_name, str) or not rule_name.strip():
        outputs["error"] = "rule_name is missing or empty."
        phantom.debug(f"rule_team_mapping: error - {outputs['error']}")
    else:
        # Flatten to keyword -> team, longest keyword first so a more
        # specific match (e.g. "active directory") wins over a
        # shorter, looser one (e.g. "ad ").
        keyword_to_team = {
            keyword: team
            for team, keywords in team_keywords.items()
            for keyword in keywords
        }
        keywords_by_length = sorted(keyword_to_team, key=len, reverse=True)

        name = rule_name.lower()
        for keyword in keywords_by_length:
            if keyword in name:
                outputs["team_name"] = keyword_to_team[keyword]
                outputs["matched_keyword"] = keyword
                break

        outputs["assigned_group"] = team_assigned_group.get(outputs["team_name"], "")

        phantom.debug(
            f"rule_team_mapping: rule_name='{rule_name}' -> "
            f"team='{outputs['team_name']}' matched_keyword='{outputs['matched_keyword']}' "
            f"assigned_group='{outputs['assigned_group']}'"
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
