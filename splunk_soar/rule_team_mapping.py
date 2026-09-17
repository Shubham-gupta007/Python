#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Rule Name to Team Mapping

Takes the name of a triggered detection rule (e.g. "WAF - Block SQLi",
"Linux - Suspicious Cron Job", "Windows - Failed Logon Spike") and
figures out which team should own the resulting case, so a playbook
can route/assign it without a big chain of Decision blocks.

Matching is keyword-based and case-insensitive: the rule name just
needs to CONTAIN one of the known keywords anywhere in it, since real
rule names rarely match a team name exactly.

How to paste into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function.
    2. Input parameter: rule_name (string)
    3. Output parameters: team_name (string), matched_keyword (string),
       error (string)
    4. Paste the body of rule_team_mapping_custom_function() into the
       generated stub.
    5. Put an Assign Ownership / Set Owner block after this one, wired
       to the team_name output.
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
}

DEFAULT_TEAM = "Unassigned"

# Flatten to keyword -> team, longest keyword first so a more specific
# match (e.g. "active directory") wins over a shorter, looser one.
_KEYWORD_TO_TEAM = {
    keyword: team for team, keywords in TEAM_KEYWORDS.items() for keyword in keywords
}
_KEYWORDS_BY_LENGTH = sorted(_KEYWORD_TO_TEAM, key=len, reverse=True)


def get_team_for_rule(rule_name):
    if not isinstance(rule_name, str) or not rule_name.strip():
        raise ValueError("rule_name is missing or empty.")

    name = rule_name.lower()

    for keyword in _KEYWORDS_BY_LENGTH:
        if keyword in name:
            return _KEYWORD_TO_TEAM[keyword], keyword

    return DEFAULT_TEAM, ""


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def rule_team_mapping_custom_function(rule_name=None, **kwargs):
    """
    Paste into the SOAR custom function editor.
    Inputs:  rule_name (string)
    Outputs: team_name (string), matched_keyword (string), error (string)
    """
    try:
        team_name, matched_keyword = get_team_for_rule(rule_name)
    except ValueError as error:
        return {"team_name": "", "matched_keyword": "", "error": str(error)}

    return {"team_name": team_name, "matched_keyword": matched_keyword, "error": ""}


if __name__ == "__main__":
    samples = [
        "WAF - Block SQL Injection Attempt",
        "Linux - Suspicious Cron Job Created",
        "Windows - Failed Logon Spike",
        "Active Directory - Kerberoasting Detected",
        "Unknown Rule - No Keyword Match",
    ]

    for rule_name in samples:
        print(rule_name, "->", rule_team_mapping_custom_function(rule_name))
