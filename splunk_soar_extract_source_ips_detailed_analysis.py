"""
Splunk SOAR "Custom Functions" library entry (Administration > Custom
Functions > New Custom Function - the /custom_function/ editor, named
input-parameter signature with **kwargs, matching the "rule_team_mapping"
style stub).

Generic source-IP extractor: pulls attacker/source IPs out of the
"Detailed analysis" section of an alert, and ONLY that section -
Recommendations / Description / Logs are never scanned, even if the whole
combined alert text gets passed in by mistake.

Works across alert templates (not hardcoded to one wording) by recognizing
several common source-IP label shapes:
  - "Source IP :", "Source IPs :", "Source IPs Observed :"
  - "Attacker IP(s) :", "Malicious IP(s) :"
  - a bare "IP :" heading (used by some templates to list each source IP's
    reputation one at a time, e.g. "IP: \\n1.2.3.4 ISP: ...")
and both layouts: IP(s) inline on the label line, or one IP per line
immediately following the label (optionally with trailing "(Geo: XX)" /
"ISP: ..." text).

Editor setup (left panel):
  Name              : extract_source_ips (or any name you like)
  Add Input         : Name = detailed_analysis   | Data Type = string
                       (wire this from the "Detailed analysis" section of
                       the alert/CEF field - passing the whole alert text
                       is also safe, see above)
  Add Output (List) : Name = source_ips       | Data Type = string
  Add Output (Item) : Name = source_ip_csv    | Data Type = string
  Add Output (Item) : Name = source_ip_count  | Data Type = numeric

Remove this function's leftover team_name / matched_keyword / error
outputs (from whichever template this was duplicated from) and add the
three above instead.
"""

import json
import re

IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"

_SOURCE_LABEL = re.compile(
    r"(?<![A-Za-z])(?:Source\s+IPs?(?:\s+Observed)?|Attacker\s+IPs?|Malicious\s+IPs?|IP)\s*:",
    re.IGNORECASE,
)
_DETAILED_ANALYSIS_HEADER = re.compile(r"Detailed\s+analysis\s*:", re.IGNORECASE)
_NEXT_SECTION_BOUNDARY = re.compile(
    r"\*{5,}|^\s*(?:Recommendations|Description|Logs)\s*:", re.MULTILINE | re.IGNORECASE
)


def refang(text: str) -> str:
    if not text:
        return text
    text = re.sub(r"\[\.\]", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    return text


def isolate_detailed_analysis(text: str) -> str:
    """Keep only the 'Detailed analysis' section, trimming off any later sections."""
    header_match = _DETAILED_ANALYSIS_HEADER.search(text)
    if header_match:
        text = text[header_match.end():]
    boundary_match = _NEXT_SECTION_BOUNDARY.search(text)
    if boundary_match:
        text = text[: boundary_match.start()]
    return text


def extract_source_ips_list(detailed_analysis_text: str):
    """Pure function: deduped, order-preserving list of source IPs."""
    text = isolate_detailed_analysis(refang(detailed_analysis_text or ""))

    source_ips = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        label_match = _SOURCE_LABEL.search(line)
        if label_match:
            # IPs after the label, on the same physical line (anything before
            # the label on that line - e.g. a preceding Affected Backend
            # value sharing the line - is correctly left out).
            same_line_tail = line[label_match.end():]
            for ip in re.findall(IPV4, same_line_tail):
                if ip not in source_ips:
                    source_ips.append(ip)
            j = i + 1
            while j < len(lines):
                ip_match = re.match(rf"^({IPV4})\b", lines[j].strip())
                if not ip_match:
                    break
                if ip_match.group(1) not in source_ips:
                    source_ips.append(ip_match.group(1))
                j += 1
            i = j
            continue
        i += 1

    return source_ips


def extract_source_ips(detailed_analysis=None, **kwargs):
    """
    Args:
        detailed_analysis (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        source_ips (CEF type: string)
        source_ip_csv (CEF type: string)
        source_ip_count (CEF type: string)
    """

    ################################################################################
    ## Custom Code Goes Below This Line
    ################################################################################

    outputs = {}

    source_ips = extract_source_ips_list(detailed_analysis)

    outputs["source_ips"] = source_ips
    outputs["source_ip_csv"] = ",".join(source_ips)
    outputs["source_ip_count"] = len(source_ips)

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    ################################################################################
    ## Custom Code Goes Above This Line
    ################################################################################


if __name__ == "__main__":
    # Case 1: just the "Detailed analysis" section (block-style "Source IPs Observed")
    detailed_analysis_only = """Hello Team, CPX SOC has observed an alert. Target Application: trc.tax.gov.ae Affected Backend:
172.27.7.91 Source IPs Observed:
172.239.117.101 (Geo: GB)
172.237.109.192 (Geo: GB)
34.68.34.65 (Geo: US)
34.68.34.72 (Geo: US)
8.34.210.56 (Geo: US) Executive Summary ...
IP:
172.239.117.101 ISP: Linode
IP:
34.68.34.65 ISP: Mandiant, Inc.
"""
    result1 = extract_source_ips(detailed_analysis=detailed_analysis_only)
    print("Case 1 (Detailed analysis only):")
    print(json.dumps(result1, indent=2))
    assert "172.27.7.91" not in result1["source_ips"]
    assert result1["source_ip_count"] == 5

    # Case 2: whole combined alert (Detailed analysis + Recommendations + Description + Logs)
    # passed in by mistake - the Description/Logs sections' ip_client=/dest_ip= values
    # must NOT leak in.
    whole_alert = (
        "Detailed analysis: - \"" + detailed_analysis_only + "\"\n"
        "****************************************************************************\n"
        "Recommendations: - \"Block 9.9.9.9 if confirmed malicious.\"\n"
        "****************************************************************************\n"
        "Description: - \"ip_client=\\\"172[.]237[.]109[.]192\\\", dest_ip=\\\"172[.]27[.]7[.]91\\\"\"\n"
        "****************************************************************************\n"
        "Logs: - \"X-Forwarded-For: 34[.]68[.]34[.]65\"\n"
    )
    result2 = extract_source_ips(detailed_analysis=whole_alert)
    print("\nCase 2 (whole alert passed in - Recommendations/Description/Logs must be ignored):")
    print(json.dumps(result2, indent=2))
    assert "9.9.9.9" not in result2["source_ips"], "Recommendations section leaked in!"
    assert result2["source_ip_count"] == 5, "Description/Logs sections leaked extra IPs in!"

    # Case 3: older simple single-line format, no "Detailed analysis" header at all
    simple_alert = "Source IP : 94.204.125.24\nDestination : 1.2.3.4\n"
    result3 = extract_source_ips(detailed_analysis=simple_alert)
    print("\nCase 3 (simple single-line format, generic across templates):")
    print(json.dumps(result3, indent=2))
    assert result3["source_ips"] == ["94.204.125.24"]

    print("\nAll cases passed.")
