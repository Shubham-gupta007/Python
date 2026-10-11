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
several common source-IP label shapes, case-insensitively and with or
without a space before "IP":
  - "Source IP :", "Source IPs :", "Source IPs Observed :"
  - "SourceIP :", "SOURCEIP :", "sourceip :", "Source ips :"
  - "Attacker IP(s) :", "Malicious IP(s) :" (same spacing/casing flexibility)
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

_STRONG_SOURCE_LABEL = re.compile(
    r"(?<![A-Za-z])(?:Source\s*IPs?(?:\s+Observed)?|Attacker\s*IPs?|Malicious\s*IPs?)\s*:",
    re.IGNORECASE,
)
# Bare "IP:" is only a source label when it's the WHOLE thing at the start
# of the line - "Destination IP:", "Dest IP:", "Target IP:", "Affected
# Backend:" etc. must never match this (that was the destination-IP leak).
_BARE_IP_LABEL = re.compile(r"^\s*IP\s*:", re.IGNORECASE)
# Anything labeled as the victim/target side - used as a final exclusion
# filter below, as a safety net on top of _BARE_IP_LABEL being anchored:
# no matter how an IP ends up in the source list, if it's independently
# labeled as a destination/backend anywhere in the text, drop it.
_DEST_LABEL = re.compile(
    r"(?<![A-Za-z])(?:Destination|Dest|Target|Victim)\s*IPs?\s*:"
    r"|(?<![A-Za-z])Affected\s+Backend\s*:"
    r"|(?<![A-Za-z])Backend\s*(?:IPs?)?\s*:"
    r"|(?<![A-Za-z])dest_ip\s*=",
    re.IGNORECASE,
)
_DETAILED_ANALYSIS_HEADER = re.compile(r"Detailed\s+analysis\s*:", re.IGNORECASE)
_NEXT_SECTION_BOUNDARY = re.compile(
    r"\*{5,}|^\s*(?:Recommendations|Description|Logs)\s*:", re.MULTILINE | re.IGNORECASE
)


def as_text(value) -> str:
    """
    Normalize a SOAR datapath value to a plain string.

    A wildcard CEF datapath (e.g. artifact:*.cef.detailed_analysis) hands the
    custom function a LIST of strings, not a plain string, even when only one
    artifact matches - passing that straight to re.sub()/re.search() raises
    "expected string or bytes-like object, got list". Join list/tuple values
    (covers multiple matching artifacts) and stringify anything else.
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "\n".join(as_text(item) for item in value if item)
    return str(value)


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


def _has_any_label(line: str) -> bool:
    return bool(
        _STRONG_SOURCE_LABEL.search(line)
        or _DEST_LABEL.search(line)
        or _BARE_IP_LABEL.match(line)
    )


def _scan_labeled_ips(lines, label_matcher) -> list:
    """
    Shared block scanner: wherever label_matcher(line) matches, collect any
    IPs on the rest of that line, then keep consuming following lines that
    are themselves just "<ip> ..." until one isn't - OR until a continuation
    line, despite starting with an IP, also carries a *different* label
    later on the same line (e.g. "172.27.7.91 Source IPs Observed:" - the
    leading IP belongs to this block, but the trailing label starts a new
    one, so sweeping must stop right there instead of continuing into the
    next block's own IPs).
    """
    found = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        label_match = label_matcher(line)
        if label_match:
            same_line_tail = line[label_match.end():]
            for ip in re.findall(IPV4, same_line_tail):
                if ip not in found:
                    found.append(ip)
            j = i + 1
            while j < len(lines):
                candidate = lines[j].strip()
                ip_match = re.match(rf"^({IPV4})\b", candidate)
                if not ip_match:
                    break
                if ip_match.group(1) not in found:
                    found.append(ip_match.group(1))
                j += 1
                if _has_any_label(candidate[ip_match.end():]):
                    break
            i = j
            continue
        i += 1
    return found


def extract_source_ips_list(detailed_analysis_text) -> list:
    """Pure function: deduped, order-preserving list of source IPs."""
    text = isolate_detailed_analysis(refang(as_text(detailed_analysis_text)))
    lines = text.splitlines()

    source_ips = _scan_labeled_ips(
        lines, lambda line: _STRONG_SOURCE_LABEL.search(line) or _BARE_IP_LABEL.match(line)
    )
    destination_ips = _scan_labeled_ips(lines, _DEST_LABEL.search)

    # Final safety net: no matter how an IP ended up in source_ips (merged
    # label lines, a continuation sweep grabbing a neighboring line, etc.),
    # if it's independently labeled as a destination/backend anywhere in
    # this same text, it must never be treated as a source IP.
    return [ip for ip in source_ips if ip not in destination_ips]


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

    # Case 4: SOAR wildcard-datapath input arrives as a list, not a plain
    # string - must not raise "expected string or bytes-like object, got list"
    result4 = extract_source_ips(detailed_analysis=[detailed_analysis_only])
    print("\nCase 4 (list input, as a wildcard CEF datapath produces):")
    print(json.dumps(result4, indent=2))
    assert result4["source_ip_count"] == 5

    # Case 5: label spacing/casing variants - "SourceIP", "SOURCEIP",
    # "sourceip", "Source ips" must all be recognized, not just "Source IP".
    for label in ("SourceIP", "SOURCEIP", "sourceip", "Source ips", "Source IPs Observed"):
        variant_text = f"{label}: 203.0.113.5, 203.0.113.6\n"
        variant_result = extract_source_ips(detailed_analysis=variant_text)
        assert variant_result["source_ips"] == ["203.0.113.5", "203.0.113.6"], (
            f"label variant {label!r} failed: {variant_result}"
        )
    print("\nCase 5 (label spacing/casing variants - SourceIP/SOURCEIP/sourceip/etc.) passed.")

    # Case 6: destination/backend IPs labeled "<word> IP:" must never leak in -
    # this was the actual bug (bare "IP:" matched anywhere in the line, so
    # "Destination IP:" was wrongly treated as a source label).
    dest_leak_text = (
        "Destination IP: 172.27.7.91\n"
        "Dest IP: 172.27.7.92\n"
        "Target IP: 172.27.7.93\n"
        "Victim IP: 172.27.7.94\n"
        "Affected Backend IP: 172.27.7.95\n"
        "Source IP: 203.0.113.9\n"
        "IP: \n"
        "203.0.113.10 ISP: Example\n"
    )
    result6 = extract_source_ips(detailed_analysis=dest_leak_text)
    print("\nCase 6 (destination-labeled IPs must not leak into source_ips):")
    print(json.dumps(result6, indent=2))
    assert result6["source_ips"] == ["203.0.113.9", "203.0.113.10"], (
        f"destination IP leaked in: {result6}"
    )
    print("\nCase 6 passed - destination IPs correctly excluded.")

    # Case 7: a destination IP with NO label of its own, sitting right after
    # a source block, gets swept in as a false "continuation" line - but it
    # IS independently labeled as a destination elsewhere in the same text,
    # so the exclusion filter must still drop it.
    leak_via_sweep_text = (
        "IP: \n"
        "203.0.113.20 ISP: Example Host\n"
        "172.27.7.91\n"
        "Destination IP: 172.27.7.91\n"
    )
    result7 = extract_source_ips(detailed_analysis=leak_via_sweep_text)
    print("\nCase 7 (unlabeled destination IP right after a source block):")
    print(json.dumps(result7, indent=2))
    assert result7["source_ips"] == ["203.0.113.20"], f"destination IP leaked via sweep: {result7}"
    print("\nCase 7 passed - destination IP excluded via the exclusion filter.")

    print("\nAll cases passed.")
