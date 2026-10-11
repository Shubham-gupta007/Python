"""
Splunk SOAR "Custom Functions" library entry (Administration > Custom
Functions > New Custom Function - the /custom_function/ editor, **kwargs
signature, plain `return outputs` dict).

Extracts the attacker/source IPs from a raw alert or WAF/F5 log dump and
returns them as a clean list, ready to feed into a "List" datapath for
downstream blocks (IP reputation lookups, block actions, artifact CEF
fields, etc.) without hand-parsing the text again.

Deliberately only pulls IPs out of SOURCE-indicating contexts, so it does
NOT pick up the destination/backend IP (dest_ip=, Destination:,
Affected Backend:):
  - "Source IP :" / "Source IPs Observed:" lines
  - ip_client="..." fields (F5 ASM log format)
  - X-Forwarded-For: ... headers / x_forwarded_for_header_value="..."
Handles defanged IOCs (1[.]2[.]3[.]4) by refanging before matching.

Editor setup (left panel):
  Name              : extract_source_ips (or any name you like)
  Add Input         : Name = alert_text   | Data Type = string
  Add Output (List) : Name = source_ips   | Data Type = string
  Add Output (Item) : Name = source_ip_csv    | Data Type = string
  Add Output (Item) : Name = source_ip_count  | Data Type = numeric
"""

import json
import re

IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"

_SOURCE_LINE_PATTERNS = [
    rf'ip_client\s*=\s*"?({IPV4})"?',
    rf'x_forwarded_for_header_value\s*=\s*"?({IPV4})"?',
    rf'X-Forwarded-For:\s*({IPV4})',
    rf'^Source IP\s*:\s*({IPV4})',
]

_SOURCE_BLOCK_HEADER = re.compile(r"Source IPs? Observed\s*:")
_SOURCE_BLOCK_LINE = re.compile(rf"^({IPV4})\b")


def refang(text: str) -> str:
    if not text:
        return text
    text = re.sub(r"\[\.\]", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    return text


def extract_source_ips_list(raw_text: str):
    """Pure function: returns a deduped, order-preserving list of source IPs."""
    text = refang(raw_text or "")

    source_ips = []

    for pattern in _SOURCE_LINE_PATTERNS:
        for match in re.finditer(pattern, text, re.MULTILINE):
            ip = match.group(1)
            if ip not in source_ips:
                source_ips.append(ip)

    # "Source IPs Observed:" is followed by one IP per line, often with a
    # trailing "(Geo: XX)" - only trust lines that start with an IP right
    # after the header, and stop at the first line that doesn't (don't rely
    # on a blank-line separator, which isn't always present).
    header_match = _SOURCE_BLOCK_HEADER.search(text)
    if header_match:
        for line in text[header_match.end():].splitlines():
            line = line.strip()
            if not line:
                break
            line_match = _SOURCE_BLOCK_LINE.match(line)
            if not line_match:
                break
            ip = line_match.group(1)
            if ip not in source_ips:
                source_ips.append(ip)

    return source_ips


def extract_source_ips(**kwargs):
    """
    Returns a JSON-serializable object that implements the configured data paths:
    """

    ################################################################################
    ## Custom Code Goes Below This Line
    ################################################################################

    outputs = {}

    alert_text = kwargs.get("alert_text") or ""
    source_ips = extract_source_ips_list(alert_text)

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
    sample = """Target Application: trc.tax.gov.ae
Affected Backend:
172.27.7.91
Source IPs Observed:
172.239.117.101 (Geo: GB)
172.237.109.192 (Geo: GB)
34.68.34.65 (Geo: US)
34.68.34.72 (Geo: US)
8.34.210.56 (Geo: US)
Executive Summary
CPX SOC investigated multiple WAF events...
...
ip_client="172[.]237[.]109[.]192", ip_client="172[.]239[.]117[.]101", ip_client="34[.]68[.]34[.]65", ip_client="34[.]68[.]34[.]72", ip_client="8[.]34[.]210[.]56", ... dest_ip="172[.]27[.]7[.]91" ...
x_forwarded_for_header_value="34[.]68[.]34[.]65"
X-Forwarded-For: 34[.]68[.]34[.]72
"""
    result = extract_source_ips(alert_text=sample)
    print(json.dumps(result, indent=2))
    assert "172.27.7.91" not in result["source_ips"], "destination IP leaked into source list!"
    print("\nDestination IP correctly excluded.")
