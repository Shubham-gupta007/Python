#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 1: Extract IOCs from an advisory

Replaces the old "clean CSV from the threat intel team" input with a
raw advisory (a text/PDF/email body pasted into a container, or the
text already pulled out of a vault file). Pulls out every IP, domain,
URL, SHA1 and SHA256 it can find and hands back a clean list ready for
step2_normalize_validate.py.

--------------------------------------------------------------------
Before writing this as a custom function, check if you even need to:
Splunk's own "Parser" app (Splunkbase app id 5832) has a built-in
"extract ioc" action that does exactly this against a vault file, PDF
or raw text and creates IOC artifacts automatically - no code required.
Use that first. Write this custom function only if the Parser app
isn't installed/licensed in your SOAR instance, or you need the exact
same extraction logic to run outside SOAR (e.g. for local testing).
--------------------------------------------------------------------

How to paste this into SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function.
    2. Add one input parameter:  advisory_text   (string)
    3. Add two output parameters: iocs_json (string), ioc_count (number)
    4. Paste the body of extract_iocs_custom_function() below into the
       generated stub (rename the stub's def line to match, SOAR
       auto-generates it with your parameter names).
    5. Wire the "iocs_json" output into a Format/Filter block that
       turns it into a list SOAR can loop over (e.g.
       json.loads(iocs_json) in a following code/format block), then
       feed each {"type":..., "value":...} into step2's inputs. SOAR
       auto-loops any downstream block fed a list, so you do not need
       a manual for-loop in the playbook itself.
"""

import re


# ============================================================
# DEFANG REVERSAL (same rules as the CLI tools, so an advisory that
# writes "hxxp://evil[.]example.com" still gets picked up)
# ============================================================

def refang_text(text):
    text = re.sub(r"hxxps://", "https://", text, flags=re.IGNORECASE)
    text = re.sub(r"hxxp://", "http://", text, flags=re.IGNORECASE)

    for pattern in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        text = re.sub(re.escape(pattern), ".", text, flags=re.IGNORECASE)

    for pattern in ("[:]", "(:)"):
        text = text.replace(pattern, ":")

    return text


# ============================================================
# EXTRACTORS
# ============================================================

URL_PATTERN = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Domains: at least two labels, alphabetic TLD 2-24 chars. Common file
# extensions are excluded so "malware.exe" inside a URL path isn't
# mistaken for a domain.
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

FILE_EXTENSIONS = {
    "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
    "zip", "rar", "7z", "js", "vbs", "php", "html", "htm", "txt",
    "jpg", "jpeg", "png", "gif", "py", "sh", "bat", "ps1", "jar",
    "bin", "scr", "msi", "apk", "tmp", "log", "ini", "cfg", "dat",
    "cab", "gz", "tar", "iso",
    # Deliberately NOT excluding "com" - it collides with the .com TLD,
    # which would silently drop the most common domain suffix there is.
}

SHA256_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")
SHA1_PATTERN = re.compile(r"\b[0-9a-fA-F]{40}\b")


def extract_urls(text):
    return {match.group(0).rstrip(".,;:)") for match in URL_PATTERN.finditer(text)}


def extract_ips(text, exclude_spans_text):
    return {
        match.group(0)
        for match in IP_PATTERN.finditer(text)
        if match.group(0) not in exclude_spans_text
    }


def extract_domains(text_without_urls):
    domains = set()

    for match in DOMAIN_PATTERN.finditer(text_without_urls):
        candidate = match.group(0)
        tld = candidate.rsplit(".", 1)[-1].lower()

        if tld in FILE_EXTENSIONS:
            continue

        if IP_PATTERN.fullmatch(candidate):
            continue

        domains.add(candidate.lower())

    return domains


def extract_hashes(text):
    sha256_hits = {match.group(0).upper() for match in SHA256_PATTERN.finditer(text)}

    # Remove the SHA256 hits before hunting for SHA1 so a 64-char run
    # never gets mistaken for two hashes.
    remaining = text
    for hit in sha256_hits:
        remaining = remaining.replace(hit, " ").replace(hit.lower(), " ")

    sha1_hits = {match.group(0).upper() for match in SHA1_PATTERN.finditer(remaining)}

    return sha256_hits, sha1_hits


def extract_iocs_from_text(raw_text):
    """
    Core extraction logic - returns a de-duplicated list of
    {"type": ..., "value": ...} dicts, in the same shape the block/
    unblock CLI tools already consume.
    """
    text = refang_text(raw_text or "")

    urls = extract_urls(text)

    # Domains that are just the hostname of a URL we already flagged
    # are still extracted separately below (on purpose - you usually
    # want the domain blocked on the firewall AND the exact malicious
    # URL blocked on Apex Central), we just avoid re-parsing the URL
    # text itself so query strings/paths can't look like a domain.
    text_without_urls = URL_PATTERN.sub(" ", text)
    domains = extract_domains(text_without_urls)

    ips = extract_ips(text_without_urls, exclude_spans_text=urls)

    sha256_hits, sha1_hits = extract_hashes(text)

    iocs = []
    iocs.extend({"type": "URL", "value": v} for v in sorted(urls))
    iocs.extend({"type": "DOMAIN", "value": v} for v in sorted(domains))
    iocs.extend({"type": "IP", "value": v} for v in sorted(ips))
    iocs.extend({"type": "SHA256", "value": v} for v in sorted(sha256_hits))
    iocs.extend({"type": "SHA1", "value": v} for v in sorted(sha1_hits))

    return iocs


# ============================================================
# SOAR CUSTOM FUNCTION WRAPPER
# ============================================================

def extract_iocs_custom_function(advisory_text=None, **kwargs):
    """
    This is the part to paste into the SOAR custom function editor.
    Input parameter:  advisory_text (string)
    Output parameters: iocs_json (string), ioc_count (number)
    """
    import json

    iocs = extract_iocs_from_text(advisory_text)

    return {
        "iocs_json": json.dumps(iocs),
        "ioc_count": len(iocs),
    }


if __name__ == "__main__":
    import json
    import sys

    sample = sys.stdin.read() if not sys.stdin.isatty() else (
        "Threat advisory: campaign uses C2 IP 192.168.1[.]100 and drops "
        "malware from hxxps://evil[.]example.com/malware.exe. Related "
        "phishing domain evil2[.]example[.]com was also observed. "
        "SHA256 hash: c71ddfa376b2a86bae93d46d997742502d127979a8774402c936ec6832bb91d0"
    )

    print(json.dumps(extract_iocs_from_text(sample), indent=2))
