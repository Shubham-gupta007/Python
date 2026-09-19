#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 1: Extract IOCs from a prose advisory

Use this when the advisory is free text (an email body, a PDF's
extracted text, a report) rather than a structured CSV - pulls out
every IP, domain, URL, SHA1 and SHA256 it can find. If the attachment
IS already a type/indicator/description CSV, use step0_read_ioc_file.py
instead.

--------------------------------------------------------------------
Before writing this as a custom function: Splunk's own "Parser" app
(Splunkbase app id 5832) has a built-in "extract ioc" action that does
this against a vault file, PDF or raw text and creates IOC artifacts
automatically - no code required. Use that first if it's available.
--------------------------------------------------------------------

No external libraries - re/json are standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "extract_iocs".
    2. Input parameter: advisory_text (string)
    3. Output parameters: iocs_json (string), ioc_count (number)
    4. Paste everything from "import re" below into the editor in
       place of the placeholder outputs = {} / "Write your custom
       code here" lines.
"""


def extract_iocs(advisory_text=None, **kwargs):
    """
    Args:
        advisory_text (CEF type: string) -- raw advisory text

    Returns a JSON-serializable object that implements the configured data paths:
        iocs_json (CEF type: string)
        ioc_count (CEF type: numeric)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import json
    import re

    def refang_text(text):
        text = re.sub(r"hxxps://", "https://", text, flags=re.IGNORECASE)
        text = re.sub(r"hxxp://", "http://", text, flags=re.IGNORECASE)

        for pattern in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
            text = re.sub(re.escape(pattern), ".", text, flags=re.IGNORECASE)

        for pattern in ("[:]", "(:)"):
            text = text.replace(pattern, ":")

        return text

    url_pattern = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)

    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    )

    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,24}\b"
    )

    file_extensions = {
        "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
        "zip", "rar", "7z", "js", "vbs", "php", "html", "htm", "txt",
        "jpg", "jpeg", "png", "gif", "py", "sh", "bat", "ps1", "jar",
        "bin", "scr", "msi", "apk", "tmp", "log", "ini", "cfg", "dat",
        "cab", "gz", "tar", "iso",
        # Deliberately NOT excluding "com" - it collides with the .com TLD.
    }

    sha256_pattern = re.compile(r"\b[0-9a-fA-F]{64}\b")
    sha1_pattern = re.compile(r"\b[0-9a-fA-F]{40}\b")

    def extract_urls(text):
        return {match.group(0).rstrip(".,;:)") for match in url_pattern.finditer(text)}

    def extract_ips(text, exclude_urls):
        return {
            match.group(0)
            for match in ip_pattern.finditer(text)
            if match.group(0) not in exclude_urls
        }

    def extract_domains(text_without_urls):
        domains = set()
        for match in domain_pattern.finditer(text_without_urls):
            candidate = match.group(0)
            tld = candidate.rsplit(".", 1)[-1].lower()
            if tld in file_extensions:
                continue
            if ip_pattern.fullmatch(candidate):
                continue
            domains.add(candidate.lower())
        return domains

    def extract_hashes(text):
        sha256_hits = {match.group(0).upper() for match in sha256_pattern.finditer(text)}
        remaining = text
        for hit in sha256_hits:
            remaining = remaining.replace(hit, " ").replace(hit.lower(), " ")
        sha1_hits = {match.group(0).upper() for match in sha1_pattern.finditer(remaining)}
        return sha256_hits, sha1_hits

    outputs = {"iocs_json": "[]", "ioc_count": 0}

    text = refang_text(advisory_text or "")

    urls = extract_urls(text)
    text_without_urls = url_pattern.sub(" ", text)
    domains = extract_domains(text_without_urls)
    ips = extract_ips(text_without_urls, exclude_urls=urls)
    sha256_hits, sha1_hits = extract_hashes(text)

    iocs = []
    iocs.extend({"type": "URL", "value": v} for v in sorted(urls))
    iocs.extend({"type": "DOMAIN", "value": v} for v in sorted(domains))
    iocs.extend({"type": "IP", "value": v} for v in sorted(ips))
    iocs.extend({"type": "SHA256", "value": v} for v in sorted(sha256_hits))
    iocs.extend({"type": "SHA1", "value": v} for v in sorted(sha1_hits))

    outputs["iocs_json"] = json.dumps(iocs)
    outputs["ioc_count"] = len(iocs)

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
