#!/usr/bin/env python3
"""
Splunk SOAR Custom Function - Step 2: Normalize, auto-fix and route one IOC

Takes one {"type": ..., "value": ...} item at a time (from step 0 or
step 1's output list) and:

    1. Auto-corrects defanged/malformed values (hxxp://, [.], spaced
       hashes, missing URL scheme, wrong case) - the same rules used
       by the CLI tool, so results stay consistent.
    2. Validates the fixed value actually matches its declared type.
       A value that still fails is marked invalid and is NOT routed
       anywhere.
    3. Says which platform(s) should block it next.

No external libraries - re/ipaddress/urllib.parse are standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "normalize_validate_ioc".
    2. Input parameters: ioc_type (string), raw_value (string)
    3. Output parameters: is_valid (boolean), fixed_value (string),
       auto_fixed (boolean), target_tool (string), error (string)
    4. Paste everything from "import re" below into the editor.
    5. Wiring the loop: feed step0/step1's iocs_json through a small
       Format/code block that does json.loads(iocs_json) to get a
       real list, then wire that list's .type/.value fields into this
       block's ioc_type/raw_value inputs. SOAR auto-runs this block
       once per list item (no explicit loop needed) - or, if your
       playbook editor has an explicit Loop block, put this block
       (and step3a/step3b/step4) inside it, looping over that same
       list.
    6. Put a Decision block right after this one, branching on
       target_tool ("FORTIGATE" / "APEX") to route to step3a+step3b or
       step4.
"""


def normalize_validate_ioc(ioc_type=None, raw_value=None, **kwargs):
    """
    Args:
        ioc_type (CEF type: string) -- "IP", "DOMAIN", "URL", "SHA1" or "SHA256"
        raw_value (CEF type: string) -- the raw indicator value

    Returns a JSON-serializable object that implements the configured data paths:
        is_valid (CEF type: boolean)
        fixed_value (CEF type: string)
        auto_fixed (CEF type: boolean)
        target_tool (CEF type: string)
        error (CEF type: string)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import json
    import re
    from urllib.parse import urlparse

    type_aliases = {
        "IP": "IP",
        "IP_ADDRESS": "IP",
        "IP ADDRESS": "IP",
        "URL": "URL",
        "DOMAIN": "DOMAIN",
        "FQDN": "DOMAIN",
        "SHA1": "SHA1",
        "SHA-1": "SHA1",
        "SHA256": "SHA256",
        "SHA-256": "SHA256",
    }

    route_to_fortigate = {"IP", "DOMAIN"}
    route_to_apex = {"URL", "SHA1", "SHA256"}

    def normalize_type(value):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("IOC 'type' is missing or empty.")
        key = value.strip().upper()
        if key not in type_aliases:
            raise ValueError(
                f"Unsupported IOC type '{value}'. Supported: IP, DOMAIN "
                "(FortiGate), URL, SHA1, SHA256 (Trend Micro Apex Central)."
            )
        return type_aliases[key]

    def target_for_type(normalized_type):
        if normalized_type in route_to_fortigate:
            return "FORTIGATE"
        if normalized_type in route_to_apex:
            return "APEX"
        return ""

    def strip_wrapping(value):
        return value.strip().strip("\"'<>").strip()

    def defang_fix(value):
        value = strip_wrapping(value)
        value = re.sub(r"hxxps://", "https://", value, flags=re.IGNORECASE)
        value = re.sub(r"hxxp://", "http://", value, flags=re.IGNORECASE)
        for pattern in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
            value = re.sub(re.escape(pattern), ".", value, flags=re.IGNORECASE)
        for pattern in ("[:]", "(:)"):
            value = value.replace(pattern, ":")
        value = value.replace("[at]", "@").replace("(at)", "@")
        return value.strip()

    def fix_ip(raw):
        return defang_fix(raw)

    def fix_domain(raw):
        return defang_fix(raw).rstrip(".").lower()

    def fix_url(raw):
        value = defang_fix(raw)
        if not re.match(r"^https?://", value, flags=re.IGNORECASE):
            value = "http://" + value
        return value

    def fix_hash(raw):
        value = defang_fix(raw)
        value = re.sub(r"[\s:-]", "", value)
        return value.upper()

    def validate_ip(value):
        import ipaddress

        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"Invalid IP address: {value}")
        if address.version != 4:
            raise ValueError(f"Expected IPv4, got IPv{address.version}: {value}")
        return str(address)

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    def validate_domain(value):
        if not domain_pattern.fullmatch(value):
            raise ValueError(f"Invalid domain: {value}")
        return value

    def validate_url(value):
        if not (value.startswith("http://") or value.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        if len(value) > 2047:
            raise ValueError("URL exceeds 2047 characters.")
        if not urlparse(value).netloc:
            raise ValueError("URL does not contain a valid hostname.")
        return value

    def validate_sha1(value):
        if not re.fullmatch(r"[0-9A-F]{40}", value):
            raise ValueError("SHA-1 must contain exactly 40 hexadecimal characters.")
        return value

    def validate_sha256(value):
        if not re.fullmatch(r"[0-9A-F]{64}", value):
            raise ValueError("SHA-256 must contain exactly 64 hexadecimal characters.")
        return value

    fixers = {"IP": fix_ip, "DOMAIN": fix_domain, "URL": fix_url, "SHA1": fix_hash, "SHA256": fix_hash}
    validators = {
        "IP": validate_ip,
        "DOMAIN": validate_domain,
        "URL": validate_url,
        "SHA1": validate_sha1,
        "SHA256": validate_sha256,
    }

    outputs = {"is_valid": False, "fixed_value": "", "auto_fixed": False, "target_tool": "", "error": ""}

    try:
        normalized_type = normalize_type(ioc_type)

        if not isinstance(raw_value, str) or not raw_value.strip():
            raise ValueError("Indicator value is missing or empty.")

        original = raw_value.strip()
        fixed = fixers[normalized_type](raw_value)
        fixed = validators[normalized_type](fixed)

        outputs["is_valid"] = True
        outputs["fixed_value"] = fixed
        outputs["auto_fixed"] = fixed != original
        outputs["target_tool"] = target_for_type(normalized_type)

    except ValueError as error:
        outputs["error"] = str(error)

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
