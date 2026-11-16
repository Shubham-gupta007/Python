#!/usr/bin/env python3
"""
Splunk SOAR Custom Function: Split a mixed IOC batch into per-type,
block-ready lists (auto-detects type from the value itself)

Takes just a batch of raw indicator values - no separate "type" input
needed - and auto-detects each one's type from its own shape (an
IPv4-looking value, a URL/scheme marker, a 64-hex-char string, or a
domain-looking value), then sorts them into separate output lists,
each ready to feed straight into the matching block function already
in this folder:

    ip_list      -> block_fortigate_dc_ip / block_fortigate_dr_ip
    domain_list  -> block_fortigate_dc_domain / block_fortigate_dr_domain
    url_list     -> block_apex (ioc_type="URL")
    sha256_list  -> block_apex (ioc_type="SHA256")
    other_list   -> anything that isn't recognized as one of the four
                     above (e.g. a SHA1/MD5 hash, an email address, or
                     a value that doesn't validate even after
                     defanging) - NOT blocked by this pipeline, kept
                     as {"indicator": ..., "reason": ...} so nothing
                     is silently dropped

Each value is defanged/auto-fixed first (hxxp://, [.], etc. - same
rules as normalize_validate_ioc.py / step2), then classified and
validated against its best-matching type. Checked in this order so
nothing gets misread:

    1. URL - a defanged scheme marker (hxxp/hxxps) or a literal
       "://" in the value
    2. Hash - a string that's pure hex once whitespace/colons/dashes
       are stripped; 64 hex chars -> SHA256, any other hex length
       (40 = SHA1, 32 = MD5, ...) -> a real hash, just not one this
       pipeline blocks, so it goes to other_list
    3. IP - parses as a valid IPv4 address
    4. Domain - matches a plain hostname shape
    5. Anything left over -> other_list

Duplicate values within the same list are dropped (order preserved).

No external libraries - re/ipaddress/urllib.parse/ast/json are all
standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "split_iocs_by_type".
    2. Input parameters: indicator (string - accepts a list too)
    3. Output parameters: ip_list, domain_list, url_list, sha256_list,
       other_list (all string - JSON arrays), ip_count, domain_count,
       url_count, sha256_count, other_count, total_count (all
       numeric), warning (string)
    4. Paste everything from "import ast" below into the editor.
    5. Downstream: a Format/code block does json.loads(ip_list) to get
       a real Python list, then wires it straight into
       block_fortigate_dc_ip's/block_fortigate_dr_ip's "value" input
       (which already accepts a whole list in one call - no Loop block
       needed). Same idea for the other three lists.
"""


def split_iocs_by_type(indicator=None, **kwargs):
    """
    Args:
        indicator (CEF type: string) -- one indicator value, or a list of them

    Returns a JSON-serializable object that implements the configured data paths:
        ip_list (CEF type: string) -- JSON array of cleaned IPs
        domain_list (CEF type: string) -- JSON array of cleaned domains
        url_list (CEF type: string) -- JSON array of cleaned URLs
        sha256_list (CEF type: string) -- JSON array of cleaned SHA256 hashes
        other_list (CEF type: string) -- JSON array of {"indicator", "reason"}
            for everything not placed in one of the lists above
            (SHA1/MD5/email/etc., or anything that fails validation)
        ip_count / domain_count / url_count / sha256_count /
            other_count / total_count (CEF type: numeric)
        warning (CEF type: string) -- non-fatal notes
    """
    ########################## Custom Code Goes Below This Line ##########################
    import ast
    import ipaddress
    import json
    import re
    from urllib.parse import urlparse

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

    def fix_url(raw):
        value = defang_fix(raw)
        if not re.match(r"^https?://", value, flags=re.IGNORECASE):
            value = "http://" + value
        return value

    def validate_url(value):
        if not (value.startswith("http://") or value.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        if len(value) > 2047:
            raise ValueError("URL exceeds 2047 characters.")
        if not urlparse(value).netloc:
            raise ValueError("URL does not contain a valid hostname.")
        return value

    def validate_ip(value):
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

    def classify_and_fix(raw):
        """
        Returns (bucket_key, fixed_value) for a recognized, validated
        IOC, or (None, reason_string) for anything that should go to
        other_list instead.
        """
        cleaned = defang_fix(raw)

        # 1. URL - checked first so a defanged URL's embedded domain
        # or path never gets misread as a plain domain/IP.
        if re.match(r"^https?://", cleaned, flags=re.IGNORECASE) or "://" in cleaned:
            try:
                return "url_list", validate_url(fix_url(raw))
            except ValueError as error:
                return None, str(error)

        # 2. Hash - pure hex once separators are stripped. Only exact
        # crypto-hash lengths are treated as "a hash" at all, so a
        # short hex-looking string still falls through to IP/domain.
        hex_only = re.sub(r"[\s:-]", "", cleaned)
        if re.fullmatch(r"[0-9A-Fa-f]+", hex_only) and len(hex_only) in (32, 40, 64):
            if len(hex_only) == 64:
                return "sha256_list", hex_only.upper()
            return None, f"{len(hex_only) * 4}-bit hash (not SHA256) - not blocked by this pipeline."

        # 3. IP
        try:
            return "ip_list", validate_ip(cleaned)
        except ValueError:
            pass

        # 4. Domain
        try:
            return "domain_list", validate_domain(cleaned.rstrip(".").lower())
        except ValueError:
            pass

        return None, f"'{raw}' does not match a recognized IOC format (IP/domain/URL/SHA256)."

    def _item_scalar(v):
        # SOAR sometimes wraps each item of a multi-item list in its
        # own one-item list. Unwrap any level of that nesting down to
        # a plain scalar.
        while isinstance(v, list):
            v = v[0] if v else None
        return v

    def _to_list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    def _parse_stringified_list(v):
        # A single SOAR data path sometimes resolves to the str()/
        # repr() of an actual Python list, e.g.
        # "['1.2.3.4', '5.6.7.8']" (a static/"Format" field stringified
        # a real list) instead of delivering a true list. A value
        # never legitimately starts with "[", so this is safe to try
        # unconditionally.
        if not isinstance(v, str):
            return None
        stripped = v.strip()
        if not (stripped.startswith("[") and stripped.endswith("]")):
            return None
        try:
            parsed = ast.literal_eval(stripped)
        except (ValueError, SyntaxError):
            return None
        if isinstance(parsed, (list, tuple)):
            return [str(p).strip() for p in parsed if str(p).strip()]
        return None

    def expand(raw_list):
        # Unwrap nested single-item lists, then expand any item that
        # turns out to itself be a stringified list.
        expanded = []
        for raw in raw_list:
            item = _item_scalar(raw)
            parsed = _parse_stringified_list(item)
            if parsed is not None:
                expanded.extend(parsed)
            elif item not in (None, ""):
                expanded.append(item)
        return expanded

    indicators = expand(_to_list(indicator))

    outputs = {
        "ip_list": "[]",
        "domain_list": "[]",
        "url_list": "[]",
        "sha256_list": "[]",
        "other_list": "[]",
        "ip_count": 0,
        "domain_count": 0,
        "url_count": 0,
        "sha256_count": 0,
        "other_count": 0,
        "total_count": 0,
        "warning": "",
    }

    if not indicators:
        outputs["warning"] = "No 'indicator' provided."
        assert json.dumps(outputs)
        return outputs

    buckets = {"ip_list": [], "domain_list": [], "url_list": [], "sha256_list": []}
    other = []

    for raw_indicator in indicators:
        bucket_key, fixed_or_reason = classify_and_fix(raw_indicator)

        if bucket_key is None:
            other.append({"indicator": raw_indicator, "reason": fixed_or_reason})
            continue

        bucket = buckets[bucket_key]
        if fixed_or_reason not in bucket:
            bucket.append(fixed_or_reason)

    count_key_for_list_key = {
        "ip_list": "ip_count",
        "domain_list": "domain_count",
        "url_list": "url_count",
        "sha256_list": "sha256_count",
    }

    for list_key, count_key in count_key_for_list_key.items():
        outputs[list_key] = json.dumps(buckets[list_key])
        outputs[count_key] = len(buckets[list_key])

    outputs["other_list"] = json.dumps(other)
    outputs["other_count"] = len(other)
    outputs["total_count"] = sum(outputs[c] for c in count_key_for_list_key.values()) + outputs["other_count"]

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
