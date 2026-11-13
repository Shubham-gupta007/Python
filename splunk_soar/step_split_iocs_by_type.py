#!/usr/bin/env python3
"""
Splunk SOAR Custom Function: Split a mixed IOC batch into per-type,
block-ready lists

Takes a batch of indicators plus their stated types (e.g. an advisory
table like Indicator/Type columns: IP Address, Domain, URL, SHA256,
...) and sorts them into separate output lists, one per blockable
type, each ready to feed straight into the matching block function
already in this folder:

    ip_list      -> block_fortigate_dc_ip / block_fortigate_dr_ip
    domain_list  -> block_fortigate_dc_domain / block_fortigate_dr_domain
    url_list     -> block_apex (ioc_type="URL")
    sha1_list    -> block_apex (ioc_type="SHA1")
    sha256_list  -> block_apex (ioc_type="SHA256")
    other_list   -> everything else (unsupported type, or a value that
                     fails validation for its stated type) - NOT
                     blocked by this pipeline, kept as
                     {"indicator": ..., "type": ...} so nothing is
                     silently dropped

Each value going into a block-ready list is defanged/auto-fixed
(hxxp://, [.], etc.) and validated first, using the same rules as
normalize_validate_ioc.py (step2) - a value that doesn't validate even
after fixing goes to other_list instead, with the reason recorded.
Duplicate values within the same list are dropped (order preserved).

No external libraries - re/ipaddress/urllib.parse/ast/json are all
standard library.

How to use in SOAR:

    1. Playbook editor -> Custom Function -> New Custom Function,
       name it "split_iocs_by_type".
    2. Input parameters: indicator (string - accepts a list too),
       ioc_type (string - accepts a list too, or a single type applied
       to every indicator)
    3. Output parameters: ip_list, domain_list, url_list, sha1_list,
       sha256_list, other_list (all string - JSON arrays), ip_count,
       domain_count, url_count, sha1_count, sha256_count, other_count,
       total_count (all numeric), warning (string)
    4. Paste everything from "import ast" below into the editor.
    5. Downstream: a Format/code block does json.loads(ip_list) to get
       a real Python list, then wires it straight into
       block_fortigate_dc_ip's/block_fortigate_dr_ip's "value" input
       (which already accepts a whole list in one call - no Loop block
       needed). Same idea for the other four lists.
"""


def split_iocs_by_type(indicator=None, ioc_type=None, **kwargs):
    """
    Args:
        indicator (CEF type: string) -- one indicator value, or a list of them
        ioc_type (CEF type: string) -- one type label per indicator (a
            list the same length as indicator), or a single type label
            applied to every indicator

    Returns a JSON-serializable object that implements the configured data paths:
        ip_list (CEF type: string) -- JSON array of cleaned IPs
        domain_list (CEF type: string) -- JSON array of cleaned domains
        url_list (CEF type: string) -- JSON array of cleaned URLs
        sha1_list (CEF type: string) -- JSON array of cleaned SHA1 hashes
        sha256_list (CEF type: string) -- JSON array of cleaned SHA256 hashes
        other_list (CEF type: string) -- JSON array of {"indicator", "type", "reason"}
            for everything not placed in one of the lists above
        ip_count / domain_count / url_count / sha1_count / sha256_count /
            other_count / total_count (CEF type: numeric)
        warning (CEF type: string) -- non-fatal notes (e.g. an
            indicator/ioc_type length mismatch)
    """
    ########################## Custom Code Goes Below This Line ##########################
    import ast
    import ipaddress
    import json
    import re
    from urllib.parse import urlparse

    type_aliases = {
        "IP": "IP",
        "IP ADDRESS": "IP",
        "IPADDRESS": "IP",
        "IPV4": "IP",
        "IP_ADDRESS": "IP",
        "DOMAIN": "DOMAIN",
        "DOMAIN NAME": "DOMAIN",
        "FQDN": "DOMAIN",
        "URL": "URL",
        "URI": "URL",
        "SHA1": "SHA1",
        "SHA-1": "SHA1",
        "SHA 1": "SHA1",
        "SHA256": "SHA256",
        "SHA-256": "SHA256",
        "SHA 256": "SHA256",
    }

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
    list_key_for_type = {
        "IP": "ip_list",
        "DOMAIN": "domain_list",
        "URL": "url_list",
        "SHA1": "sha1_list",
        "SHA256": "sha256_list",
    }

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

    # ioc_type additionally gets a plain comma/newline split - type
    # labels never legitimately contain a comma, unlike indicator
    # values (a URL's query string can), so this is only safe to do
    # for ioc_type.
    def expand_types(raw_list):
        expanded = expand(raw_list)
        final = []
        for item in expanded:
            if isinstance(item, str) and ("," in item or "\n" in item):
                final.extend(p.strip() for p in item.replace("\n", ",").split(",") if p.strip())
            else:
                final.append(item)
        return final

    indicators = expand(_to_list(indicator))
    types_raw = expand_types(_to_list(ioc_type))

    outputs = {
        "ip_list": "[]",
        "domain_list": "[]",
        "url_list": "[]",
        "sha1_list": "[]",
        "sha256_list": "[]",
        "other_list": "[]",
        "ip_count": 0,
        "domain_count": 0,
        "url_count": 0,
        "sha1_count": 0,
        "sha256_count": 0,
        "other_count": 0,
        "total_count": 0,
        "warning": "",
    }

    if not indicators:
        outputs["warning"] = "No 'indicator' provided."
        assert json.dumps(outputs)
        return outputs

    if not types_raw:
        outputs["warning"] = "No 'ioc_type' provided."
        assert json.dumps(outputs)
        return outputs

    if len(types_raw) not in (1, len(indicators)):
        outputs["warning"] = (
            f"'ioc_type' has {len(types_raw)} value(s) but 'indicator' has "
            f"{len(indicators)} - pairing by index up to the shorter length."
        )

    def type_for(index):
        if len(types_raw) == len(indicators):
            return types_raw[index]
        return types_raw[0]

    buckets = {"ip_list": [], "domain_list": [], "url_list": [], "sha1_list": [], "sha256_list": []}
    other = []

    pair_count = min(len(indicators), len(types_raw)) if len(types_raw) != 1 else len(indicators)

    for index in range(pair_count):
        raw_indicator = indicators[index]
        raw_type = type_for(index)
        type_label = (raw_type or "").strip().upper()
        normalized_type = type_aliases.get(type_label)

        if normalized_type is None:
            other.append({
                "indicator": raw_indicator,
                "type": raw_type,
                "reason": f"Unsupported/unrecognized type '{raw_type}' - not blocked by this pipeline.",
            })
            continue

        try:
            fixed = fixers[normalized_type](raw_indicator)
            fixed = validators[normalized_type](fixed)
        except ValueError as error:
            other.append({"indicator": raw_indicator, "type": raw_type, "reason": str(error)})
            continue

        bucket = buckets[list_key_for_type[normalized_type]]
        if fixed not in bucket:
            bucket.append(fixed)

    for key, values in buckets.items():
        outputs[key] = json.dumps(values)

    count_key_for_list_key = {
        "ip_list": "ip_count",
        "domain_list": "domain_count",
        "url_list": "url_count",
        "sha1_list": "sha1_count",
        "sha256_list": "sha256_count",
    }
    for list_key, count_key in count_key_for_list_key.items():
        outputs[count_key] = len(buckets[list_key])

    outputs["other_list"] = json.dumps(other)
    outputs["other_count"] = len(other)
    outputs["total_count"] = sum(outputs[c] for c in count_key_for_list_key.values()) + outputs["other_count"]

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
