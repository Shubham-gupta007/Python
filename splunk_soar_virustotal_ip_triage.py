"""
Splunk SOAR Custom Function: VirusTotal IP reputation + UAE/whitelist triage.

Looks up one or more IPs (single IP, comma-separated string, or list) against
the VirusTotal v3 API directly (no "asset action" block needed - this calls
VT's REST API straight from the custom function, synchronously, so you get a
real list back immediately instead of dealing with phantom.act()'s async
callback pattern) and splits them into:

  - allow_ips  : should NOT be blocked - either explicitly whitelisted, or
                 VirusTotal reports their location as UAE ("AE")
  - block_ips  : everything else - feed this single List output into your
                 Fortinet DC, Fortinet DR, and Palo Alto "block IP" action
                 blocks (connect the same List datapath to all three; SOAR
                 fans out one call per IP per asset automatically)
  - error_ips  : IPs whose VirusTotal lookup failed (bad API key, VT
                 outage, rate limit, unknown IP, network error). These are
                 deliberately NOT added to block_ips - a transient lookup
                 failure should never silently trigger a firewall block.
                 Review these manually or re-run.

Editor setup (left panel):
  Name              : virustotal_ip_triage (or any name you like)
  Add Input         : Name = ips             | Data Type = string
                       (one IP, "1.2.3.4,5.6.7.8", or a List datapath - all accepted)
  Add Input         : Name = whitelist_ips   | Data Type = string (optional, same formats)
  Add Input         : Name = vt_api_key      | Data Type = string
  Add Output (List) : Name = allow_ips       | Data Type = string
  Add Output (List) : Name = block_ips       | Data Type = string
  Add Output (List) : Name = error_ips       | Data Type = string
  Add Output (Item) : Name = vt_results_json | Data Type = string
"""

import json
import re
import time

try:
    import requests  # present in the SOAR custom-function sandbox
except ImportError:
    requests = None

IPV4 = r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$"
UAE_COUNTRY_CODE = "AE"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_REQUEST_DELAY_SECONDS = 1  # be gentle with VirusTotal's public-tier rate limit (4 req/min)


def as_ip_list(value):
    """Normalize a single IP, comma/whitespace-separated string, or list/tuple
    into a deduped, order-preserving list of valid IPv4 addresses."""
    items = []
    if value is None:
        return items
    if isinstance(value, (list, tuple)):
        for v in value:
            items.extend(as_ip_list(v))
        return items
    for token in re.split(r"[,\s]+", str(value).strip()):
        if token:
            items.append(token)

    deduped = []
    for ip in items:
        ip = ip.strip()
        if re.match(IPV4, ip) and ip not in deduped:
            deduped.append(ip)
    return deduped


def lookup_virustotal_country(ip, api_key, session):
    """Query VirusTotal for one IP. Returns (country_code_or_None, result_dict)."""
    try:
        resp = session.get(
            VT_IP_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=30,
        )
        if resp.status_code != 200:
            return None, {"ip": ip, "error": f"HTTP {resp.status_code}", "body": resp.text[:500]}
        attributes = resp.json().get("data", {}).get("attributes", {})
        country = attributes.get("country")
        return country, {
            "ip": ip,
            "country": country,
            "malicious": attributes.get("last_analysis_stats", {}).get("malicious"),
            "as_owner": attributes.get("as_owner"),
        }
    except Exception as exc:
        return None, {"ip": ip, "error": str(exc)}


def triage_ips(ips, whitelist_ips, api_key, lookup_fn=lookup_virustotal_country, session=None):
    """
    Core triage logic, independent of the HTTP layer so it can be unit tested
    with a fake lookup_fn(ip, api_key, session) -> (country_or_None, result_dict).
    """
    target_ips = as_ip_list(ips)
    whitelist = set(as_ip_list(whitelist_ips))

    allow_ips, block_ips, error_ips, vt_results = [], [], [], []
    if session is None and lookup_fn is lookup_virustotal_country:
        session = requests.Session()

    for i, ip in enumerate(target_ips):
        if ip in whitelist:
            allow_ips.append(ip)
            vt_results.append({"ip": ip, "reason": "whitelisted", "country": None})
            continue

        if i > 0:
            time.sleep(VT_REQUEST_DELAY_SECONDS)

        country, result = lookup_fn(ip, api_key, session)
        vt_results.append(result)

        if "error" in result:
            error_ips.append(ip)
        elif country == UAE_COUNTRY_CODE:
            allow_ips.append(ip)
        else:
            block_ips.append(ip)

    return allow_ips, block_ips, error_ips, vt_results


def virustotal_ip_triage(ips=None, whitelist_ips=None, vt_api_key=None, **kwargs):
    """
    Returns a JSON-serializable object that implements the configured data paths:
        allow_ips (CEF type: string)
        block_ips (CEF type: string)
        error_ips (CEF type: string)
        vt_results_json (CEF type: string)
    """

    ################################################################################
    ## Custom Code Goes Below This Line
    ################################################################################

    outputs = {}

    allow_ips, block_ips, error_ips, vt_results = triage_ips(ips, whitelist_ips, vt_api_key)

    outputs["allow_ips"] = allow_ips
    outputs["block_ips"] = block_ips
    outputs["error_ips"] = error_ips
    outputs["vt_results_json"] = json.dumps(vt_results)

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    ################################################################################
    ## Custom Code Goes Above This Line
    ################################################################################


if __name__ == "__main__":
    # Fake VirusTotal responses so this is testable without a real API key/network call.
    FAKE_VT_DB = {
        "5.6.7.8": {"country": "AE"},     # UAE - should be allowed
        "9.9.9.9": {"country": "US"},     # not UAE, not whitelisted - should be blocked
        "203.0.113.5": {"country": "RU"}, # not UAE - should be blocked
        "198.51.100.1": None,             # simulate a lookup failure
    }

    def fake_lookup(ip, api_key, session):
        entry = FAKE_VT_DB.get(ip)
        if entry is None:
            return None, {"ip": ip, "error": "simulated VT lookup failure"}
        return entry["country"], {"ip": ip, "country": entry["country"]}

    allow_ips, block_ips, error_ips, vt_results = triage_ips(
        ips="5.6.7.8, 9.9.9.9 203.0.113.5 198.51.100.1 1.2.3.4",
        whitelist_ips=["1.2.3.4"],
        api_key="dummy-key",
        lookup_fn=fake_lookup,
    )

    print("allow_ips:", allow_ips)
    print("block_ips:", block_ips)
    print("error_ips:", error_ips)
    print("vt_results:", json.dumps(vt_results, indent=2))

    assert allow_ips == ["5.6.7.8", "1.2.3.4"], "whitelisted + UAE IP should be allowed"
    assert block_ips == ["9.9.9.9", "203.0.113.5"], "non-UAE, non-whitelisted IPs should be blocked"
    assert error_ips == ["198.51.100.1"], "failed lookups must not silently end up in block_ips"
    print("\nAll checks passed.")
