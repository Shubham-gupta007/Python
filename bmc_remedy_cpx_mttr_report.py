#!/usr/bin/env python3

# =========================================================================== #
#                              CONFIGURATION                                  #
#           Fill in your values below, save, and run the script.              #
# =========================================================================== #

# Remedy REST API URL: protocol + server + port, no "/" at the end.
BMC_URL = "https://remedy.example.com:8443"

# Remedy login (needs read access to the HPD:Help Desk form).
BMC_USERNAME = "your_username"
BMC_PASSWORD = "your_password"

# Report options.
YEAR = 2026                      # year to report on
MONTHS = [7, 8, 9]               # July, August, September
# Which incidents to include: those whose PREFIX_FIELD starts with ANY of
# the INCIDENT_PREFIXES. Add as many as you need, each in quotes, separated
# by commas. PREFIX_FIELD must be a Remedy *field name*, e.g.
#   "Incident Number"  -> the INC/CPX number
#   "Description"      -> the incident Summary
INCIDENT_PREFIXES = ["CPX"]      # e.g. ["CPX | ID:", "CPY | ID:", "ABC"]
PREFIX_FIELD = "Incident Number" # field name to search in
DETECT_FIELD = "Reported Date"   # Time to Detect = Submit Date - this field
TIMEZONE = ""                    # e.g. "+05:30"; "" = this machine's time zone
VERIFY_TLS = True                # False if the server uses a self-signed cert
OUTPUT_FILE = ""                 # "" = incident_mttr_report_<timestamp>.csv

# =========================================================================== #
#                     Nothing below needs to be changed.                      #
# =========================================================================== #

# BMC Remedy (Helix ITSM) - CPX Incident MTTR Report via REST API
#
# Pulls every incident from the HPD:Help Desk form whose Incident Number
# starts with "CPX" and whose Submit Date falls in July, August or September,
# then writes a CSV report (opens directly in Excel) with:
#
#     Incident section -> Incident Number, Summary, Status, Priority, Month,
#                         Reported Date, Submit Date, Last Resolved Date,
#                         Time to Detect, Time to Resolve
#     Summary section  -> per-month and overall incident count, resolved
#                         count, Average MTTR and Average Time to Detect
#
# Definitions:
#
#     Time to Detect  (TTD)  = Submit Date        - Reported Date
#     Time to Resolve (TTR)  = Last Resolved Date - Submit Date
#     MTTR                   = average TTR of the resolved incidents
#                              (open incidents have no Last Resolved Date
#                              and are left out of the average)
#
# Authentication: AR-JWT token from POST /api/jwt/login, sent as
# "Authorization: AR-JWT <token>"; the token is released on exit.
#
# Docs: https://docs.bmc.com -> Remedy AR System REST API -> Entry endpoints
#
# Requirements:
#     Python 3.6+ standard library only - no pip packages needed.
#
# Run (after filling in CONFIGURATION above):
#
#     python3 bmc_remedy_cpx_mttr_report.py
#     python3 bmc_remedy_cpx_mttr_report.py --year 2025 --months 7 8 9
#     python3 bmc_remedy_cpx_mttr_report.py --output cpx_q3.csv
#
#     Without --year, YEAR from CONFIGURATION is used.

import argparse
import calendar
import csv
import getpass
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

FORM = "HPD:Help Desk"
PAGE_SIZE = 500
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# --------------------------------------------------------------------------- #
# HTTP (urllib only)
# --------------------------------------------------------------------------- #

def ssl_context(verify):
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http(method, url, ctx, headers=None, data=None, timeout=120):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")
        if '"messageNumber":1587' in detail.replace(" ", ""):
            detail += ("\n\nHint: a field name in the query does not exist on "
                       "HPD:Help Desk. Check PREFIX_FIELD and DETECT_FIELD in "
                       "the CONFIGURATION section - they must be field names "
                       "(e.g. \"Incident Number\", \"Description\"), not the "
                       "text you are searching for, which goes in "
                       "INCIDENT_PREFIXES.")
        sys.exit(f"Remedy returned HTTP {err.code} for {method} {url}\n{detail}")
    except urllib.error.URLError as err:
        sys.exit(f"Could not reach Remedy at {url}: {err.reason}")


# --------------------------------------------------------------------------- #
# Remedy REST API
# --------------------------------------------------------------------------- #

def login(host, username, password, ctx):
    return http(
        "POST", f"{host}/api/jwt/login", ctx,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"username": username, "password": password},
        timeout=60,
    ).strip()


def logout(host, token, ctx):
    req = urllib.request.Request(
        f"{host}/api/jwt/logout", data=b"", method="POST",
        headers={"Authorization": f"AR-JWT {token}"},
    )
    try:
        urllib.request.urlopen(req, context=ctx, timeout=30).close()
    except (urllib.error.URLError, OSError):
        pass


def fetch_incidents(host, token, qualification, fields, ctx):
    """Return every entry matching the qualification, following pagination."""
    url = f"{host}/api/arsys/v1/entry/{urllib.parse.quote(FORM, safe=':')}"
    headers = {"Authorization": f"AR-JWT {token}", "Accept": "application/json"}
    entries = []
    offset = 0
    while True:
        params = urllib.parse.urlencode({
            "q": qualification,
            "fields": f"values({','.join(fields)})",
            "sort": "Submit Date.asc",
            "limit": PAGE_SIZE,
            "offset": offset,
        }, quote_via=urllib.parse.quote)
        page = json.loads(http("GET", f"{url}?{params}", ctx,
                               headers=headers)).get("entries", [])
        entries.extend(e.get("values", {}) for e in page)
        print(f"  fetched {len(entries)} incident(s)...")
        if len(page) < PAGE_SIZE:
            return entries
        offset += PAGE_SIZE


def like_literal(text):
    """Escape a value for a Remedy LIKE pattern: wildcards % _ [ become
    literal by wrapping them in brackets, and double quotes are doubled."""
    out = "".join(f"[{c}]" if c in "%_[" else c for c in text)
    return out.replace('"', '""')


def build_qualification(prefix_field, prefixes, start, end):
    # One LIKE per prefix, OR-ed together, so a single query covers them all.
    # Date fields are compared as epoch seconds, which avoids any dependence
    # on the server's date-format locale.
    likes = " OR ".join(f"'{prefix_field}' LIKE \"{like_literal(p)}%\""
                        for p in prefixes)
    return (
        f"({likes}) "
        f"AND 'Submit Date' >= {int(start.timestamp())} "
        f"AND 'Submit Date' < {int(end.timestamp())}"
    )


# --------------------------------------------------------------------------- #
# Date / duration helpers
# --------------------------------------------------------------------------- #

def resolve_timezone(name):
    if not name:
        return datetime.now().astimezone().tzinfo
    m = re.fullmatch(r"(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d{2})?", name.strip())
    if m:
        sign = 1 if m.group(1) == "+" else -1
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
        return timezone(sign * delta)
    if name.strip().upper() in ("UTC", "GMT", "Z"):
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        sys.exit(f"Unknown TIMEZONE {name!r}; use a UTC offset like +05:30.")


def parse_remedy_date(value, tz):
    """Remedy returns e.g. "2026-07-03T14:22:10.000+0000"; result is naive local."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz).replace(tzinfo=None)
    text = str(value).strip()
    dt = None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    if dt is None:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
    return dt.astimezone(tz).replace(tzinfo=None)


def hours_between(start, end):
    if start is None or end is None:
        return None
    return round((end - start).total_seconds() / 3600, 2)


def fmt_duration(hours):
    """12.5 -> "0d 12:30"; None -> ""."""
    if hours is None:
        return ""
    sign = "-" if hours < 0 else ""
    minutes = int(round(abs(hours) * 60))
    days, minutes = divmod(minutes, 24 * 60)
    hh, mm = divmod(minutes, 60)
    return f"{sign}{days}d {hh:02d}:{mm:02d}"


def fmt_date(dt):
    return dt.strftime(DATE_FORMAT) if dt else ""


def blank(value):
    return "" if value is None else value


def average(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 2) if values else None


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def matched_prefix(value, prefixes):
    """Longest configured prefix the value starts with (case-insensitive,
    like Remedy's LIKE on most databases)."""
    value = (value or "").casefold()
    hits = [p for p in prefixes if value.startswith(p.casefold())]
    return max(hits, key=len) if hits else ""


def build_rows(entries, detect_field, prefix_field, prefixes, tz):
    rows = []
    seen = set()
    for e in entries:
        key = e.get("Incident Number")
        if key in seen:
            continue
        seen.add(key)
        reported = parse_remedy_date(e.get(detect_field), tz)
        submitted = parse_remedy_date(e.get("Submit Date"), tz)
        resolved = parse_remedy_date(e.get("Last Resolved Date"), tz)
        rows.append({
            "incident": e.get("Incident Number") or "",
            "prefix": matched_prefix(e.get(prefix_field), prefixes),
            "summary": e.get("Description") or "",
            "status": e.get("Status") or "",
            "priority": e.get("Priority") or "",
            "reported": reported,
            "submitted": submitted,
            "resolved": resolved,
            "ttd": hours_between(reported, submitted),
            "ttr": hours_between(submitted, resolved),
            "month": submitted.strftime("%B %Y") if submitted else "",
        })
    rows.sort(key=lambda r: (r["submitted"] or datetime.min, r["incident"]))
    return rows


def summarise(label, subset):
    mttr = average(r["ttr"] for r in subset)
    mttd = average(r["ttd"] for r in subset)
    resolved = sum(1 for r in subset if r["resolved"])
    return [label, len(subset), resolved, len(subset) - resolved,
            blank(mttr), fmt_duration(mttr), blank(mttd), fmt_duration(mttd)], mttr


def write_report(rows, months, year, detect_field, prefixes, prefix_field,
                 path):
    # utf-8-sig adds a BOM so Excel detects the encoding correctly.
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)

        w.writerow(["Incident Number", "Matched Prefix", "Summary", "Status", "Priority", "Month",
                    detect_field, "Submit Date", "Last Resolved Date",
                    "Time to Detect (hrs)", "Time to Detect (d hh:mm)",
                    "Time to Resolve (hrs)", "Time to Resolve (d hh:mm)"])
        for r in rows:
            w.writerow([r["incident"], r["prefix"], r["summary"], r["status"],
                        r["priority"], r["month"], fmt_date(r["reported"]),
                        fmt_date(r["submitted"]), fmt_date(r["resolved"]),
                        blank(r["ttd"]), fmt_duration(r["ttd"]),
                        blank(r["ttr"]), fmt_duration(r["ttr"])])

        w.writerow([])
        w.writerow(["SUMMARY"])
        w.writerow(["Period", "Total Incidents", "Resolved", "Open / Unresolved",
                    "Average MTTR (hrs)", "Average MTTR (d hh:mm)",
                    "Average Time to Detect (hrs)",
                    "Average Time to Detect (d hh:mm)"])
        for m in months:
            label = f"{calendar.month_name[m]} {year}"
            w.writerow(summarise(label, [r for r in rows if r["month"] == label])[0])
        overall_label = (f"Overall ({calendar.month_abbr[months[0]]}-"
                         f"{calendar.month_abbr[months[-1]]} {year})")
        line, overall_mttr = summarise(overall_label, rows)
        w.writerow(line)

        if len(prefixes) > 1:
            w.writerow([])
            w.writerow(["SUMMARY BY PREFIX"])
            w.writerow(["Prefix", "Total Incidents", "Resolved",
                        "Open / Unresolved", "Average MTTR (hrs)",
                        "Average MTTR (d hh:mm)",
                        "Average Time to Detect (hrs)",
                        "Average Time to Detect (d hh:mm)"])
            for p in prefixes:
                w.writerow(summarise(p, [r for r in rows if r["prefix"] == p])[0])

        w.writerow([])
        quoted = ", ".join(f'"{p}"' for p in prefixes)
        w.writerow([f"Incidents whose {prefix_field} starts with any of: "
                    f"{quoted}; filtered on Submit Date."])
        w.writerow([f"Time to Detect = Submit Date - {detect_field}; "
                    f"Time to Resolve = Last Resolved Date - Submit Date."])
        w.writerow(["MTTR averages resolved incidents only; open incidents "
                    "are counted but excluded from the average."])
    return overall_mttr


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="BMC Remedy incident MTTR report (CSV). "
                    "Values come from the CONFIGURATION section at the top "
                    "of this file; these options override them for one run.")
    parser.add_argument("--year", type=int, default=YEAR,
                        help=f"year to report on (default: {YEAR})")
    parser.add_argument("--months", type=int, nargs="+", default=MONTHS,
                        help=f"month numbers (default: {' '.join(map(str, MONTHS))})")
    parser.add_argument("--output", default=OUTPUT_FILE,
                        help="output .csv path (default: timestamped name)")
    args = parser.parse_args()

    host = BMC_URL.strip().rstrip("/")
    username = BMC_USERNAME.strip()
    password = BMC_PASSWORD
    if (not host or "example.com" in host or not username
            or username == "your_username"):
        sys.exit("Edit the CONFIGURATION section at the top of this script: "
                 "set BMC_URL, BMC_USERNAME and BMC_PASSWORD.")
    if not host.lower().startswith(("http://", "https://")):
        host = "https://" + host
    if not password or password == "your_password":
        password = getpass.getpass(f"Remedy password for {username}: ")

    prefixes = INCIDENT_PREFIXES
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    prefixes = list(dict.fromkeys(p for p in prefixes if p and p.strip()))
    if not prefixes:
        sys.exit("INCIDENT_PREFIXES is empty - add at least one prefix.")
    prefix_field = PREFIX_FIELD
    detect_field = DETECT_FIELD
    ctx = ssl_context(VERIFY_TLS)
    tz = resolve_timezone(TIMEZONE)

    months = sorted(set(args.months))
    if any(m < 1 or m > 12 for m in months):
        sys.exit("MONTHS must be between 1 and 12.")
    output = args.output or (f"incident_mttr_report_"
                             f"{datetime.now():%Y%m%d_%H%M%S}.csv")
    print(f"Connecting to {host} as {username}")
    print(f"Prefixes on '{prefix_field}': " + ", ".join(prefixes))

    fields = ["Incident Number", "Description", "Status", "Priority",
              "Submit Date", "Last Resolved Date", detect_field]
    if prefix_field not in fields:
        fields.append(prefix_field)

    token = login(host, username, password, ctx)
    try:
        entries = []
        for m in months:
            start = datetime(args.year, m, 1, tzinfo=tz)
            end = (datetime(args.year + 1, 1, 1, tzinfo=tz) if m == 12
                   else datetime(args.year, m + 1, 1, tzinfo=tz))
            print(f"Querying {calendar.month_name[m]} {args.year}...")
            entries.extend(fetch_incidents(
                host, token,
                build_qualification(prefix_field, prefixes, start, end),
                fields, ctx,
            ))
    finally:
        logout(host, token, ctx)

    rows = build_rows(entries, detect_field, prefix_field, prefixes, tz)
    overall_mttr = write_report(rows, months, args.year, detect_field,
                                prefixes, prefix_field, output)

    print(f"\n{len(rows)} incident(s) found.")
    for p in prefixes:
        print(f'  "{p}" -> {sum(1 for r in rows if r["prefix"] == p)}')
    print(f"Average MTTR: {fmt_duration(overall_mttr) or 'n/a'}"
          + (f" ({overall_mttr} hrs)" if overall_mttr is not None else ""))
    print(f"Report written to {output}")


if __name__ == "__main__":
    main()
