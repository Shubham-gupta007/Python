#!/usr/bin/env python3
"""
Splunk SOAR playbook execution report.

Pulls playbook run history from the Splunk SOAR REST API for a list of
playbooks, writes a CSV with the number of executions and the success rate
of each one, and emails the CSV over SMTP.

Uses only the Python standard library. Edit the CONFIGURATION section below,
then run:
    python soar_playbook_report.py
    python soar_playbook_report.py --days 30 --no-email
    python soar_playbook_report.py --playbooks local/pb_one community/pb_two
"""

import argparse
import csv
import json
import logging
import os
import smtplib
import ssl
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import escape
from itertools import chain
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# =============================================================================
# CONFIGURATION
# =============================================================================

# ---- Splunk SOAR ------------------------------------------------------------
SOAR_BASE_URL = "https://soar.example.com"
# ph-auth-token of a SOAR automation user.
# Leave empty to read it from the SOAR_AUTH_TOKEN environment variable.
SOAR_AUTH_TOKEN = ""
# True, False (self-signed certificate; not recommended) or a path to a CA bundle file.
SOAR_VERIFY_SSL = True
SOAR_TIMEOUT = 60        # seconds per request
SOAR_PAGE_SIZE = 500     # records fetched per page

# Playbooks to report on. "repo/name" picks one repo; a bare "name" matches
# that name in every repo and combines their runs into one row.
PLAYBOOKS = [
    "local/phishing_investigate_and_respond",
    "community/ip_reputation_lookup",
    "malware_triage",
]
LOOKBACK_DAYS = 7        # report window in days
OUTPUT_DIR = "reports"   # folder the CSV is written to

# ---- SMTP -------------------------------------------------------------------
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 587
SMTP_USE_TLS = True      # STARTTLS, usually port 587
SMTP_USE_SSL = False     # implicit SSL, usually port 465 (takes priority over SMTP_USE_TLS)
SMTP_USERNAME = "soar-reports@example.com"   # "" if the server needs no login
# Leave empty to read it from the SMTP_PASSWORD environment variable.
SMTP_PASSWORD = ""
SMTP_TIMEOUT = 60

EMAIL_FROM = "soar-reports@example.com"
EMAIL_TO = ["soc-team@example.com"]
EMAIL_CC = []
EMAIL_SUBJECT = "Splunk SOAR Playbook Execution Report"

# =============================================================================

log = logging.getLogger("soar_playbook_report")

CSV_COLUMNS = [
    "Playbook",
    "Total Runs",
    "Succeeded",
    "Failed",
    "In Progress / Other",
    "Success Rate (%)",
    "Avg Duration (s)",
    "Last Run (UTC)",
    "Notes",
]

COMPLETED_STATUSES = ("success", "failed")


def soar_auth_token():
    return SOAR_AUTH_TOKEN or os.environ.get("SOAR_AUTH_TOKEN", "")


def smtp_password():
    return SMTP_PASSWORD or os.environ.get("SMTP_PASSWORD", "")


class SoarClient:
    """Minimal Splunk SOAR REST client authenticated with a ph-auth-token."""

    def __init__(self, base_url, auth_token, verify_ssl=True, timeout=60, page_size=500):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.timeout = timeout
        self.page_size = page_size
        if isinstance(verify_ssl, str):
            self.ssl_context = ssl.create_default_context(cafile=verify_ssl)
        else:
            self.ssl_context = ssl.create_default_context()
            if not verify_ssl:
                log.warning("TLS certificate verification is disabled for SOAR requests")
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE

    def get(self, endpoint, params=None):
        url = f"{self.base_url}/rest/{endpoint.lstrip('/')}"
        if params:
            url += "?" + urlencode(params)
        req = Request(url, headers={"ph-auth-token": self.auth_token, "Accept": "application/json"})
        try:
            with urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                body = resp.read().decode("utf-8")
        except HTTPError as e:
            if e.code == 401:
                raise RuntimeError("SOAR rejected the auth token (HTTP 401); check the ph-auth-token")
            detail = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"SOAR request failed with HTTP {e.code} for {url}: {detail}")
        except URLError as e:
            raise RuntimeError(f"Could not reach SOAR at {self.base_url}: {e.reason}")
        try:
            return json.loads(body)
        except ValueError:
            raise RuntimeError(f"SOAR returned a non-JSON response for {url}")

    def get_all(self, endpoint, params=None):
        """Yield every record of a list endpoint, following SOAR's 0-based paging."""
        params = dict(params or {})
        params["page_size"] = self.page_size
        page = 0
        while True:
            params["page"] = page
            body = self.get(endpoint, params)
            yield from body.get("data", [])
            page += 1
            if page >= body.get("num_pages", 0):
                break

    def find_playbooks(self, full_name):
        """Return playbook records matching "name" or "repo/name" (e.g. "local/my_playbook")."""
        repo, _, name = full_name.strip().rpartition("/")
        # String filter values must be double-quoted, which json.dumps does (with escaping).
        params = {"_filter_name": json.dumps(name)}
        if repo:
            scms = list(self.get_all("scm", {"_filter_name": json.dumps(repo)}))
            if not scms:
                log.warning("Source control repo %r not found in SOAR", repo)
                return []
            params["_filter_scm"] = scms[0]["id"]
        return list(self.get_all("playbook", params))

    def playbook_runs(self, playbook_id, since):
        """Yield the runs of one playbook that started at or after `since` (UTC)."""
        params = {
            "_filter_playbook": playbook_id,
            "_filter_start_time__gte": json.dumps(since.strftime("%Y-%m-%dT%H:%M:%S")),
        }
        return self.get_all("playbook_run", params)


def parse_time(value):
    """Parse a SOAR timestamp such as "2026-10-29T07:36:41.728895Z"."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def summarize_runs(name, runs, note=""):
    """Reduce an iterable of playbook_run records to one CSV row."""
    statuses = Counter()
    durations = []
    last_start = None

    for run in runs:
        status = (run.get("status") or "unknown").lower()
        statuses[status] += 1
        start = parse_time(run.get("start_time"))
        if start and (last_start is None or start > last_start):
            last_start = start
        end = parse_time(run.get("update_time"))
        if status in COMPLETED_STATUSES and start and end:
            durations.append((end - start).total_seconds())

    total = sum(statuses.values())
    succeeded = statuses["success"]
    failed = statuses["failed"]
    completed = succeeded + failed

    return {
        "Playbook": name,
        "Total Runs": total,
        "Succeeded": succeeded,
        "Failed": failed,
        "In Progress / Other": total - completed,
        # Success rate is over completed runs, so runs still in progress don't drag it down.
        "Success Rate (%)": round(succeeded / completed * 100, 2) if completed else "N/A",
        "Avg Duration (s)": round(sum(durations) / len(durations), 1) if durations else "N/A",
        "Last Run (UTC)": last_start.strftime("%Y-%m-%d %H:%M:%S") if last_start else "",
        "Notes": note,
    }


def build_report_rows(client, playbook_names, since):
    rows = []
    for full_name in playbook_names:
        log.info("Collecting runs for %s", full_name)
        playbooks = client.find_playbooks(full_name)
        if not playbooks:
            log.warning("Playbook not found in SOAR: %s", full_name)
            rows.append(summarize_runs(full_name, [], note="Playbook not found"))
            continue

        note = ""
        if len(playbooks) > 1:
            note = f"Combined {len(playbooks)} playbooks with this name (ids {', '.join(str(p['id']) for p in playbooks)})"
        runs = chain.from_iterable(client.playbook_runs(pb["id"], since) for pb in playbooks)
        rows.append(summarize_runs(full_name, runs, note))
    return rows


def write_csv(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def overall_summary(rows):
    total = sum(r["Total Runs"] for r in rows)
    succeeded = sum(r["Succeeded"] for r in rows)
    completed = succeeded + sum(r["Failed"] for r in rows)
    rate = f"{succeeded / completed * 100:.2f}%" if completed else "N/A"
    return f"{total} runs across {len(rows)} playbooks, overall success rate {rate}"


def build_email(rows, csv_path, period):
    summary = overall_summary(rows)

    text_lines = [f"Splunk SOAR playbook execution report for {period}", summary, ""]
    for r in rows:
        rate = r["Success Rate (%)"]
        text_lines.append(
            f"- {r['Playbook']}: {r['Total Runs']} runs, {r['Succeeded']} succeeded, "
            f"{r['Failed']} failed, success rate {rate if rate == 'N/A' else f'{rate}%'}"
        )
    text_lines += ["", "Success rate = succeeded / (succeeded + failed). Full report attached as CSV."]

    header_html = "".join(
        f'<th style="border:1px solid #ccc;padding:6px;background:#f2f2f2;text-align:left">{escape(c)}</th>'
        for c in CSV_COLUMNS
    )
    rows_html = "".join(
        "<tr>"
        + "".join(f'<td style="border:1px solid #ccc;padding:6px">{escape(str(r[c]))}</td>' for c in CSV_COLUMNS)
        + "</tr>"
        for r in rows
    )
    html = f"""\
<html><body style="font-family:Arial,sans-serif;font-size:14px">
<p>Splunk SOAR playbook execution report for <b>{escape(period)}</b></p>
<p>{escape(summary)}</p>
<table style="border-collapse:collapse">
<tr>{header_html}</tr>
{rows_html}
</table>
<p style="color:#666">Success rate = succeeded / (succeeded + failed); runs still in progress are excluded.
The full report is attached as CSV.</p>
</body></html>
"""

    msg = EmailMessage()
    msg["Subject"] = f"{EMAIL_SUBJECT} ({period})"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    if EMAIL_CC:
        msg["Cc"] = ", ".join(EMAIL_CC)
    msg.set_content("\n".join(text_lines))
    msg.add_alternative(html, subtype="html")
    with open(csv_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="text", subtype="csv", filename=os.path.basename(csv_path))
    return msg


def send_email(msg):
    context = ssl.create_default_context()
    if SMTP_USE_SSL:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT)
    else:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)

    with server:
        if not SMTP_USE_SSL and SMTP_USE_TLS:
            server.starttls(context=context)
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, smtp_password())
        # send_message delivers to every address in the To and Cc headers.
        server.send_message(msg)


def check_config(playbook_names, send_mail):
    problems = []
    if not SOAR_BASE_URL:
        problems.append("SOAR_BASE_URL is empty")
    if not soar_auth_token():
        problems.append("SOAR auth token missing: set SOAR_AUTH_TOKEN at the top of the script or as an env var")
    if not playbook_names:
        problems.append("no playbooks given: fill in PLAYBOOKS or pass --playbooks")
    if send_mail:
        if not SMTP_HOST:
            problems.append("SMTP_HOST is empty")
        if not EMAIL_FROM:
            problems.append("EMAIL_FROM is empty")
        if not EMAIL_TO:
            problems.append("EMAIL_TO is empty")
    if problems:
        raise ValueError("Configuration problem: " + "; ".join(problems))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Splunk SOAR playbook execution / success-rate report")
    parser.add_argument("--days", type=int, help="look-back window in days (overrides LOOKBACK_DAYS)")
    parser.add_argument("--playbooks", nargs="+", help="playbook names to report on (overrides PLAYBOOKS)")
    parser.add_argument("--output", help="CSV output path (default: OUTPUT_DIR/soar_playbook_report_<timestamp>.csv)")
    parser.add_argument("--no-email", action="store_true", help="only write the CSV, don't send it")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        playbook_names = args.playbooks or PLAYBOOKS
        check_config(playbook_names, send_mail=not args.no_email)

        days = args.days or LOOKBACK_DAYS
        now = datetime.now(timezone.utc)
        since = now - timedelta(days=days)
        period = f"{since:%Y-%m-%d %H:%M} to {now:%Y-%m-%d %H:%M} UTC"

        client = SoarClient(
            SOAR_BASE_URL,
            soar_auth_token(),
            verify_ssl=SOAR_VERIFY_SSL,
            timeout=SOAR_TIMEOUT,
            page_size=SOAR_PAGE_SIZE,
        )
        rows = build_report_rows(client, playbook_names, since)

        csv_path = args.output or os.path.join(OUTPUT_DIR, f"soar_playbook_report_{now:%Y%m%d_%H%M%S}.csv")
        write_csv(rows, csv_path)
        log.info("Report written to %s (%s)", csv_path, overall_summary(rows))

        if args.no_email:
            return 0
        send_email(build_email(rows, csv_path, period))
        log.info("Report emailed to %s", ", ".join(EMAIL_TO + EMAIL_CC))
        return 0

    except (ValueError, RuntimeError, OSError, smtplib.SMTPException) as e:
        log.error("%s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
