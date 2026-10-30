#!/usr/bin/env python3
"""
Splunk SOAR playbook execution report.

Pulls playbook run history from the Splunk SOAR REST API for a list of
playbooks, writes a CSV with the number of executions and the success rate
of each one, and emails the CSV over SMTP.

Usage:
    python soar_playbook_report.py --config config.json
    python soar_playbook_report.py --config config.json --days 30 --no-email
    python soar_playbook_report.py --config config.json --playbooks local/pb_one community/pb_two

Secrets can be kept out of the config file with environment variables:
    SOAR_AUTH_TOKEN   ph-auth-token of a SOAR automation user
    SMTP_PASSWORD     password for the SMTP login
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

import requests
import urllib3

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


class SoarClient:
    """Minimal Splunk SOAR REST client authenticated with a ph-auth-token."""

    def __init__(self, base_url, auth_token, verify_ssl=True, timeout=60, page_size=500):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.page_size = page_size
        self.session = requests.Session()
        self.session.headers.update({"ph-auth-token": auth_token, "Accept": "application/json"})
        # verify_ssl may be True, False, or a path to a CA bundle.
        self.session.verify = verify_ssl
        if verify_ssl is False:
            log.warning("TLS certificate verification is disabled for SOAR requests")
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, endpoint, params=None):
        url = f"{self.base_url}/rest/{endpoint.lstrip('/')}"
        resp = self.session.get(url, params=params, timeout=self.timeout)
        if resp.status_code == 401:
            raise RuntimeError("SOAR rejected the auth token (HTTP 401); check the ph-auth-token")
        resp.raise_for_status()
        return resp.json()

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


def build_email(smtp_cfg, rows, csv_path, period):
    summary = overall_summary(rows)
    subject = f"{smtp_cfg.get('subject', 'Splunk SOAR Playbook Execution Report')} ({period})"

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
    msg["Subject"] = subject
    msg["From"] = smtp_cfg["from"]
    msg["To"] = ", ".join(smtp_cfg["to"])
    if smtp_cfg.get("cc"):
        msg["Cc"] = ", ".join(smtp_cfg["cc"])
    msg.set_content("\n".join(text_lines))
    msg.add_alternative(html, subtype="html")
    with open(csv_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="text", subtype="csv", filename=os.path.basename(csv_path))
    return msg


def send_email(smtp_cfg, msg):
    host = smtp_cfg["host"]
    port = int(smtp_cfg.get("port", 587))
    timeout = int(smtp_cfg.get("timeout", 60))
    context = ssl.create_default_context()

    if smtp_cfg.get("use_ssl"):
        server = smtplib.SMTP_SSL(host, port, context=context, timeout=timeout)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)

    with server:
        if not smtp_cfg.get("use_ssl") and smtp_cfg.get("use_tls", True):
            server.starttls(context=context)
        if smtp_cfg.get("username"):
            server.login(smtp_cfg["username"], smtp_cfg.get("password") or "")
        # send_message delivers to every address in the To and Cc headers.
        server.send_message(msg)


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)

    soar = cfg.setdefault("soar", {})
    soar["auth_token"] = os.environ.get("SOAR_AUTH_TOKEN") or soar.get("auth_token")
    smtp = cfg.setdefault("smtp", {})
    smtp["password"] = os.environ.get("SMTP_PASSWORD") or smtp.get("password")

    if not soar.get("base_url"):
        raise ValueError("soar.base_url is missing from the config")
    if not soar.get("auth_token"):
        raise ValueError("SOAR auth token missing: set soar.auth_token or the SOAR_AUTH_TOKEN env var")
    return cfg


def validate_smtp(smtp_cfg):
    missing = [k for k in ("host", "from", "to") if not smtp_cfg.get(k)]
    if missing:
        raise ValueError(f"smtp config is missing: {', '.join(missing)}")
    if isinstance(smtp_cfg["to"], str):
        smtp_cfg["to"] = [smtp_cfg["to"]]
    if isinstance(smtp_cfg.get("cc"), str):
        smtp_cfg["cc"] = [smtp_cfg["cc"]]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Splunk SOAR playbook execution / success-rate report")
    parser.add_argument("-c", "--config", default="config.json", help="path to the JSON config file")
    parser.add_argument("--days", type=int, help="look-back window in days (overrides lookback_days)")
    parser.add_argument("--playbooks", nargs="+", help="playbook names to report on (overrides the config list)")
    parser.add_argument("--output", help="CSV output path (default: <output_dir>/soar_playbook_report_<timestamp>.csv)")
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
        cfg = load_config(args.config)
        playbook_names = args.playbooks or cfg.get("playbooks") or []
        if not playbook_names:
            raise ValueError("No playbooks given: add a \"playbooks\" list to the config or pass --playbooks")
        if not args.no_email:
            validate_smtp(cfg["smtp"])

        days = args.days or int(cfg.get("lookback_days", 7))
        now = datetime.now(timezone.utc)
        since = now - timedelta(days=days)
        period = f"{since:%Y-%m-%d %H:%M} to {now:%Y-%m-%d %H:%M} UTC"

        soar = cfg["soar"]
        client = SoarClient(
            soar["base_url"],
            soar["auth_token"],
            verify_ssl=soar.get("verify_ssl", True),
            timeout=int(soar.get("timeout", 60)),
            page_size=int(soar.get("page_size", 500)),
        )
        rows = build_report_rows(client, playbook_names, since)

        csv_path = args.output or os.path.join(
            cfg.get("output_dir", "reports"), f"soar_playbook_report_{now:%Y%m%d_%H%M%S}.csv"
        )
        write_csv(rows, csv_path)
        log.info("Report written to %s (%s)", csv_path, overall_summary(rows))

        if args.no_email:
            return 0
        send_email(cfg["smtp"], build_email(cfg["smtp"], rows, csv_path, period))
        log.info("Report emailed to %s", ", ".join(cfg["smtp"]["to"] + (cfg["smtp"].get("cc") or [])))
        return 0

    except (ValueError, RuntimeError, OSError, requests.RequestException, smtplib.SMTPException) as e:
        log.error("%s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
