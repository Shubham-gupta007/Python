#!/usr/bin/env python3
"""
Splunk SOAR playbook execution report.

Pulls playbook run history from the Splunk SOAR REST API for a list of
playbooks and a time range, then builds an Excel workbook with two sheets:
  1. Event Executions - every playbook run, with the event (container) ID it ran on
  2. Success Summary  - runs, successes, failures and success rate per playbook
and emails the workbook over SMTP.

Uses only the Python standard library (no pip installs). Edit the
CONFIGURATION section below, then run:
    python soar_playbook_report.py
"""

import json
import logging
import os
import re
import smtplib
import ssl
import sys
import zipfile
from collections import Counter
from datetime import datetime, time, timedelta, timezone
from email.message import EmailMessage
from html import escape
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from xml.sax.saxutils import escape as xml_escape

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

# ---- Report time range ------------------------------------------------------
# Runs whose start time falls between START_TIME and END_TIME (both inclusive).
# Format: "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD" (a date-only END_TIME covers
# that whole day). Times are UTC unless you add an offset, e.g.
# "2026-10-01 00:00:00+05:30".
# Leave START_TIME empty to use END_TIME minus LOOKBACK_DAYS.
# Leave END_TIME empty to use the current time.
START_TIME = "2026-10-01 00:00:00"
END_TIME = "2026-10-31 23:59:59"
LOOKBACK_DAYS = 7

# ---- Output -----------------------------------------------------------------
OUTPUT_DIR = "reports"   # folder the .xlsx report is written to
SEND_EMAIL = True        # False = only write the report file, don't email it
# True = also log the exact REST requests and, for every playbook ID with runs in
# the time window, its name, version, run count and whether it was counted. Use it
# when the counts in the report differ from what you see in SOAR.
DEBUG = False

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

EXECUTION_SHEET = "Event Executions"
EXECUTION_COLUMNS = [
    "Event ID",
    "Playbook",
    "Playbook Version",
    "Run ID",
    "Status",
    "Start Time (UTC)",
    "End Time (UTC)",
    "Duration (s)",
]

SUMMARY_SHEET = "Success Summary"
SUMMARY_COLUMNS = [
    "Playbook",
    "Events",
    "Total Runs",
    "Succeeded",
    "Failed",
    "In Progress / Other",
    "Success Rate (%)",
    "Avg Duration (s)",
    "Last Run (UTC)",
    "Notes",
]
TOTAL_ROW_NAME = "ALL PLAYBOOKS"

COMPLETED_STATUSES = ("success", "failed")
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
XLSX_MIME = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def soar_auth_token():
    return SOAR_AUTH_TOKEN or os.environ.get("SOAR_AUTH_TOKEN", "")


def smtp_password():
    return SMTP_PASSWORD or os.environ.get("SMTP_PASSWORD", "")


class SoarHTTPError(RuntimeError):
    """SOAR answered with an HTTP error status."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


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
        log.debug("GET %s", url)
        req = Request(url, headers={"ph-auth-token": self.auth_token, "Accept": "application/json"})
        try:
            with urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                body = resp.read().decode("utf-8")
        except HTTPError as e:
            if e.code == 401:
                raise SoarHTTPError(401, "SOAR rejected the auth token (HTTP 401); check the ph-auth-token")
            detail = e.read().decode("utf-8", errors="replace")[:300]
            raise SoarHTTPError(e.code, f"SOAR request failed with HTTP {e.code} for {url}: {detail}")
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
        page = fetched = 0
        while True:
            params["page"] = page
            body = self.get(endpoint, params)
            data = body.get("data", [])
            fetched += len(data)
            yield from data
            page += 1
            num_pages = body.get("num_pages")
            if not data or (page >= num_pages if num_pages is not None else len(data) < self.page_size):
                break
        if body.get("count") is not None and fetched != body["count"]:
            log.warning("SOAR reported %s %s records but %s were downloaded", body["count"], endpoint, fetched)

    def playbook(self, playbook_id):
        """The playbook record for an id (any version), or None if SOAR no longer has it."""
        try:
            return self.get(f"playbook/{playbook_id}")
        except SoarHTTPError as e:
            if e.code in (403, 404):
                return None
            raise

    def find_playbooks(self, full_name):
        """Return the current playbook record(s) matching "name" or "repo/name" (e.g. "local/my_playbook")."""
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


def time_filter(start, end):
    """SOAR filter for runs whose start_time is between `start` and `end` (UTC, inclusive)."""
    return {
        "_filter_start_time__gte": json.dumps(start.strftime("%Y-%m-%dT%H:%M:%S")),
        # .999999 so an END_TIME like 23:59:59 also includes runs during that last second.
        "_filter_start_time__lte": json.dumps(end.strftime("%Y-%m-%dT%H:%M:%S") + ".999999"),
    }


# ---- Time handling ----------------------------------------------------------

def parse_time(value):
    """Parse a SOAR timestamp such as "2026-10-29T07:36:41.728895Z"."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_user_time(value, setting, end_of_day=False):
    """Parse a START_TIME / END_TIME value into an aware UTC datetime."""
    value = value.strip()
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            f"{setting} {value!r} is not a valid time; use 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DD'"
        )
    if end_of_day and len(value) == 10:  # date only, e.g. "2026-10-31"
        dt = datetime.combine(dt.date(), time(23, 59, 59))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def resolve_time_range(start_value, end_value, lookback_days):
    end = parse_user_time(end_value, "END_TIME", end_of_day=True) if end_value else datetime.now(timezone.utc)
    start = parse_user_time(start_value, "START_TIME") if start_value else end - timedelta(days=lookback_days)
    if start >= end:
        raise ValueError(f"START_TIME ({start:{TIME_FORMAT}}) must be before END_TIME ({end:{TIME_FORMAT}})")
    return start, end


def fmt_time(dt):
    return dt.strftime(TIME_FORMAT) if dt else ""


# ---- Report building --------------------------------------------------------

def execution_row(playbook_name, playbook_version, run):
    """One row of the Event Executions sheet."""
    status = (run.get("status") or "unknown").lower()
    started = parse_time(run.get("start_time"))
    # update_time is when the run last changed, i.e. when it finished for completed runs.
    ended = parse_time(run.get("update_time")) if status in COMPLETED_STATUSES else None
    return {
        "Event ID": run.get("container"),
        "Playbook": playbook_name,
        "Playbook Version": playbook_version,
        "Run ID": run.get("id"),
        "Status": status,
        "Start Time (UTC)": fmt_time(started),
        "End Time (UTC)": fmt_time(ended),
        "Duration (s)": round((ended - started).total_seconds(), 1) if started and ended else "",
    }


def summary_row(name, executions, note=""):
    """One row of the Success Summary sheet, built from that playbook's execution rows."""
    statuses = Counter(e["Status"] for e in executions)
    durations = [e["Duration (s)"] for e in executions if e["Duration (s)"] != ""]
    total = len(executions)
    succeeded = statuses["success"]
    failed = statuses["failed"]
    completed = succeeded + failed
    return {
        "Playbook": name,
        "Events": len({e["Event ID"] for e in executions if e["Event ID"] is not None}),
        "Total Runs": total,
        "Succeeded": succeeded,
        "Failed": failed,
        "In Progress / Other": total - completed,
        # Success rate is over completed runs, so runs still in progress don't drag it down.
        "Success Rate (%)": round(succeeded / completed * 100, 2) if completed else "N/A",
        "Avg Duration (s)": round(sum(durations) / len(durations), 1) if durations else "N/A",
        # TIME_FORMAT strings sort chronologically, so max() is the latest run.
        "Last Run (UTC)": max((e["Start Time (UTC)"] for e in executions), default=""),
        "Notes": note,
    }


def build_report(client, playbook_names, start, end):
    """Return (execution rows, summary rows) for the given playbooks and time range.

    SOAR keeps every saved version of a playbook as a separate playbook record
    with its own id, and each run points at the id of the version that ran. So
    runs are matched by the playbook's repo and name, not by the current id.
    """
    scm_names = {s["id"]: s["name"] for s in client.get_all("scm")}
    wanted = {}  # configured name -> (repo or "", playbook name)
    for full_name in playbook_names:
        repo, _, name = full_name.strip().rpartition("/")
        wanted[full_name] = (repo, name)

    playbooks = {}            # playbook id -> playbook record, None if SOAR no longer has it
    rows_by_name = {full_name: [] for full_name in playbook_names}
    ids_by_name = {full_name: set() for full_name in playbook_names}
    runs_per_id = Counter()

    log.info("Downloading playbook runs in the window")
    for run in client.get_all("playbook_run", time_filter(start, end)):
        pb_id = run.get("playbook")
        runs_per_id[pb_id] += 1
        if pb_id not in playbooks:
            playbooks[pb_id] = client.playbook(pb_id)
        pb = playbooks[pb_id]
        if not pb:
            continue
        repo = scm_names.get(pb.get("scm"), "")
        for full_name, (want_repo, want_name) in wanted.items():
            if pb.get("name") == want_name and (not want_repo or want_repo == repo):
                rows_by_name[full_name].append(execution_row(full_name, pb.get("version", ""), run))
                ids_by_name[full_name].add(pb_id)

    if DEBUG:
        log.debug("Runs in the window for ALL playbooks: %s", sum(runs_per_id.values()))
        for pb_id, runs in runs_per_id.most_common():
            pb = playbooks.get(pb_id)
            label = f"{scm_names.get(pb.get('scm'), '?')}/{pb.get('name')} (version {pb.get('version')})" if pb else \
                "(playbook record not found - deleted or no access)"
            counted = [n for n, ids in ids_by_name.items() if pb_id in ids]
            log.debug("  playbook id %-6s %-60s %5s runs  %s", pb_id, label, runs,
                      f"-> counted as {', '.join(counted)}" if counted else "(not in PLAYBOOKS)")

    executions, summary = [], []
    for full_name in playbook_names:
        rows = rows_by_name[full_name]
        ids = sorted(ids_by_name[full_name])
        note = ""
        if len(ids) > 1:
            note = f"Counted across {len(ids)} playbook IDs/versions: {', '.join(map(str, ids))}"
        elif not rows and not client.find_playbooks(full_name):
            log.warning("Playbook not found in SOAR: %s", full_name)
            note = "Playbook not found"
        executions.extend(rows)
        summary.append(summary_row(full_name, rows, note))

    executions.sort(key=lambda e: (e["Event ID"] is None, e["Event ID"] or 0, e["Start Time (UTC)"]))
    summary.append(summary_row(TOTAL_ROW_NAME, executions))
    return executions, summary


# ---- Excel (.xlsx) writer, standard library only ----------------------------

_ILLEGAL_XML_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _column_letter(index):
    """0 -> A, 25 -> Z, 26 -> AA."""
    letters = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _cell_xml(ref, value, style=0):
    style_attr = f' s="{style}"' if style else ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    text = xml_escape(_ILLEGAL_XML_CHARS.sub("", "" if value is None else str(value)))
    return f'<c r="{ref}"{style_attr} t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def _sheet_xml(columns, rows, bold_last_row=False):
    widths = [len(c) for c in columns]
    for row in rows:
        for i, c in enumerate(columns):
            widths[i] = max(widths[i], len(str(row.get(c, ""))))
    cols_xml = "".join(
        f'<col min="{i + 1}" max="{i + 1}" width="{min(w + 3, 70)}" customWidth="1"/>' for i, w in enumerate(widths)
    )

    lines = ["<row r=\"1\">" + "".join(_cell_xml(f"{_column_letter(i)}1", c, style=1) for i, c in enumerate(columns)) + "</row>"]
    for r, row in enumerate(rows, start=2):
        style = 2 if bold_last_row and r == len(rows) + 1 else 0
        cells = "".join(_cell_xml(f"{_column_letter(i)}{r}", row.get(c), style) for i, c in enumerate(columns))
        lines.append(f'<row r="{r}">{cells}</row>')

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        f"<cols>{cols_xml}</cols>"
        f"<sheetData>{''.join(lines)}</sheetData>"
        "</worksheet>"
    )


_STYLES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
    '<fills count="3"><fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFD9E1F2"/><bgColor indexed="64"/></patternFill></fill></fills>'
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
    '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    "</styleSheet>"
)


def write_xlsx(path, sheets):
    """Write an .xlsx workbook. `sheets` is a list of (sheet name, columns, rows, bold_last_row)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    count = len(sheets)
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + "".join(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            for i in range(1, count + 1)
        )
        + "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
        + "".join(
            f'<sheet name="{xml_escape(name[:31])}" sheetId="{i}" r:id="rId{i}"/>'
            for i, (name, *_) in enumerate(sheets, start=1)
        )
        + "</sheets></workbook>"
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(
            f'<Relationship Id="rId{i}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{i}.xml"/>'
            for i in range(1, count + 1)
        )
        + f'<Relationship Id="rId{count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/></Relationships>'
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/styles.xml", _STYLES_XML)
        for i, (_, columns, rows, bold_last_row) in enumerate(sheets, start=1):
            zf.writestr(f"xl/worksheets/sheet{i}.xml", _sheet_xml(columns, rows, bold_last_row))


# ---- Email ------------------------------------------------------------------

def overall_summary(summary):
    total = summary[-1]  # the ALL PLAYBOOKS row
    rate = total["Success Rate (%)"]
    return (
        f"{total['Total Runs']} runs on {total['Events']} events across {len(summary) - 1} playbooks, "
        f"overall success rate {rate if rate == 'N/A' else f'{rate}%'}"
    )


def build_email(summary, report_path, period):
    headline = overall_summary(summary)

    text_lines = [f"Splunk SOAR playbook execution report for {period}", headline, ""]
    for r in summary[:-1]:
        rate = r["Success Rate (%)"]
        text_lines.append(
            f"- {r['Playbook']}: {r['Total Runs']} runs on {r['Events']} events, {r['Succeeded']} succeeded, "
            f"{r['Failed']} failed, success rate {rate if rate == 'N/A' else f'{rate}%'}"
        )
    text_lines += [
        "",
        "Success rate = succeeded / (succeeded + failed).",
        f"Attached workbook: sheet '{EXECUTION_SHEET}' lists every run by event ID, "
        f"sheet '{SUMMARY_SHEET}' has the success rate per playbook.",
    ]

    header_html = "".join(
        f'<th style="border:1px solid #ccc;padding:6px;background:#d9e1f2;text-align:left">{escape(c)}</th>'
        for c in SUMMARY_COLUMNS
    )
    bold = ' style="font-weight:bold"'
    rows_html = "".join(
        f"<tr{bold if r['Playbook'] == TOTAL_ROW_NAME else ''}>"
        + "".join(f'<td style="border:1px solid #ccc;padding:6px">{escape(str(r[c]))}</td>' for c in SUMMARY_COLUMNS)
        + "</tr>"
        for r in summary
    )
    html = f"""\
<html><body style="font-family:Arial,sans-serif;font-size:14px">
<p>Splunk SOAR playbook execution report for <b>{escape(period)}</b></p>
<p>{escape(headline)}</p>
<table style="border-collapse:collapse">
<tr>{header_html}</tr>
{rows_html}
</table>
<p style="color:#666">Success rate = succeeded / (succeeded + failed); runs still in progress are excluded.<br>
Attached workbook: sheet <b>{escape(EXECUTION_SHEET)}</b> lists every run by event ID,
sheet <b>{escape(SUMMARY_SHEET)}</b> has the success rate per playbook.</p>
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
    with open(report_path, "rb") as f:
        msg.add_attachment(f.read(), maintype=XLSX_MIME[0], subtype=XLSX_MIME[1], filename=os.path.basename(report_path))
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


# ---- Main -------------------------------------------------------------------

def check_config():
    problems = []
    if not SOAR_BASE_URL:
        problems.append("SOAR_BASE_URL is empty")
    if not soar_auth_token():
        problems.append("SOAR auth token missing: set SOAR_AUTH_TOKEN at the top of the script or as an env var")
    if not PLAYBOOKS:
        problems.append("PLAYBOOKS is empty")
    if SEND_EMAIL:
        if not SMTP_HOST:
            problems.append("SMTP_HOST is empty")
        if not EMAIL_FROM:
            problems.append("EMAIL_FROM is empty")
        if not EMAIL_TO:
            problems.append("EMAIL_TO is empty")
    if problems:
        raise ValueError("Configuration problem: " + "; ".join(problems))


def main():
    logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        check_config()
        start, end = resolve_time_range(START_TIME, END_TIME, LOOKBACK_DAYS)
        period = f"{start:{TIME_FORMAT}} to {end:{TIME_FORMAT}} UTC"
        log.info("Reporting on runs started from %s", period)

        client = SoarClient(
            SOAR_BASE_URL,
            soar_auth_token(),
            verify_ssl=SOAR_VERIFY_SSL,
            timeout=SOAR_TIMEOUT,
            page_size=SOAR_PAGE_SIZE,
        )
        executions, summary = build_report(client, PLAYBOOKS, start, end)

        report_path = os.path.join(OUTPUT_DIR, f"soar_playbook_report_{start:%Y%m%d_%H%M}_to_{end:%Y%m%d_%H%M}.xlsx")
        write_xlsx(report_path, [
            (EXECUTION_SHEET, EXECUTION_COLUMNS, executions, False),
            (SUMMARY_SHEET, SUMMARY_COLUMNS, summary, True),
        ])
        log.info("Report written to %s (%s)", report_path, overall_summary(summary))

        if not SEND_EMAIL:
            return 0
        send_email(build_email(summary, report_path, period))
        log.info("Report emailed to %s", ", ".join(EMAIL_TO + EMAIL_CC))
        return 0

    except (ValueError, RuntimeError, OSError, smtplib.SMTPException) as e:
        log.error("%s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
