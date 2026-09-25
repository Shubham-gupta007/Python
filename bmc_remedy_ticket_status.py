#!/usr/bin/env python3

"""
BMC Remedy (Helix ITSM) - Incident Ticket Status Checker

Looks up the current status of one or many BMC Remedy incident
tickets (INC numbers) through the AR System REST API.


Login flow (JWT):

    1. POST {REMEDY_URL}/api/jwt/login
           Content-Type: application/x-www-form-urlencoded
           body: username=<user>&password=<password>

       On success (HTTP 200) the response BODY is the raw JWT token
       as plain text - it is NOT wrapped in JSON.

    2. Every following request sends the token in the header:

           Authorization: AR-JWT <token>

       (note the "AR-JWT" scheme - "Bearer" is rejected by Remedy)

    3. POST {REMEDY_URL}/api/jwt/logout  (same header) when done,
       so the token is invalidated on the server.

    Tokens expire (1 hour by default on AR System). This script:
        - refreshes the token proactively before it gets that old
        - re-logs in once and retries if Remedy answers 401 anyway


Ticket lookup:

    GET {REMEDY_URL}/api/arsys/v1/entry/HPD:Help Desk
        ?q='Incident Number'="INC000000000001" OR 'Incident Number'="..."
        &fields=values(Incident Number,Status,...)

    Incidents are queried in batches (BATCH_SIZE per request) instead
    of one request per ticket, and paging (_links.next) is followed.
    Tickets that Remedy does not return are reported as NOT FOUND.


Input:

    Incident IDs on the command line and/or a file (-f). The file can
    be a CSV with an incident column (header "Incident Number",
    "Incident ID", "Incident", "Ticket", "ID", ... - any case), plain
    text (one ID per line, or comma separated), or a JSON list:

        ["INC000000123456", "INC000000123457"]

    A header-less CSV is also accepted: every cell is read as an ID.


Output:

    A CSV with one row per incident, in input order:

        Incident Number, Status, Status_Reason, Resolution,
        Resolution Category, Last Resolved Date, Priority,
        Assigned Group, Assignee, Last Modified Date, Description

    With -f and no -o, it is written next to the input file as
    <input name>_status.csv. Tickets Remedy does not know are written
    with Status "NOT FOUND"; lookups that failed get Status "ERROR"
    with the reason in the Remarks column.


Requirements:
    Python 3
    requests

Install:
    pip install requests


Environment:

    export REMEDY_URL="https://remedy.example.com:8443"
    export REMEDY_USERNAME="api_user"
    export REMEDY_PASSWORD="********"      # prompted for if not set
    export REMEDY_VERIFY_TLS="true"        # "false" for self-signed certs


Run:

    python3 bmc_remedy_ticket_status.py INC000000123456 INC000000123457
    python3 bmc_remedy_ticket_status.py -f incidents.csv
        -> incidents_status.csv
    python3 bmc_remedy_ticket_status.py -f incidents.csv -o status.csv
    python3 bmc_remedy_ticket_status.py -f incidents.csv -o status.json
"""


import argparse
import csv
import getpass
import json
import os
import re
import sys
import time

import requests


# ============================================================
# CONFIGURATION
# ============================================================

REMEDY_URL = os.environ.get("REMEDY_URL", "")
REMEDY_USERNAME = os.environ.get("REMEDY_USERNAME", "")
REMEDY_PASSWORD = os.environ.get("REMEDY_PASSWORD", "")

# Set REMEDY_VERIFY_TLS=false only if the Remedy certificate cannot
# be validated and you understand the risk.
VERIFY_TLS = os.environ.get(
    "REMEDY_VERIFY_TLS", "true"
).strip().lower() not in ("0", "false", "no")

LOGIN_PATH = "/api/jwt/login"
LOGOUT_PATH = "/api/jwt/logout"
INCIDENT_FORM = "HPD:Help Desk"
ENTRY_PATH = "/api/arsys/v1/entry/" + INCIDENT_FORM

# Fields pulled for every incident.
INCIDENT_FIELDS = [
    "Incident Number",
    "Status",
    "Status_Reason",
    "Resolution",
    "Resolution Category",
    "Last Resolved Date",
    "Priority",
    "Assigned Group",
    "Assignee",
    "Last Modified Date",
    "Description",
]

# Output columns = Remedy fields + our own note for NOT FOUND / ERROR.
OUTPUT_COLUMNS = INCIDENT_FIELDS + ["Remarks"]

# Header names (lower-case) recognised as the incident column in an
# input CSV, most specific first.
INCIDENT_COLUMN_NAMES = (
    "incident number", "incident_number", "incident id", "incident_id",
    "incident", "incident no", "ticket number", "ticket id", "ticket",
    "id",
)

# Incidents per query. Keeps the URL (q=... OR ...) well under
# typical web server / proxy URL length limits.
BATCH_SIZE = 25

# AR System default JWT lifetime is 60 minutes; renew a bit earlier.
TOKEN_MAX_AGE_SECONDS = 55 * 60

REQUEST_TIMEOUT = 60

INCIDENT_ID_PATTERN = re.compile(r"^INC\d+$")


# ============================================================
# ERRORS
# ============================================================

class RemedyError(Exception):
    pass


class RemedyAuthError(RemedyError):
    pass


def remedy_error_text(response):
    """
    Remedy returns errors as a JSON list:

        [{"messageType": "ERROR", "messageText": "...",
          "messageNumber": 623, "messageAppendedText": "..."}]

    Fall back to the raw body if it is anything else.
    """

    try:
        body = response.json()
    except ValueError:
        return response.text.strip() or response.reason

    if isinstance(body, dict):
        body = [body]

    messages = []

    if isinstance(body, list):
        for item in body:
            if not isinstance(item, dict):
                continue
            text = item.get("messageText", "")
            number = item.get("messageNumber")
            appended = item.get("messageAppendedText")
            if number is not None:
                text = "[ARERR {}] {}".format(number, text)
            if appended:
                text += " - " + appended
            if text:
                messages.append(text)

    return "; ".join(messages) or response.text.strip()


# ============================================================
# REMEDY CLIENT
# ============================================================

class RemedyClient:
    """
    Holds one JWT session. Use as a context manager so the token is
    always logged out, even when a lookup fails:

        with RemedyClient(url, user, password) as client:
            client.get_incident_statuses([...])
    """

    def __init__(self, base_url, username, password, verify_tls=True):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.token = None
        self.token_issued_at = 0.0

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.logout()
        self.session.close()

    # --------------------------------------------------------
    # LOGIN / LOGOUT
    # --------------------------------------------------------

    def login(self):
        try:
            response = self.session.post(
                self.base_url + LOGIN_PATH,
                data={
                    "username": self.username,
                    "password": self.password,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise RemedyError(
                "Cannot reach Remedy at {}: {}".format(self.base_url, exc)
            )

        if response.status_code in (401, 403):
            raise RemedyAuthError(
                "Login failed for user '{}': {}".format(
                    self.username, remedy_error_text(response)
                )
            )

        if response.status_code != 200:
            raise RemedyAuthError(
                "Login failed (HTTP {}): {}".format(
                    response.status_code, remedy_error_text(response)
                )
            )

        # The token is the whole plain-text body.
        token = response.text.strip()

        # A login page / HTML error from a proxy would also be 200.
        if not token or token.startswith("<") or " " in token:
            raise RemedyAuthError(
                "Login returned HTTP 200 but no JWT token. Check that "
                "REMEDY_URL points at the AR REST API (e.g. "
                "https://host:8443), not the Mid-Tier web UI."
            )

        self.token = token
        self.token_issued_at = time.monotonic()

    def logout(self):
        if not self.token:
            return

        try:
            self.session.post(
                self.base_url + LOGOUT_PATH,
                headers=self._auth_header(),
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException:
            # Token expires on its own; nothing else to do.
            pass
        finally:
            self.token = None

    def _auth_header(self):
        return {"Authorization": "AR-JWT " + self.token}

    def _ensure_token(self):
        age = time.monotonic() - self.token_issued_at
        if not self.token or age >= TOKEN_MAX_AGE_SECONDS:
            self.logout()
            self.login()

    # --------------------------------------------------------
    # AUTHENTICATED GET
    # --------------------------------------------------------

    def _get(self, url, params=None):
        """
        GET with the JWT header. On 401 (token expired / revoked on
        the server) log in again and retry exactly once.
        """

        self._ensure_token()

        for attempt in (1, 2):
            try:
                response = self.session.get(
                    url,
                    params=params,
                    headers={
                        **self._auth_header(),
                        "Accept": "application/json",
                    },
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as exc:
                raise RemedyError("Request to Remedy failed: {}".format(exc))

            if response.status_code == 401 and attempt == 1:
                self.token = None
                self.login()
                continue

            if response.status_code != 200:
                raise RemedyError(
                    "HTTP {} from Remedy: {}".format(
                        response.status_code, remedy_error_text(response)
                    )
                )

            try:
                return response.json()
            except ValueError:
                raise RemedyError(
                    "Remedy returned a non-JSON response: {}".format(
                        response.text[:200]
                    )
                )

    # --------------------------------------------------------
    # INCIDENT LOOKUP
    # --------------------------------------------------------

    def _query_batch(self, incident_ids):
        qualification = " OR ".join(
            "'Incident Number'=\"{}\"".format(i.replace('"', '""'))
            for i in incident_ids
        )

        params = {
            "q": qualification,
            "fields": "values({})".format(",".join(INCIDENT_FIELDS)),
            "limit": len(incident_ids),
        }

        url = self.base_url + ENTRY_PATH
        entries = []

        while url:
            body = self._get(url, params=params)
            entries.extend(body.get("entries", []))

            # The next link already carries every query parameter.
            url = body.get("_links", {}).get("next", [{}])[0].get("href")
            params = None

        return [entry.get("values", {}) for entry in entries]

    def get_incident_statuses(self, incident_ids):
        """
        Returns {incident_id: values_dict or None}, in input order.
        None means Remedy has no incident with that number.
        A failed batch is recorded as {"error": "..."} for each of
        its tickets so the remaining batches still run.
        """

        results = {i: None for i in incident_ids}

        for start in range(0, len(incident_ids), BATCH_SIZE):
            batch = incident_ids[start:start + BATCH_SIZE]

            try:
                rows = self._query_batch(batch)
            except RemedyAuthError:
                raise
            except RemedyError as exc:
                for incident_id in batch:
                    results[incident_id] = {"error": str(exc)}
                continue

            for values in rows:
                number = (values.get("Incident Number") or "").upper()
                if number in results:
                    results[number] = values

        return results


# ============================================================
# INPUT
# ============================================================

def read_ids_from_file(path):
    with open(path, encoding="utf-8-sig") as handle:
        content = handle.read()

    stripped = content.strip()

    if stripped.startswith("["):
        data = json.loads(stripped)
        return [str(item) for item in data]

    rows = list(csv.reader(stripped.splitlines()))
    if not rows:
        return []

    header = [h.strip().lower() for h in rows[0]]
    for column in INCIDENT_COLUMN_NAMES:
        if column in header:
            index = header.index(column)
            return [row[index] for row in rows[1:] if len(row) > index]

    # No recognised header: an incident-looking cell anywhere in the
    # first row means there is no header at all, so take every cell.
    cells = [cell for row in rows for cell in row]
    if any(INCIDENT_ID_PATTERN.match(c.strip().upper()) for c in rows[0]):
        return cells

    raise ValueError(
        "{}: could not find the incident column. Name it one of: {}".format(
            path, ", ".join('"{}"'.format(c) for c in INCIDENT_COLUMN_NAMES)
        )
    )


def normalize_ids(raw_ids):
    """
    Upper-case, trim and de-duplicate (keeping order). IDs that do
    not look like INC numbers are still queried, with a warning.
    """

    seen = set()
    ids = []

    for raw in raw_ids:
        incident_id = raw.strip().strip('"').upper()
        if not incident_id or incident_id in seen:
            continue
        if not INCIDENT_ID_PATTERN.match(incident_id):
            print(
                "WARNING: '{}' does not look like an incident number "
                "(INC...)".format(incident_id),
                file=sys.stderr,
            )
        seen.add(incident_id)
        ids.append(incident_id)

    return ids


# ============================================================
# OUTPUT
# ============================================================

def build_rows(results):
    rows = []

    for incident_id, values in results.items():
        if values is None:
            rows.append({
                "Incident Number": incident_id,
                "Status": "NOT FOUND",
                "Remarks": "No incident with this number in Remedy",
            })
        elif "error" in values:
            rows.append({
                "Incident Number": incident_id,
                "Status": "ERROR",
                "Remarks": values["error"],
            })
        else:
            row = {field: values.get(field) for field in INCIDENT_FIELDS}
            row["Incident Number"] = incident_id
            rows.append(row)

    return rows


def print_table(rows):
    columns = ["Incident Number", "Status", "Status_Reason",
               "Resolution Category", "Assigned Group"]

    def cell(value):
        return "" if value is None else str(value)

    widths = {
        c: max(len(c), *(len(cell(r.get(c))) for r in rows)) for c in columns
    }

    print("  ".join(c.ljust(widths[c]) for c in columns))
    print("  ".join("-" * widths[c] for c in columns))
    for row in rows:
        print("  ".join(cell(row.get(c)).ljust(widths[c]) for c in columns))


def save_rows(rows, path):
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=2)
        return

    # utf-8-sig so Excel shows non-ASCII text correctly. Multi-line
    # Resolution text is quoted by the csv module and stays in one cell.
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                c: "" if row.get(c) is None else row.get(c)
                for c in OUTPUT_COLUMNS
            })


# ============================================================
# MAIN
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Get the status of BMC Remedy incident tickets."
    )
    parser.add_argument(
        "incidents", nargs="*",
        help="Incident numbers, e.g. INC000000123456",
    )
    parser.add_argument(
        "-f", "--file",
        help="File with incident numbers (csv, txt or json list)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results to this file (.csv or .json). Default with "
             "-f: <input name>_status.csv next to the input file",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    raw_ids = list(args.incidents)
    if args.file:
        try:
            raw_ids.extend(read_ids_from_file(args.file))
        except (OSError, ValueError) as exc:
            print("ERROR: {}".format(exc), file=sys.stderr)
            return 2
        if not args.output:
            args.output = os.path.splitext(args.file)[0] + "_status.csv"

    incident_ids = normalize_ids(raw_ids)
    if not incident_ids:
        print("No incident numbers given. See --help.", file=sys.stderr)
        return 2

    missing = [
        name for name, value in (
            ("REMEDY_URL", REMEDY_URL),
            ("REMEDY_USERNAME", REMEDY_USERNAME),
        ) if not value
    ]
    if missing:
        print(
            "Missing environment variable(s): " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    password = REMEDY_PASSWORD or getpass.getpass(
        "Remedy password for {}: ".format(REMEDY_USERNAME)
    )

    if not VERIFY_TLS:
        requests.packages.urllib3.disable_warnings()

    try:
        with RemedyClient(
            REMEDY_URL, REMEDY_USERNAME, password, VERIFY_TLS
        ) as client:
            results = client.get_incident_statuses(incident_ids)
    except RemedyError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1

    rows = build_rows(results)
    print_table(rows)

    if args.output:
        save_rows(rows, args.output)
        print("\nSaved {} ticket(s) to {}".format(len(rows), args.output))

    failed = sum(1 for r in rows if r["Status"] == "ERROR")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
