# Splunk SOAR Playbook Execution Report

`soar_playbook_report.py` reads playbook run history from the Splunk SOAR REST API
for a list of playbooks and a time range. It builds an Excel workbook with two
sheets, then emails the workbook over SMTP.

It uses only the Python standard library (Python 3.7+), so you don't need to
install anything with `pip`.

## Report sheets

**Sheet 1: Event Executions.** One row per playbook run, sorted by event ID.

| Column | Meaning |
|---|---|
| Event ID | The SOAR event (container) the playbook ran on |
| Playbook | Name as listed in `PLAYBOOKS` |
| Run ID | The playbook run's ID |
| Status | `success`, `failed`, `running`, ... |
| Start Time (UTC) / End Time (UTC) | When the run started and finished (blank while running) |
| Duration (s) | End minus start, for finished runs |

**Sheet 2: Success Summary.** One row per playbook, plus an **ALL PLAYBOOKS** total row.

| Column | Meaning |
|---|---|
| Playbook | Name as listed in `PLAYBOOKS` (`name` or `repo/name`) |
| Events | Number of distinct events the playbook ran on |
| Total Runs | Runs started inside the time range |
| Succeeded / Failed | Runs with status `success` / `failed` |
| In Progress / Other | Runs that have not finished yet (for example `running`) |
| Success Rate (%) | `succeeded / (succeeded + failed) * 100`. Unfinished runs are left out |
| Avg Duration (s) | Average run time of finished runs |
| Last Run (UTC) | Start time of the most recent run |
| Notes | For example "Playbook not found" or "Combined N playbooks with this name" |

The email has the summary table in its body and the workbook attached. The
workbook is written with the standard library (`zipfile`), so it needs no
Excel library.

## Setup

1. In SOAR, create an **automation user** (Administration > User Management) and
   give it a role that can view playbooks and playbook runs. Copy its
   `ph-auth-token`.
2. Open `soar_playbook_report.py` and edit the **CONFIGURATION** section at the top:

| Setting | What to put there |
|---|---|
| `SOAR_BASE_URL` | Your SOAR URL, for example `https://soar.company.com` |
| `SOAR_AUTH_TOKEN` | The automation user's token, or `""` to read the `SOAR_AUTH_TOKEN` env var |
| `SOAR_VERIFY_SSL` | `True`, `False` (self-signed certificate; not recommended), or the path to a CA bundle file |
| `PLAYBOOKS` | Playbooks to report on. `repo/name` (for example `local/my_playbook`) picks one repo. A bare `name` matches every repo and combines their runs into one row |
| `START_TIME`, `END_TIME` | Time range of the report, see below |
| `LOOKBACK_DAYS` | Used only when `START_TIME` is empty: the range starts this many days before `END_TIME` |
| `OUTPUT_DIR` | Folder the `.xlsx` report is written to |
| `SEND_EMAIL` | `True` to email the report, `False` to only write the file |
| `SMTP_HOST`, `SMTP_PORT` | Your mail server |
| `SMTP_USE_TLS` / `SMTP_USE_SSL` | Port 587: `SMTP_USE_TLS = True` (STARTTLS). Port 465: `SMTP_USE_SSL = True` |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | SMTP login. Leave `SMTP_USERNAME = ""` if your relay does not need one. Leave `SMTP_PASSWORD = ""` to read the `SMTP_PASSWORD` env var |
| `EMAIL_FROM`, `EMAIL_TO`, `EMAIL_CC`, `EMAIL_SUBJECT` | Sender, recipient lists, and subject line |

### Time range

The report includes runs whose **start time** is between `START_TIME` and
`END_TIME`, both inclusive. For example, for October 2026:

```python
START_TIME = "2026-10-01 00:00:00"
END_TIME = "2026-10-31 23:59:59"
```

Accepted values:

| Value | Meaning |
|---|---|
| `"2026-10-01 00:00:00"` | Exact time, UTC |
| `"2026-10-01"` | Date only. For `START_TIME` this is 00:00:00. For `END_TIME` it covers the whole day, up to 23:59:59 |
| `"2026-10-01 09:00:00+05:30"` | Time with a UTC offset (here IST). It is converted to UTC |
| `""` (empty) | `END_TIME`: now. `START_TIME`: `END_TIME` minus `LOOKBACK_DAYS` |

SOAR stores times in UTC, so the report shows UTC times.

If you don't want the token and password stored in the file, leave them empty
and set them as environment variables:

```bash
export SOAR_AUTH_TOKEN='...'
export SMTP_PASSWORD='...'
```

## Run

```bash
python soar_playbook_report.py
```

All settings come from the CONFIGURATION section, so the script takes no
command-line options. The report is saved as
`OUTPUT_DIR/soar_playbook_report_<start>_to_<end>.xlsx`.

The script exits with code 1 on any error (bad token, SOAR unreachable, SMTP
failure, and so on), so a scheduler can catch the failure.

## Schedule it (weekly, Monday 08:00)

For a recurring report, leave `START_TIME` and `END_TIME` empty so each run
covers the last `LOOKBACK_DAYS` days.

```cron
0 8 * * 1 cd /opt/soar-report && /usr/bin/python3 soar_playbook_report.py >> report.log 2>&1
```

## REST endpoints used

- `GET /rest/scm?_filter_name="<repo>"`: resolves a repo name to its id
- `GET /rest/playbook?_filter_name="<name>"&_filter_scm=<id>`: resolves a playbook to its id(s)
- `GET /rest/playbook_run?_filter_playbook=<id>&_filter_start_time__gte="<start>"&_filter_start_time__lte="<end>"`:
  run history, read page by page (`page`, `page_size`). Each run's `container`
  field is the event ID

The script counts statuses itself, so it does not depend on the server
filtering by status.
