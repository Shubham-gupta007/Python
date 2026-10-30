# Splunk SOAR Playbook Execution Report

`soar_playbook_report.py` reads playbook run history from the Splunk SOAR REST API
for a list of playbooks. It writes a CSV with the number of executions and the
success rate of each playbook, then emails the CSV over SMTP.

It uses only the Python standard library (Python 3.7+), so you don't need to
install anything with `pip`.

## Report columns

| Column | Meaning |
|---|---|
| Playbook | Name as listed in `PLAYBOOKS` (`name` or `repo/name`) |
| Total Runs | Runs started inside the look-back window |
| Succeeded / Failed | Runs with status `success` / `failed` |
| In Progress / Other | Runs that have not finished yet (for example `running`) |
| Success Rate (%) | `succeeded / (succeeded + failed) * 100`. Unfinished runs are left out |
| Avg Duration (s) | Average of `update_time - start_time` over finished runs |
| Last Run (UTC) | Start time of the most recent run |
| Notes | For example "Playbook not found" or "Combined N playbooks with this name" |

The email has the same table in its body, plus an overall success rate, and
the CSV attached.

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
| `LOOKBACK_DAYS` | Report window in days |
| `OUTPUT_DIR` | Folder the CSV is written to |
| `SMTP_HOST`, `SMTP_PORT` | Your mail server |
| `SMTP_USE_TLS` / `SMTP_USE_SSL` | Port 587: `SMTP_USE_TLS = True` (STARTTLS). Port 465: `SMTP_USE_SSL = True` |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | SMTP login. Leave `SMTP_USERNAME = ""` if your relay does not need one. Leave `SMTP_PASSWORD = ""` to read the `SMTP_PASSWORD` env var |
| `EMAIL_FROM`, `EMAIL_TO`, `EMAIL_CC`, `EMAIL_SUBJECT` | Sender, recipient lists, and subject line |

If you don't want the token and password stored in the file, leave them empty
and set them as environment variables:

```bash
export SOAR_AUTH_TOKEN='...'
export SMTP_PASSWORD='...'
```

## Run

```bash
python soar_playbook_report.py                          # CSV + email
python soar_playbook_report.py --no-email               # CSV only
python soar_playbook_report.py --days 30                # override LOOKBACK_DAYS
python soar_playbook_report.py --playbooks local/pb_a community/pb_b   # override PLAYBOOKS
```

The script exits with code 1 on any error (bad token, SOAR unreachable, SMTP
failure, and so on), so a scheduler can catch the failure.

## Schedule it (weekly, Monday 08:00)

```cron
0 8 * * 1 cd /opt/soar-report && /usr/bin/python3 soar_playbook_report.py >> report.log 2>&1
```

## REST endpoints used

- `GET /rest/scm?_filter_name="<repo>"`: resolves a repo name to its id
- `GET /rest/playbook?_filter_name="<name>"&_filter_scm=<id>`: resolves a playbook to its id(s)
- `GET /rest/playbook_run?_filter_playbook=<id>&_filter_start_time__gte="<UTC time>"`:
  run history, read page by page (`page`, `page_size`)

The script counts statuses itself, so it does not depend on the server
filtering by status.
