# Splunk SOAR Playbook Execution Report

`soar_playbook_report.py` reads playbook run history from the Splunk SOAR REST API
for a list of playbooks. It writes a CSV with the number of executions and the
success rate of each playbook, then emails the CSV over SMTP.

## Report columns

| Column | Meaning |
|---|---|
| Playbook | Name as given in the config (`name` or `repo/name`) |
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

```bash
pip install -r requirements.txt
cp config.example.json config.json   # then edit config.json
```

1. In SOAR, create an **automation user** (Administration > User Management) and
   give it a role that can view playbooks and playbook runs. Copy its
   `ph-auth-token`.
2. Edit `config.json`:
   - `soar.base_url`: your SOAR URL, for example `https://soar.company.com`.
   - `soar.verify_ssl`: `true`, `false` (self-signed certificate; not recommended),
     or the path to a CA bundle file.
   - `playbooks`: the playbooks to report on. Use `repo/name` (for example
     `local/my_playbook`) to pick one repo. A bare `name` matches that name in
     every repo, and the runs are combined into one row.
   - `lookback_days`: the report window.
   - `smtp`: server, port, and recipients. For port 587 use `"use_tls": true`
     (STARTTLS). For port 465 use `"use_ssl": true`. Leave `username` empty if
     your relay does not need a login.
3. Keep secrets out of the file with environment variables:

```bash
export SOAR_AUTH_TOKEN='...'
export SMTP_PASSWORD='...'
```

## Run

```bash
python soar_playbook_report.py -c config.json                  # CSV + email
python soar_playbook_report.py -c config.json --no-email       # CSV only
python soar_playbook_report.py -c config.json --days 30        # override the window
python soar_playbook_report.py -c config.json --playbooks local/pb_a community/pb_b
```

The script exits with code 1 on any error (bad token, SMTP failure, and so
on), so a scheduler can catch the failure.

## Schedule it (weekly, Monday 08:00)

```cron
0 8 * * 1 cd /opt/soar-report && SOAR_AUTH_TOKEN=... SMTP_PASSWORD=... /usr/bin/python3 soar_playbook_report.py -c config.json >> report.log 2>&1
```

## REST endpoints used

- `GET /rest/scm?_filter_name="<repo>"`: resolves a repo name to its id
- `GET /rest/playbook?_filter_name="<name>"&_filter_scm=<id>`: resolves a playbook to its id(s)
- `GET /rest/playbook_run?_filter_playbook=<id>&_filter_start_time__gte="<UTC time>"`:
  run history, read page by page (`page`, `page_size`)

The script counts statuses itself, so it does not depend on the server
filtering by status.
