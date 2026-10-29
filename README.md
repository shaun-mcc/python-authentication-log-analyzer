## Python Authentication Log Analyzer

Educational Python project for analyzing authentication events.

The analyzer validates CSV authentication records, detects repeated
failed logins by source IP within a rolling time window, and optionally
saves a structured JSON findings report.

Findings identify activity that meets the configured detection rule,
they do not establish that an attack occurred.

## Current Features

- Loads authentication events from CSV
- Checks for missing, unexpected, or duplicate headers
- Rejects records with missing or extra values
- Rejects empty required fields
- Validates timestamps and requires a timezone offset
- Normalizes timestamps to UTC
- Validates and standardizes IPv4 and IPv6 source addresses
- Accepts only `SUCCESS` or `FAILURE` outcomes
- Displays validation errors with the corresponding record's line location
- Stops loading at first invalid record
- Detects repeated failed logins by source IP using a
  threshold and rolling time window
- Prints detection alerts with the source IP, failure count, and
  first and last failure timestamps in the triggering window
- Defaults to five failures within ten minutes and reports the first
  qualifying alert per source IP per run
- Accepts the input CSV path through a command-line argument
- Optionally saves a structured JSON findings report
- Reports the input filename, event count, detection settings, and alerts
- Saves a zero alert report when no findings are detected

## Requirements

- Python 3.7 or newer
- No third party packages required

## Getting Started

Open a terminal in the project directory and run the analyzer with a CSV file path:

```bash
python analyzer.py sample_events.csv
```

Analyze the sample CSV and save a JSON findings report:

```bash
python analyzer.py sample_events.csv --output report.json
```

This example uses the included `sample_events.csv`. To analyze another file,
replace it with that file's path. Put quotation marks around paths containing spaces.

The program prints the number of valid events, the cleaned event details,
and any repeated failure alerts. It flags a source IP when it
reaches five failed logins within a rolling ten-minute window, reporting
the first qualifying alert per source IP per run. When `--output` is supplied, it also saves
a JSON report.

To view command-line help:

```bash
python analyzer.py --help
```

The output directory must already exist. An existing output file is
overwritten. Use a different path for the report than for the input CSV.

## Input Formatting

The CSV must have these exact headers in no particular order:

```csv
timestamp,source_ip,username,outcome
```

| Field | Requirement |
|---|---|
| `timestamp` | ISO 8601 timestamp with an explicit timezone offset |
| `source_ip` | Valid IPv4 or IPv6 address |
| `username` | Nonempty value |
| `outcome` | Exactly `SUCCESS` or `FAILURE` |

Surrounding whitespace is stripped from field values.
Both headers and outcome values are case sensitive.

The included sample contains only synthetic demonstration events,
not real authentication logs.

## Report Format

The optional JSON report contains:

- `input_file`: the input CSV path supplied to the program
- `events_loaded`: the number of validated authentication events
- `threshold`: the failure threshold used for detection
- `window_minutes`: the detection window length
- `alert_count`: the number of findings
- `alerts`: the findings, including source IP, failure count, and
  first and last failure timestamps in the triggering window

Example alert:

```json
{
  "source_ip": "192.0.2.10",
  "failure_count": 5,
  "window_start": "2026-10-23T14:00:00+00:00",
  "window_end": "2026-10-23T14:08:00+00:00"
}
```

Report timestamps use UTC. When there are no findings, `alert_count`
is zero and `alerts` is an empty list.

A valid header only CSV produces a zero event report. Invalid input
stops processing before a new report is written.

## Testing

The project includes automated unit tests for event validation,
repeated-failure detection, CSV loading, command-line argument
parsing, JSON reporting, and integrated command-line workflow using Python's built-in `unittest` framework.

Run the tests from the project directory:

```bash
python -m unittest -v test_analyzer
```

The validation tests cover:

- Valid events and accepted SUCCESS/FAILURE outcomes
- IPv4 and IPv6 address handling
- Rejection of invalid IP addresses and malformed timestamps
- Rejection of timestamps without timezone information
- Conversion of timezone-aware timestamps to UTC
- Rejection of missing values, empty values, and blank usernames
- Rejection of extra CSV values
- Removal of surrounding whitespace from input fields

The repeated-failure detection tests cover:

- An alert when a source IP reaches five failed logins within ten minutes
- No alert when failures remain below the threshold
- No alert when failures fall outside the time window
- Successful logins not counting toward the failure threshold
- Separate failure counts for each source IP
- Inclusion of failures exactly at the ten-minute window boundary
- Correct detection when input events are out of order
- One alert per source IP per analysis, even when more failures follow
- Empty event input returning no alerts
- Rejection of a zero failure threshold or zero time-window setting

The CSV-loader tests cover:

- Loading valid CSV records as cleaned events
- Rejection of empty files without headers
- Header-only files returning an empty event list
- Rejection of missing, unexpected, or duplicate header columns
- Invalid record errors including the CSV line number
- Rejection of records with too few or too many values
- Missing input files raising FileNotFoundError

The command-line argument tests cover:

- Accepting a CSV file path
- Preserving file paths containing spaces
- Rejecting a missing required file path
- Rejecting unrecognized arguments
- Displaying help and exiting successfully

The JSON report tests cover:

- Saving expected alert details and analysis settings
- Saving reports without alerts
- Recording custom detection settings
- Propagating output-file errors

The integrated command-line tests cover:

- Saving the expected findings from a complete analysis
- Terminal only operation when no output path is supplied
- Saving a zero event report from a header only CSV
- Exiting unsuccessfully when report writing fails
- Rejecting invalid input without creating a report
  
## Limitations

- Does not collect live logs or connect to a SIEM
- Supports only the documented CSV input format
- Stops at the first validation error
- Loads events into memory and sorts for detection
- Detection threshold and time window cannot yet be changed through
  command-line options, they are only configurable through function arguments
- Groups by source IP, not username
- Reports only the first qualifying alert per source IP per run
- Reports contain alert summaries, not full supporting event records
- Existing report files are overwritten


## Future Improvements

- Add command-line options for the failure threshold and time window
- Include supporting event records in each finding
- Correlate repeated failures with subsequent successful logins
