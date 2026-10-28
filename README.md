## Python Authentication Log Analyzer

Educational Python project for analyzing authentication events.

The current version loads and validates events from a documented CSV format. Suspicious login detection is planned but currently not implemented.

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
- Detects repeated failed logins by source IP using a configurable
  threshold and rolling time window
- Prints detection alerts with the source IP, failure count, and
  first and last failure timestamps in the triggering window
- Defaults to five failures within ten minutes and reports the first
  qualifying alert per source IP per run

## Requirements

- Python 3.7 or newer
- No third party packages required

## Getting Started

Put `analyzer.py` and 'sample_events.csv` in the same directory. Open a terminal in that directory and run:

```bash
python analyzer.py
```
The program currently reads `sample_events.csv` from the working directory.
It prints the number of valid events followed by the cleaned event details.

## Input Formatting

The CSV must have these exact headers in no particular order:

```csv
timestamp,source_ip,username,outcome
```

| Field | Requirement |
|---|---|
| `timestamp` | Parseable date/time with an explicit timezone offset |
| `source_ip` | Valid IPv4 or IPv6 address |
| `username` | Nonempty value |
| `outcome` | Exactly `SUCCESS` or `FAILURE` |

Surrounding whitespace is stripped from field values.
Both headers and outcome values are case sensitive.

The included sample is solely synthetic demonstration events and is not an actual authentication log.

## Testing

The project includes automated unit tests for event validation using
Python's built-in `unittest` framework.

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

## Limitations

- Does not collect live logs or connect to a SIEM
- Supports only the documented CSV input format
- Stops at the first validation error
- Loads events into memory


## Planned Improvements

- Produce summaries containing the events supporting each finding
