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

## Limitations

- Does not yet detect suspicious login patterns.
- Does not collect live logs or connect to a SIEM.
- Supports only the documented CSV input format.
- Stops at the first validation error.
- Loads events into memory.
- Does not yet include automated tests.

## Planned Improvements

- Add automated validation tests.
- Detect repeated failed logins within a configurable time window.
- Produce summaries containing the events supporting each finding.
