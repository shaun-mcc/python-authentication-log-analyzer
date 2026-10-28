import csv
import ipaddress
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta



REQUIRED_FIELDS = (
    "timestamp",
    "source_ip",
    "username",
    "outcome"
)

def validate_event(row, line_number):
    """Validate one csv record and return cleaned event"""
    location = f"CSV record ending on line {line_number}"

    # DictReader stores extra values under None key
    if None in row:
        raise ValueError(
            f"{location}: too many values. "
            "Check for extra commas or unquoted commas."
        )

    # Missing column in a record have a value of None
    for field in REQUIRED_FIELDS:
        value = row[field]

        if value is None:
            raise ValueError(
                f"{location}: missing '{field}' value"
            )
        if not value.strip():
            raise ValueError(
                f"{location}: '{field}' value is empty"
            )
    cleaned = {
        field: row[field].strip()
        for field in REQUIRED_FIELDS
    }

    # parse timestamp and require timezone
    try:
        event_time = datetime.fromisoformat(cleaned["timestamp"])

    except ValueError as error:
        raise ValueError(
            f"{location}: invalid timestamp "
            f"{cleaned['timestamp']!r}. "
            "Use a value such as "
            "'2026-10-23T14:00:00+00:00'."
        ) from error

    if event_time.tzinfo is None or event_time.utcoffset() is None:
        raise ValueError(
            f"{location}: timestamp must include timezone offset, "
            "such as +00:00"
        )
    # validate and standardize the source address
    try:
        source_address = ipaddress.ip_address(cleaned["source_ip"])
    except ValueError as error:
        raise ValueError(
            f"{location}: invalid source_ip "
            f"{cleaned['source_ip']!r}. "
        ) from error
    if cleaned["outcome"] not in ("SUCCESS", "FAILURE"):
        raise ValueError(
            f"{location}: invalid outcome {cleaned['outcome']!r}. "
            "Outcome must be 'SUCCESS' or 'FAILURE'."
        )
    return {
        "timestamp": event_time.astimezone(timezone.utc),
        "source_ip": str(source_address),
        "username": cleaned["username"],
        "outcome": cleaned["outcome"]
    }

def load_events(file_path):
    """Read and validate authentication events from a csv file."""
    events = []

    with open(file_path, newline='', encoding='utf-8-sig') as log_file:
        reader = csv.DictReader(log_file, strict=True)
        headers = reader.fieldnames

        if headers is None:
            raise ValueError("No headers found")

        # Duplicate headers addressed as they could hide column values
        if len(headers) != len(set(headers)):
            raise ValueError("The CSV header contains duplicate column names")

        missing_fields = [
            field for field in REQUIRED_FIELDS if field not in headers
        ]

        unexpected_fields = [
            field for field in headers if field not in REQUIRED_FIELDS
        ]

        if missing_fields or unexpected_fields:
            details = []

            if missing_fields:
                details.append(f"Missing columns: {missing_fields}")
            if unexpected_fields:
                details.append(f"Unexpected columns: {unexpected_fields}")

            raise ValueError(
                "invalid CSV header: " + "; ".join(details)
            )

        for row in reader:
            event = validate_event(row, reader.line_num)
            events.append(event)

    return events

def detect_repeated_failures(events, threshold=5, window_minutes=10):
    """Return first qualifying failure window alert for each source IP"""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than 0")

    window = timedelta(minutes=window_minutes)
    failures_by_ip = defaultdict(deque)
    alerted_ips = set()
    alerts = []

    sorted_events = sorted(events, key=lambda event: event["timestamp"])

    for event in sorted_events:
        if event in sorted_events:
            if event["outcome"] != "FAILURE":
                continue

            source_ip = event["source_ip"]
            timestamp = event["timestamp"]

            if source_ip in alerted_ips:
                continue

            recent_failures = failures_by_ip[source_ip]
            recent_failures.append(timestamp)

            cutoff = timestamp - window

            while recent_failures[0] < cutoff:
                recent_failures.popleft()

            if len(recent_failures) >= threshold:
                alerts.append({
                    "source_ip": source_ip,
                    "failure_count": len(recent_failures),
                    "window_start": recent_failures[0],
                    "window_end": timestamp
                })
                alerted_ips.add(source_ip)
    return alerts

def parse_arguments(argv=None):
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=(
            "Analyze authentication CSV logs for repeated failed logins"
        )
    )

    parser.add_argument(
        "file_path",
        help="Path to authentication CSV file"
    )

    return parser.parse_args(argv)

def main():
    args = parse_arguments()
    file_path = args.file_path

    try:
        events = load_events(file_path)

    except FileNotFoundError:
        print(f"Input error: {file_path} not found")
        raise SystemExit(1)

    except UnicodeDecodeError:
        print(f"Input error: {file_path} must use UTF-8 encoding")
        raise SystemExit(1)

    except csv.Error as error:
        print(f"CSV error: {error}")
        raise SystemExit(1)

    except OSError as error:
        print(f"Could not open {file_path}: {error}")
        raise SystemExit(1)

    except ValueError as error:
        print(f"CSV error: {error}")
        raise SystemExit(1)

    print(f"Loaded {len(events)} valid authentication events")

    if not events:
        print(f"No valid authentication events found")
        return

    for event in events:
        print(
            f"{event['timestamp'].isoformat()}: "
            f"SRC={event['source_ip']} "
            f"USER={event['username']} "
            f"OUTCOME={event['outcome']}"
        )

    alerts = detect_repeated_failures(events)

    print(f"\nRepeated failure alerts: {len(alerts)}")

    for alert in alerts:
        print(
            f"ALERT: SRC={alert['source_ip']} "
            f"FAILURES={alert['failure_count']} "
            f"START={alert['window_start'].isoformat()} "
            f"END={alert['window_end'].isoformat()}"
        )


if __name__ == "__main__":
    main()
