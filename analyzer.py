import csv
import ipaddress
from datetime import datetime, timezone

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

def main():
    file_path = "sample_events.csv"

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


if __name__ == "__main__":
    main()
