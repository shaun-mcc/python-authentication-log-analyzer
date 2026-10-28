import unittest
from datetime import datetime, timezone, timedelta
from tempfile import TemporaryDirectory
from pathlib import Path
import io
from contextlib import redirect_stdout, redirect_stderr

from analyzer import (
    validate_event,
    detect_repeated_failures,
    load_events,
    parse_arguments
)

class TestValidateEvent(unittest.TestCase):
    def setUp(self):
        self.valid_row = {
            "timestamp": "2026-10-23T14:00:00+00:00",
            "source_ip": "192.0.2.10",
            "username": "alice",
            "outcome": "SUCCESS"
        }

    def test_valid_event_returned_clean(self):
        result = validate_event(self.valid_row, 2)

        expected = {
            "timestamp": datetime(
                2026, 10, 23, 14, 0,tzinfo=timezone.utc
            ),
            "source_ip": "192.0.2.10",
            "username": "alice",
            "outcome": "SUCCESS"
        }

        self.assertEqual(result, expected)

    def test_invalid_ip_rejected(self):
        row = {
            **self.valid_row,
            "source_ip": "999.1.1.1"
        }
        with self.assertRaisesRegex(ValueError, "invalid source_ip"):
            validate_event(row, 2)

    def test_timestamp_without_timezone_rejected(self):
        row = {
            **self.valid_row,
            "timestamp": "2026-10-23T14:00:00"
        }
        with self.assertRaisesRegex(ValueError, "timezone"):
            validate_event(row, 2)

    def test_invalid_outcome_rejected(self):
        row = {
            **self.valid_row,
            "outcome": "FAILED"
        }
        with self.assertRaisesRegex(ValueError, "invalid outcome"):
            validate_event(row, 2)

    def test_blank_username_rejected(self):
        row = {
            **self.valid_row,
            "username": " "
        }
        with self.assertRaisesRegex(ValueError, "username"):
            validate_event(row, 2)

    def test_valid_ipv6_accepted(self):
        row = {
            **self.valid_row,
            "source_ip": "2001:db8::10"
        }
        result = validate_event(row, 2)
        self.assertEqual(result["source_ip"], "2001:db8::10")

    def test_timestamp_is_converted_to_utc(self):
        row = {
            **self.valid_row,
            "timestamp": "2026-10-23T14:00:00+02:00"
        }
        result = validate_event(row, 2)

        expected_time = datetime(
            2026, 10, 23, 12, 0, tzinfo=timezone.utc
        )
        self.assertEqual(result["timestamp"], expected_time)
        self.assertEqual(result["timestamp"].tzinfo, timezone.utc)

    def test_malformed_timestamp_rejected(self):
        row = {
            **self.valid_row,
            "timestamp": "not-a-date"
        }
        with self.assertRaisesRegex(ValueError, "invalid timestamp"):
            validate_event(row, 2)

    def test_missing_field_value_rejected(self):
        row = {
            **self.valid_row,
            "source_ip": None
        }
        with self.assertRaisesRegex(ValueError, "missing 'source_ip'"):
            validate_event(row, 2)

    def test_empty_source_ip_rejected(self):
        row = {
            **self.valid_row,
            "source_ip": " "
        }

        with self.assertRaisesRegex(ValueError, "'source_ip' value is empty"):
            validate_event(row, 2)

    def test_extra_csv_values_rejected(self):
        row = {
            **self.valid_row,
            None: ["unexpected value"]
        }
        with self.assertRaisesRegex(ValueError, "too many values"):
            validate_event(row, 2)

    def test_surrounding_whitespace_removed(self):
        row = {
            "timestamp": "2026-10-23T14:00:00+00:00",
            "source_ip": "192.0.2.10",
            "username": "alice",
            "outcome": "SUCCESS"
        }

        result = validate_event(row, 2)

        expected = {
            "timestamp": datetime(
                2026, 10, 23, 14, 0, tzinfo=timezone.utc
            ),
            "source_ip": "192.0.2.10",
            "username": "alice",
            "outcome": "SUCCESS"
        }

        self.assertEqual(result, expected)

    def test_failure_outcome_accepted(self):
        row = {
            **self.valid_row,
            "outcome": "FAILURE"
        }

        result = validate_event(row, 2)
        self.assertEqual(result["outcome"], "FAILURE")


class TestDetectRepeatedFailures(unittest.TestCase):
    def setUp(self):
        self.start_time = datetime(
            2026, 10, 23, 14, 0, tzinfo=timezone.utc
        )

    def make_event(
            self,
            minutes,
            source_ip="192.0.2.10",
            outcome="FAILURE"
    ):
        return {
            "timestamp": self.start_time + timedelta(minutes=minutes),
            "source_ip": source_ip,
            "username": "alice",
            "outcome": outcome
        }

    def test_threshold_reached_creates_alert(self):
        events = [
            self.make_event(minutes)
            for minutes in (0, 2, 4, 6, 8)
        ]

        alerts = detect_repeated_failures(events)

        expected = [{
            "source_ip": "192.0.2.10",
            "failure_count": 5,
            "window_start": self.start_time,
            "window_end": self.start_time + timedelta(minutes=8),
        }]

        self.assertEqual(alerts, expected)

    def test_below_threshold_returns_no_alert(self):
        events = [
            self.make_event(minutes)
            for minutes in (0, 2, 4, 6)
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(alerts, [])

    def test_failures_outside_window_return_no_alert(self):
        events = [
            self.make_event(minutes)
            for minutes in (0, 3, 6, 9, 12)
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(alerts, [])

    def test_successes_do_not_count_as_failures(self):
        events = [
            self.make_event(0),
            self.make_event(1),
            self.make_event(2),
            self.make_event(3),
            self.make_event(4, outcome="SUCCESS")
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(alerts, [])

    def test_different_ips_counted_separately(self):
        events = [
            self.make_event(0),
            self.make_event(1),
            self.make_event(2),
            self.make_event(3, source_ip="192.0.2.20"),
            self.make_event(4, source_ip="192.0.2.20"),
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(alerts, [])

    # edge cases
    def test_exact_window_boundary_creates_alert(self):
        events = [
            self.make_event(minutes)
            for minutes in (0, 2, 4, 6, 10)
        ]

        alerts = detect_repeated_failures(events)

        expected = [{
            "source_ip": "192.0.2.10",
            "failure_count": 5,
            "window_start": self.start_time,
            "window_end": self.start_time + timedelta(minutes=10),
        }]

        self.assertEqual(alerts, expected)

    def test_unsorted_events_create_correct_alert(self):
        events = [
            self.make_event(minutes)
            for minutes in (8, 0, 6, 2, 4)
        ]

        alerts = detect_repeated_failures(events)

        expected = [{
            "source_ip": "192.0.2.10",
            "failure_count": 5,
            "window_start": self.start_time,
            "window_end": self.start_time + timedelta(minutes=8),
        }]

        self.assertEqual(alerts, expected)

    def test_same_ip_only_alert_once(self):
        events = [
            self.make_event(minutes)
            for minutes in (0, 1, 2, 3, 4, 5, 6)
        ]

        alerts = detect_repeated_failures(events)

        expected = [{
            "source_ip": "192.0.2.10",
            "failure_count": 5,
            "window_start": self.start_time,
            "window_end": self.start_time + timedelta(minutes=4),
        }]

        self.assertEqual(alerts, expected)

    def test_empty_events_return_no_alerts(self):
        alerts = detect_repeated_failures([])

        self.assertEqual(alerts, [])

    def test_zero_threshold_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "threshold must be at least 1"
        ):
            detect_repeated_failures([], threshold=0)

    def test_zero_window_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "window_minutes must be greater than 0"
        ):
            detect_repeated_failures([], window_minutes=0)


class TestLoadEvents(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.file_path = Path(self.temp_dir.name) / "events.csv"
        self.header = "timestamp,source_ip,username,outcome\n"

    def write_csv(self, content):
        with self.file_path.open("w", encoding="utf-8", newline="") as csv_file:
            csv_file.write(content)

    def test_valid_csv_returns_cleaned_events(self):
        self.write_csv(
            self.header
            + "2026-10-23T14:00:00+00:00,"
              "192.0.2.10,alice,SUCCESS\n"
            + "2026-10-23T14:02:00+00:00,"
              "192.0.2.20,bob,FAILURE\n"
        )

        events = load_events(self.file_path)

        expected = [
            {
                "timestamp": datetime(
                    2026, 10, 23, 14, 0, tzinfo=timezone.utc
                ),
                "source_ip": "192.0.2.10",
                "username": "alice",
                "outcome": "SUCCESS"
            },
            {
                "timestamp": datetime(
                    2026, 10, 23, 14, 2, tzinfo=timezone.utc
                ),
                "source_ip": "192.0.2.20",
                "username": "bob",
                "outcome": "FAILURE",
            }
        ]

        self.assertEqual(events, expected)

    def test_empty_file_rejected(self):
        self.write_csv("")

        with self.assertRaisesRegex(ValueError, "No headers found"):
            load_events(self.file_path)

    def test_header_only_returns_empty_list(self):
        self.write_csv(self.header)

        events = load_events(self.file_path)

        self.assertEqual(events, [])

    def test_missing_header_column_rejected(self):
        self.write_csv("timestamp,source_ip,username\n")

        with self.assertRaisesRegex(ValueError, "Missing columns:.*outcome"):
            load_events(self.file_path)

    def test_unexpected_header_column_rejected(self):
        self.write_csv("timestamp,source_ip,username,outcome,extra\n")

        with self.assertRaisesRegex(ValueError, "Unexpected columns:.*extra"):
            load_events(self.file_path)

    def test_duplicate_header_column_rejected(self):
        self.write_csv("timestamp,source_ip,username,outcome,username\n")

        with self.assertRaisesRegex(ValueError, "duplicate column names"):
            load_events(self.file_path)

    def test_invalid_record_rejected(self):
        self.write_csv(
            self.header
            + "2026-10-23T14:00:00+00:00,"
              "not-an-ip,alice,SUCCESS\n"
        )

        with self.assertRaisesRegex(ValueError, "invalid source_ip"):
            load_events(self.file_path)

    def test_record_with_missing_value_rejected(self):
        self.write_csv(
            self.header
            + "2026-10-23T14:00:00+00:00,"
              "192.0.2.10,alice\n"
        )

        with self.assertRaisesRegex(ValueError, "missing 'outcome' value"):
            load_events(self.file_path)

    def test_record_with_extra_value_rejected(self):
        self.write_csv(
            self.header
            + "2026-10-23T14:00:00+00:00,"
              "192.0.2.10,alice,SUCCESS,unexpected\n"
        )

        with self.assertRaisesRegex(ValueError, "too many values"):
            load_events(self.file_path)

    def test_missing_file_rejected(self):
        missing_path = Path(self.temp_dir.name) / "missing.csv"

        with self.assertRaises(FileNotFoundError):
            load_events(missing_path)


class TestParseArguments(unittest.TestCase):
    def test_csv_path_accepted(self):
        args = parse_arguments(["sample_events.csv"])

        self.assertEqual(args.file_path, "sample_events.csv")

    def test_path_with_spaces_accepted(self):
        file_path = "logs/authentication events.csv"

        args = parse_arguments([file_path])

        self.assertEqual(args.file_path, file_path)

    def test_missing_path_rejected(self):
        output = io.StringIO()

        with redirect_stderr(output):
            with self.assertRaises(SystemExit) as context:
                parse_arguments([])

        self.assertEqual(context.exception.code, 2)
        self.assertIn("file_path", output.getvalue())

    def test_unexpected_argument_rejected(self):
        output = io.StringIO()

        with redirect_stderr(output):
            with self.assertRaises(SystemExit) as context:
                parse_arguments([
                    "sample_events.csv",
                    "--unknown-option"
                ])

        self.assertEqual(context.exception.code, 2)
        self.assertIn("--unknown-option", output.getvalue())

    def test_help_exits_successfully(self):
        output = io.StringIO()

        with redirect_stdout(output):
            with self.assertRaises(SystemExit) as context:
                parse_arguments(["--help"])

        self.assertEqual(context.exception.code, 0)
        self.assertIn("--help", output.getvalue())


if __name__ == '__main__':
    unittest.main()
