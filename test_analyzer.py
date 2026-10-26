import unittest
from datetime import datetime, timezone

from analyzer import validate_event


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


if __name__ == '__main__':
    unittest.main()
