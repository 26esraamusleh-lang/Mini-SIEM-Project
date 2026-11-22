"""
Unit Tests for Mini SIEM Foundation (Stage 1)
Tests log ingestion, data integrity, and KPI metrics.
"""
import unittest
from pathlib import Path
import pandas as pd

from src.log_loader import load_logs, EXPECTED_COLUMNS
from src.metrics import (
    get_total_events,
    get_successful_logins,
    get_failed_logins,
    get_security_alerts,
)


class TestMiniSIEM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_path = Path(__file__).parent.parent / "data" / "sample_logs.csv"
        cls.df = load_logs(cls.data_path)

    def test_log_file_exists(self):
        """Verify sample_logs.csv exists."""
        self.assertTrue(self.data_path.exists(), "Sample logs CSV file does not exist.")

    def test_dataset_not_empty(self):
        """Ensure dataset contains records."""
        self.assertGreater(len(self.df), 0, "Log dataset should not be empty.")

    def test_required_columns_present(self):
        """Ensure all required SIEM columns are present."""
        for col in EXPECTED_COLUMNS:
            self.assertIn(col, self.df.columns, f"Column '{col}' is missing from logs.")

    def test_timestamp_parsed_correctly(self):
        """Verify timestamps are parsed as datetime."""
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(self.df["timestamp"]))

    def test_kpi_metrics(self):
        """Verify calculations return valid non-negative integers."""
        total = get_total_events(self.df)
        success = get_successful_logins(self.df)
        failed = get_failed_logins(self.df)
        alerts = get_security_alerts(self.df)

        self.assertEqual(total, len(self.df))
        self.assertGreaterEqual(success, 0)
        self.assertGreaterEqual(failed, 0)
        self.assertGreaterEqual(alerts, 0)

        # Basic sanity check
        self.assertLessEqual(success + failed, total)


if __name__ == "__main__":
    unittest.main()
