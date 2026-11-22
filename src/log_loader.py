"""
Log Loader Module
Provides functions to load and validate security event logs from CSV.
"""
from pathlib import Path
import pandas as pd


EXPECTED_COLUMNS = [
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "status",
    "details"
]


def load_logs(file_path: str | Path) -> pd.DataFrame:
    """
    Loads security logs from a CSV file into a pandas DataFrame.
    Converts timestamps to datetime objects and validates required columns.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found at: {path}")

    # Read CSV
    df = pd.read_csv(path)

    # Ensure all expected columns are present
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = "Unknown"

    # Convert timestamp to datetime for time-based filtering and sorting
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Sort in reverse chronological order (newest events first)
    df = df.sort_values(by="timestamp", ascending=False).reset_index(drop=True)

    return df
