"""
Metrics Module
Calculates security metrics and KPIs from log data.
"""
import pandas as pd


def get_total_events(df: pd.DataFrame) -> int:
    """Returns the total number of recorded security events."""
    return len(df)


def get_successful_logins(df: pd.DataFrame) -> int:
    """Returns the count of successful login events."""
    if df.empty:
        return 0
    condition = (df["event_type"].str.lower() == "login") & (df["status"].str.lower() == "success")
    return int(condition.sum())


def get_failed_logins(df: pd.DataFrame) -> int:
    """Returns the count of failed login attempts."""
    if df.empty:
        return 0
    condition = (df["event_type"].str.lower() == "login") & (df["status"].str.lower() == "failed")
    return int(condition.sum())


def get_security_alerts(df: pd.DataFrame) -> int:
    """
    Returns the count of events classified as security alerts or high-priority warnings.
    Checks both status and event_type for alert indicators.
    """
    if df.empty:
        return 0
    is_alert_status = df["status"].str.lower().isin(["alert", "blocked", "warning"])
    is_alert_type = df["event_type"].str.lower().isin(["security alert", "malware detected", "port scan"])
    return int((is_alert_status | is_alert_type).sum())
