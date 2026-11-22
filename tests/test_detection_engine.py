"""
Unit Tests for Detection Engine (Stage 2)
Tests all 5 threat detection rules, alert generation structure, and targeted fixes:
- Port scan threshold & time window correlation (RULE-04)
- Exclusion of missing/unknown usernames in targeted authentication failures (RULE-02)
- Multi-category correlation and deduplication for Suspicious IP Activity (RULE-03)
"""
import unittest
from pathlib import Path
import pandas as pd

from src.log_loader import load_logs
from src.detection_engine import DetectionEngine, SecurityAlert


class TestDetectionEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_path = Path(__file__).parent.parent / "data" / "sample_logs.csv"
        cls.df = load_logs(cls.data_path)
        cls.engine = DetectionEngine()

    def test_alert_schema(self):
        """Verify generated alerts have all required fields."""
        alerts_df = self.engine.run_all_rules(self.df)
        self.assertFalse(alerts_df.empty, "Detection engine should generate alerts from sample logs.")

        required_fields = [
            "alert_id", "timestamp", "source_ip", "username",
            "threat_type", "severity", "detection_rule", "explanation"
        ]
        for field in required_fields:
            self.assertIn(field, alerts_df.columns, f"Field '{field}' missing from generated alerts.")

    def test_brute_force_rule(self):
        """Verify brute force detection finds repeated failed logins from same IP."""
        bf_alerts = self.engine.detect_brute_force(self.df)
        self.assertGreater(len(bf_alerts), 0, "Brute force rule should detect brute force attempts.")
        ips = [a.source_ip for a in bf_alerts]
        self.assertIn("203.0.113.14", ips)
        for a in bf_alerts:
            self.assertEqual(a.threat_type, "Brute Force Attack")
            self.assertIn(a.severity, ["High", "Critical"])

    def test_repeated_failed_logins_rule(self):
        """Verify repeated failed logins targeting valid usernames are caught."""
        fl_alerts = self.engine.detect_repeated_failed_logins(self.df)
        self.assertGreater(len(fl_alerts), 0, "Repeated failed logins rule should generate alerts for valid users.")
        for a in fl_alerts:
            self.assertEqual(a.threat_type, "Repeated Failed Logins")
            self.assertNotEqual(a.username.lower(), "unknown")
            self.assertNotIn("unknown", a.explanation.lower())

    def test_repeated_failed_logins_ignores_unknown_and_missing(self):
        """Verify RULE-02 explicitly ignores missing, empty, null, and 'unknown' usernames."""
        test_data = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "unknown", "source_ip": "192.168.1.50", "event_type": "Login", "status": "Failed", "details": "Failed 1"},
            {"timestamp": "2026-11-22 10:02:00", "username": "UNKNOWN", "source_ip": "192.168.1.50", "event_type": "Login", "status": "Failed", "details": "Failed 2"},
            {"timestamp": "2026-11-22 10:04:00", "username": "", "source_ip": "192.168.1.50", "event_type": "Login", "status": "Failed", "details": "Failed 3"},
            {"timestamp": "2026-11-22 10:05:00", "username": None, "source_ip": "192.168.1.50", "event_type": "Login", "status": "Failed", "details": "Failed 4"},
            {"timestamp": "2026-11-22 10:06:00", "username": "   ", "source_ip": "192.168.1.50", "event_type": "Login", "status": "Failed", "details": "Failed 5"},
        ])
        engine = DetectionEngine(failed_logins_threshold=2, failed_logins_window_minutes=30)
        alerts = engine.detect_repeated_failed_logins(test_data)
        self.assertEqual(len(alerts), 0, "RULE-02 should produce 0 alerts for missing/unknown usernames.")

        test_data_valid = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "jdoe", "source_ip": "192.168.1.50", "event_type": "Login", "status": "Failed", "details": "Failed 1"},
            {"timestamp": "2026-11-22 10:02:00", "username": "jdoe", "source_ip": "192.168.1.50", "event_type": "Login", "status": "Failed", "details": "Failed 2"},
        ])
        alerts_valid = engine.detect_repeated_failed_logins(test_data_valid)
        self.assertEqual(len(alerts_valid), 1)
        self.assertEqual(alerts_valid[0].username, "jdoe")
        self.assertIn("Threshold: 2", alerts_valid[0].explanation)

    def test_suspicious_ip_rule(self):
        """Verify suspicious IP activity detection on sample dataset."""
        sip_alerts = self.engine.detect_suspicious_ip_activity(self.df)
        self.assertGreater(len(sip_alerts), 0, "Suspicious IP rule should generate alerts for multi-category IPs.")
        for a in sip_alerts:
            self.assertEqual(a.threat_type, "Suspicious IP Activity")
            self.assertIn("categories", a.explanation.lower())

    def test_suspicious_ip_multi_category_trigger(self):
        """Verify RULE-03 triggers on combinations of distinct suspicious categories."""
        engine = DetectionEngine(suspicious_ip_threshold=2, suspicious_ip_min_categories=2, suspicious_ip_window_minutes=60)

        # 1. Firewall Block + Malware Detected
        df1 = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "system", "source_ip": "10.0.1.1", "event_type": "Firewall Block", "status": "Blocked", "details": "Traffic blocked"},
            {"timestamp": "2026-11-22 10:05:00", "username": "system", "source_ip": "10.0.1.1", "event_type": "Malware Detected", "status": "Alert", "details": "Malware detected"},
        ])
        alerts1 = engine.detect_suspicious_ip_activity(df1)
        self.assertEqual(len(alerts1), 1, "Firewall Block + Malware Detected should trigger RULE-03.")
        self.assertEqual(alerts1[0].source_ip, "10.0.1.1")

        # 2. Security Alert + File Access
        df2 = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "guest", "source_ip": "10.0.1.2", "event_type": "File Access", "status": "Failed", "details": "Denied access"},
            {"timestamp": "2026-11-22 10:02:00", "username": "guest", "source_ip": "10.0.1.2", "event_type": "Security Alert", "status": "Alert", "details": "Unauthorized access attempt"},
        ])
        alerts2 = engine.detect_suspicious_ip_activity(df2)
        self.assertEqual(len(alerts2), 1, "Security Alert + File Access should trigger RULE-03.")
        self.assertEqual(alerts2[0].source_ip, "10.0.1.2")

        # 3. Login + Port Scan
        df3 = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "unknown", "source_ip": "10.0.1.3", "event_type": "Login", "status": "Failed", "details": "Bad login"},
            {"timestamp": "2026-11-22 10:10:00", "username": "system", "source_ip": "10.0.1.3", "event_type": "Port Scan", "status": "Alert", "details": "SYN scan"},
        ])
        alerts3 = engine.detect_suspicious_ip_activity(df3)
        self.assertEqual(len(alerts3), 1, "Login + Port Scan should trigger RULE-03.")
        self.assertEqual(alerts3[0].source_ip, "10.0.1.3")

    def test_suspicious_ip_single_category_ignored(self):
        """Verify RULE-03 does NOT trigger on multiple events from only one event category."""
        engine = DetectionEngine(suspicious_ip_threshold=2, suspicious_ip_min_categories=2, suspicious_ip_window_minutes=60)

        # Login + Login only
        df_login_only = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "user1", "source_ip": "10.0.2.1", "event_type": "Login", "status": "Failed", "details": "Failed pass 1"},
            {"timestamp": "2026-11-22 10:05:00", "username": "user1", "source_ip": "10.0.2.1", "event_type": "Login", "status": "Failed", "details": "Failed pass 2"},
        ])
        alerts_login = engine.detect_suspicious_ip_activity(df_login_only)
        self.assertEqual(len(alerts_login), 0, "Login + Login only should NOT trigger RULE-03.")

        # Port Scan + Port Scan only
        df_scan_only = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "system", "source_ip": "10.0.2.2", "event_type": "Port Scan", "status": "Alert", "details": "Scan probe 1"},
            {"timestamp": "2026-11-22 10:05:00", "username": "system", "source_ip": "10.0.2.2", "event_type": "Port Scan", "status": "Alert", "details": "Scan probe 2"},
        ])
        alerts_scan = engine.detect_suspicious_ip_activity(df_scan_only)
        self.assertEqual(len(alerts_scan), 0, "Port Scan + Port Scan only should NOT trigger RULE-03.")

    def test_port_scan_rule(self):
        """Verify port scan detection with repeated events threshold."""
        ps_alerts = self.engine.detect_port_scans(self.df)
        self.assertGreater(len(ps_alerts), 0, "Port scan rule should detect repeated scanning events.")
        for a in ps_alerts:
            self.assertEqual(a.threat_type, "Port Scanning")
            self.assertIn("Threshold: 2", a.explanation)
            self.assertIn("minutes", a.explanation)

    def test_port_scan_requires_repeated_events_in_window(self):
        """Verify RULE-04 ignores isolated single port scan events and honors time windows."""
        single_scan = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "system", "source_ip": "10.0.0.99", "event_type": "Port Scan", "status": "Alert", "details": "Scan 1"}
        ])
        engine = DetectionEngine(port_scan_threshold=2, port_scan_window_minutes=15)
        self.assertEqual(len(engine.detect_port_scans(single_scan)), 0)

        spaced_scans = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "system", "source_ip": "10.0.0.99", "event_type": "Port Scan", "status": "Alert", "details": "Scan 1"},
            {"timestamp": "2026-11-22 11:00:00", "username": "system", "source_ip": "10.0.0.99", "event_type": "Port Scan", "status": "Alert", "details": "Scan 2"},
        ])
        self.assertEqual(len(engine.detect_port_scans(spaced_scans)), 0)

        repeated_scans = pd.DataFrame([
            {"timestamp": "2026-11-22 10:00:00", "username": "system", "source_ip": "10.0.0.99", "event_type": "Port Scan", "status": "Alert", "details": "Scan 1"},
            {"timestamp": "2026-11-22 10:05:00", "username": "system", "source_ip": "10.0.0.99", "event_type": "Port Scan", "status": "Alert", "details": "Scan 2"},
        ])
        alerts = engine.detect_port_scans(repeated_scans)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "10.0.0.99")
        self.assertIn("Detected 2 port scanning events", alerts[0].explanation)
        self.assertIn("(Threshold: 2)", alerts[0].explanation)

    def test_privilege_escalation_rule(self):
        """Verify unauthorized privilege escalation is flagged."""
        pe_alerts = self.engine.detect_privilege_escalation(self.df)
        self.assertGreater(len(pe_alerts), 0, "Privilege escalation rule should flag unauthorized attempts.")
        for a in pe_alerts:
            self.assertEqual(a.threat_type, "Privilege Escalation")
            self.assertEqual(a.severity, "Critical")

    def test_empty_dataframe(self):
        """Verify engine safely handles empty DataFrame."""
        empty_df = pd.DataFrame(columns=["timestamp", "username", "source_ip", "event_type", "status", "details"])
        alerts_df = self.engine.run_all_rules(empty_df)
        self.assertTrue(alerts_df.empty)


if __name__ == "__main__":
    unittest.main()
