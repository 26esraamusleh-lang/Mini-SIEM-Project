"""
Mini SIEM - Security Information and Event Management System
Stage 2: Threat Detection Engine & SOC Monitoring Console
"""
from pathlib import Path
import streamlit as st
import pandas as pd
from src.log_loader import load_logs
from src.metrics import (
    get_total_events,
    get_successful_logins,
    get_failed_logins,
)
from src.detection_engine import DetectionEngine

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="Mini SIEM - SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------
# Custom SOC Dark Cyber Theme Styling
# ---------------------------------------------------------
CUSTOM_CSS = """
<style>
    /* Global background and font styling */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Header card */
    .soc-header {
        background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        border: 1px solid #374151;
        border-left: 5px solid #10b981;
        border-radius: 8px;
        padding: 1.2rem 1.6rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    }
    .soc-header h1 {
        margin: 0;
        font-size: 1.8rem;
        font-weight: 700;
        color: #f9fafb;
        letter-spacing: 0.5px;
    }
    .soc-header p {
        margin: 0.3rem 0 0 0;
        color: #9ca3af;
        font-size: 0.95rem;
    }

    /* Metric Cards */
    .metric-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
    }
    .metric-title {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #9ca3af;
        margin-bottom: 0.25rem;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin: 0;
        line-height: 1.2;
    }
    .metric-sub {
        font-size: 0.78rem;
        color: #6b7280;
        margin-top: 0.25rem;
    }

    /* Metric color variants */
    .card-total { border-left: 4px solid #38bdf8; }
    .card-total .metric-value { color: #38bdf8; }

    .card-success { border-left: 4px solid #10b981; }
    .card-success .metric-value { color: #10b981; }

    .card-failed { border-left: 4px solid #f59e0b; }
    .card-failed .metric-value { color: #f59e0b; }

    .card-alert { border-left: 4px solid #ef4444; }
    .card-alert .metric-value { color: #ef4444; }

    /* Badges */
    .badge-simulated {
        display: inline-block;
        background-color: #064e3b;
        color: #6ee7b7;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-engine {
        display: inline-block;
        background-color: #1e1b4b;
        color: #a5b4fc;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-left: 6px;
    }
    .severity-pill-critical {
        background-color: #450a0a;
        color: #f87171;
        border: 1px solid #7f1d1d;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .severity-pill-high {
        background-color: #431407;
        color: #fb923c;
        border: 1px solid #7c2d12;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .severity-pill-medium {
        background-color: #422006;
        color: #facc15;
        border: 1px solid #713f12;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .alert-banner {
        background: #18181b;
        border: 1px solid #27272a;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin-bottom: 1rem;
        display: flex;
        gap: 15px;
        align-items: center;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------
# Data Loading Helper (Cached for Performance)
# ---------------------------------------------------------
@st.cache_data
def get_cached_logs():
    data_path = Path(__file__).parent / "data" / "sample_logs.csv"
    return load_logs(data_path)


# ---------------------------------------------------------
# Sidebar: Controls, Filters & Engine Configuration
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ Mini SIEM Controls")
    st.markdown(
        """
        <div style="background-color: #1f2937; padding: 10px; border-radius: 6px; margin-bottom: 15px;">
            <div style="font-size: 0.8rem; color: #9ca3af;">ENVIRONMENT</div>
            <div style="font-weight: 600; color: #10b981;">● Academic Lab (Isolated)</div>
            <div style="font-size: 0.75rem; color: #a5b4fc; margin-top: 4px;">● Threat Detection Engine: Active</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    try:
        raw_df = get_cached_logs()
        load_success = True
    except Exception as e:
        st.error(f"Error loading logs: {e}")
        load_success = False
        raw_df = pd.DataFrame()

    if load_success and not raw_df.empty:
        st.markdown("#### 🔍 Log Stream Filters")

        # Event Type Filter
        all_event_types = sorted(raw_df["event_type"].dropna().unique().tolist())
        selected_event_types = st.multiselect(
            "Event Type",
            options=all_event_types,
            default=all_event_types,
            help="Filter logs by event category"
        )

        # Status Filter
        all_statuses = sorted(raw_df["status"].dropna().unique().tolist())
        selected_statuses = st.multiselect(
            "Status",
            options=all_statuses,
            default=all_statuses,
            help="Filter logs by status outcome"
        )

        # Username Search
        search_user = st.text_input(
            "Filter by Username",
            placeholder="e.g. admin, jsmith",
            help="Case-insensitive search in username"
        ).strip().lower()

        # IP Address Search
        search_ip = st.text_input(
            "Filter by Source IP",
            placeholder="e.g. 192.168, 203.0",
            help="Case-insensitive search in IP address"
        ).strip()

        st.divider()
        st.markdown("#### ⚙️ Detection Engine Rules")
        with st.expander("Configure Thresholds", expanded=False):
            bf_thresh = st.slider("Brute Force Threshold", min_value=2, max_value=10, value=3, help="Failed logins per IP to flag brute force")
            bf_window = st.slider("Brute Force Window (min)", min_value=1, max_value=60, value=15, help="Time window for brute force analysis")
            fl_thresh = st.slider("Username Failures Threshold", min_value=1, max_value=5, value=2, help="Failed attempts per user")
            fl_window = st.slider("Username Failures Window (min)", min_value=1, max_value=60, value=30, help="Time window for username failure correlation")
            sip_thresh = st.slider("Suspicious IP Threshold", min_value=1, max_value=5, value=2, help="Suspicious events per IP")
            sip_categories = st.slider("Suspicious IP Min Categories", min_value=1, max_value=4, value=2, help="Distinct event categories required")
            sip_window = st.slider("Suspicious IP Window (min)", min_value=5, max_value=120, value=60, help="Time window for suspicious IP correlation")
            ps_thresh = st.slider("Port Scan Threshold", min_value=1, max_value=5, value=2, help="Port scan events per IP required to alert")
            ps_window = st.slider("Port Scan Window (min)", min_value=1, max_value=60, value=15, help="Time window for port scan correlation")

        st.divider()
        st.markdown("#### ℹ️ Project Info")
        st.caption("**Stage 2**: Threat Detection Engine")
        st.caption("**Active Rules**: 5 (BF, FL, SIP, PS, PE)")
        st.caption("No real external network traffic is used.")
    else:
        selected_event_types = []
        selected_statuses = []
        search_user = ""
        search_ip = ""
        bf_thresh, bf_window, fl_thresh, fl_window, sip_thresh, sip_categories, sip_window, ps_thresh, ps_window = 3, 15, 2, 30, 2, 2, 60, 2, 15


# ---------------------------------------------------------
# Filter Processing
# ---------------------------------------------------------
filtered_df = raw_df.copy() if load_success and not raw_df.empty else pd.DataFrame()

if not filtered_df.empty:
    if selected_event_types:
        filtered_df = filtered_df[filtered_df["event_type"].isin(selected_event_types)]
    else:
        filtered_df = filtered_df.iloc[0:0]

    if selected_statuses:
        filtered_df = filtered_df[filtered_df["status"].isin(selected_statuses)]
    else:
        filtered_df = filtered_df.iloc[0:0]

    if search_user:
        filtered_df = filtered_df[
            filtered_df["username"].str.lower().str.contains(search_user, na=False)
        ]

    if search_ip:
        filtered_df = filtered_df[
            filtered_df["source_ip"].str.contains(search_ip, na=False)
        ]


# ---------------------------------------------------------
# Threat Detection Engine Execution
# ---------------------------------------------------------
engine = DetectionEngine(
    brute_force_threshold=bf_thresh,
    brute_force_window_minutes=bf_window,
    failed_logins_threshold=fl_thresh,
    failed_logins_window_minutes=fl_window,
    suspicious_ip_threshold=sip_thresh,
    suspicious_ip_window_minutes=sip_window,
    suspicious_ip_min_categories=sip_categories,
    port_scan_threshold=ps_thresh,
    port_scan_window_minutes=ps_window,
)

# Run detection rules on current dataset
alerts_df = engine.run_all_rules(filtered_df)


# ---------------------------------------------------------
# Main Dashboard Header
# ---------------------------------------------------------
st.markdown(
    """
    <div class="soc-header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>🛡️ Mini SIEM – SOC Monitoring Console</h1>
                <p>Security Information & Event Management System &bull; University Project (Stage 2: Threat Detection Engine)</p>
            </div>
            <div>
                <span class="badge-simulated">LAB ENVIRONMENT</span>
                <span class="badge-engine">ENGINE ACTIVE</span>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# ---------------------------------------------------------
# KPI Metric Cards
# ---------------------------------------------------------
total_events = get_total_events(filtered_df)
successful_logins = get_successful_logins(filtered_df)
failed_logins = get_failed_logins(filtered_df)
security_alerts_count = len(alerts_df)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f"""
        <div class="metric-card card-total">
            <div class="metric-title">📊 Total Events</div>
            <div class="metric-value">{total_events}</div>
            <div class="metric-sub">Matched by current filters</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:
    st.markdown(
        f"""
        <div class="metric-card card-success">
            <div class="metric-title">🔓 Successful Logins</div>
            <div class="metric-value">{successful_logins}</div>
            <div class="metric-sub">Legitimate auth sessions</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col3:
    st.markdown(
        f"""
        <div class="metric-card card-failed">
            <div class="metric-title">⚠️ Failed Logins</div>
            <div class="metric-value">{failed_logins}</div>
            <div class="metric-sub">Potential bad credentials</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col4:
    st.markdown(
        f"""
        <div class="metric-card card-alert">
            <div class="metric-title">🚨 Security Alerts</div>
            <div class="metric-value">{security_alerts_count}</div>
            <div class="metric-sub">Generated by Detection Engine</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.write("")

# ---------------------------------------------------------
# Stage 2: Generated Security Alerts Section
# ---------------------------------------------------------
st.subheader("🚨 Active Threat Alerts (Detection Engine)")

if alerts_df.empty:
    st.info("No security alerts generated for the current log selection. The detection engine rules did not flag any active threats.")
else:
    # Breakdown by severity
    crit_count = len(alerts_df[alerts_df["severity"] == "Critical"])
    high_count = len(alerts_df[alerts_df["severity"] == "High"])
    med_count = len(alerts_df[alerts_df["severity"] == "Medium"])

    st.markdown(
        f"""
        <div class="alert-banner">
            <div><strong>Severity Summary:</strong></div>
            <span class="severity-pill-critical">Critical: {crit_count}</span>
            <span class="severity-pill-high">High: {high_count}</span>
            <span class="severity-pill-medium">Medium: {med_count}</span>
            <div style="margin-left: auto; color: #9ca3af; font-size: 0.85rem;">Generated dynamically across 5 detection rules</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Display Alerts Table
    st.dataframe(
        alerts_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "alert_id": st.column_config.TextColumn("Alert ID", width="small"),
            "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
            "severity": st.column_config.TextColumn("Severity", width="small"),
            "threat_type": st.column_config.TextColumn("Threat Type", width="medium"),
            "source_ip": st.column_config.TextColumn("Source IP", width="small"),
            "username": st.column_config.TextColumn("Target/User", width="small"),
            "detection_rule": st.column_config.TextColumn("Detection Rule", width="large"),
            "explanation": st.column_config.TextColumn("Detection Explanation", width="large"),
        }
    )

    # Detailed Alert Inspection Expander
    with st.expander("🔎 Alert Triage Inspector (Inspect Alert Reason & Context)"):
        selected_alert_idx = st.number_input(
            "Select Alert Row Index to inspect (0 to N-1)",
            min_value=0,
            max_value=max(0, len(alerts_df) - 1),
            step=1,
            value=0,
            key="alert_inspector_idx"
        )
        if len(alerts_df) > 0:
            alert_record = alerts_df.iloc[selected_alert_idx].to_dict()
            st.json(alert_record)

st.write("")

# ---------------------------------------------------------
# Security Events Table Section (Stage 1 Preserved)
# ---------------------------------------------------------
st.subheader("📋 Security Events Log Stream")

if filtered_df.empty:
    st.warning("No security events match the selected filters. Adjust your sidebar filters to view events.")
else:
    showing_txt = f"Showing **{len(filtered_df)}** of **{len(raw_df)}** total events"
    st.caption(showing_txt)

    # Format timestamp for clean presentation in table
    display_df = filtered_df.copy()
    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Column configuration for professional table rendering
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.TextColumn("Timestamp (UTC)", width="medium"),
            "username": st.column_config.TextColumn("Username", width="small"),
            "source_ip": st.column_config.TextColumn("Source IP", width="small"),
            "event_type": st.column_config.TextColumn("Event Type", width="medium"),
            "status": st.column_config.TextColumn("Status", width="small"),
            "details": st.column_config.TextColumn("Activity Details", width="large"),
        }
    )

    # Quick Inspection Expander (Stage 1 Preserved)
    with st.expander("🔎 Raw Event Inspector (Inspect raw log record)"):
        selected_index = st.number_input(
            "Select event row index to inspect (0 to N-1)",
            min_value=0,
            max_value=max(0, len(display_df) - 1),
            step=1,
            value=0,
            key="raw_log_inspector_idx"
        )
        if len(display_df) > 0:
            record = display_df.iloc[selected_index].to_dict()
            st.json(record)

# ---------------------------------------------------------
# Footer
# ---------------------------------------------------------
st.divider()
st.markdown(
    """
    <div style="text-align: center; color: #6b7280; font-size: 0.8rem; margin-top: 10px;">
        Mini SIEM Educational Project &bull; Built with Python &amp; Streamlit &bull; Stage 2: Security Threat Detection Engine
    </div>
    """,
    unsafe_allow_html=True
)
