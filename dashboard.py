import threading
from network_sniffer.alerts import detect_traffic_alerts
from network_sniffer.analyzer import analyze_packet
from network_sniffer.capture import live_capture, list_interfaces
from network_sniffer.exporter import export_csv

from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

# ----------------------------------
# 1. Project paths
# ----------------------------------

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

REPORT_FILES = {
    "Live Traffic Report": REPORTS_DIR / "live_traffic_report.csv",
    "Demo Traffic Report": REPORTS_DIR / "demo_traffic_report.csv",
}

REQUIRED_COLUMNS = [
    "timestamp_utc",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_length_bytes",
]

# ----------------------------------
# 2. Page configuration
# ----------------------------------

st.set_page_config(
    page_title="NETSENTRY Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ NETSENTRY")
st.subheader("Network Traffic Analyzer Dashboard")
st.caption("Network packet metadata and traffic statistics")

# ----------------------------------
# 3. Sidebar controls
# ----------------------------------

st.sidebar.title("NETSENTRY Controls")

selected_report = st.sidebar.selectbox(
    "Select Traffic Report",
    list(REPORT_FILES.keys()),
)

auto_refresh = st.sidebar.toggle(
    "Enable Automatic Refresh",
    value=True,
)

refresh_seconds = st.sidebar.selectbox(
    "Refresh Interval",
    options=[5, 10, 15, 30, 60],
    index=1,
    format_func=lambda seconds: f"{seconds} seconds",
    disabled=not auto_refresh,
)

if st.sidebar.button("🔄 Refresh Now", width="stretch"):
    st.rerun()

st.sidebar.info(
    "Automatic refresh reloads the saved CSV report. "
    "It does not start packet capture."
)
# ----------------------------------
# Live Capture State
# ----------------------------------

if "capture_state" not in st.session_state:
    st.session_state.capture_state = {
        "running": False,
        "packet_count": 0,
        "status": "Ready",
        "error": None,
    }

if "capture_stop_event" not in st.session_state:
    st.session_state.capture_stop_event = None

if "capture_thread" not in st.session_state:
    st.session_state.capture_thread = None


def capture_worker(interface, state, stop_event):
    """Capture packet metadata in a background thread."""

    records = []
    output_path = REPORT_FILES["Live Traffic Report"]

    def process_packet(packet):
        record = analyze_packet(packet)

        if record is not None:
            records.append(record)
            state["packet_count"] = len(records)

            # Save the latest report after every analyzed packet.
            export_csv(records, output_path)

    try:
        live_capture(
            count=10,
            callback=process_packet,
            interface=interface,
            stop_event=stop_event,
        )

        # Ensure the report exists even if no packets were analyzed.
        export_csv(records, output_path)

        if stop_event.is_set():
            state["status"] = "Stopped"
        else:
            state["status"] = "Finished"

    except Exception as error:
        state["error"] = str(error)
        state["status"] = "Error"

    finally:
        state["running"] = False


# ----------------------------------
# Live Capture Controls
# ----------------------------------

@st.fragment(run_every="1s")
def show_capture_controls():
    state = st.session_state.capture_state

    st.divider()
    st.header("🎛️ Live Capture Controls")
    st.caption(
        "Capture up to 10 packets on an interface you are "
        "authorized to monitor."
    )

    try:
        interfaces = list_interfaces()
    except Exception as error:
        interfaces = []
        st.error(f"Could not list network interfaces: {error}")

    if not interfaces:
        st.warning(
            "No interfaces found. Check Npcap and your "
            "network adapter configuration."
        )
        return

    selected_interface = st.selectbox(
        "Select network interface",
        interfaces,
        key="capture_interface",
        disabled=state["running"],
    )

    authorized = st.checkbox(
        "I am authorized to monitor this network.",
        key="capture_authorized",
        disabled=state["running"],
    )

    start_col, stop_col = st.columns(2)

    with start_col:
        start_clicked = st.button(
            "▶️ Start Capture",
            width="stretch",
            disabled=state["running"] or not authorized,
        )

    with stop_col:
        stop_clicked = st.button(
            "⏹️ Stop Capture",
            width="stretch",
            disabled=not state["running"],
        )

    if start_clicked:
        # Reset the previous run's status.
        state["packet_count"] = 0
        state["error"] = None
        state["status"] = "Starting"
        state["running"] = True

        stop_event = threading.Event()
        st.session_state.capture_stop_event = stop_event

        worker = threading.Thread(
            target=capture_worker,
            args=(selected_interface, state, stop_event),
            daemon=True,
        )

        st.session_state.capture_thread = worker
        worker.start()

    if stop_clicked:
        stop_event = st.session_state.capture_stop_event

        if stop_event is not None:
            stop_event.set()
            state["status"] = "Stopping..."

    # The fragment refreshes this status every second.
    if state["running"]:
        st.info("Capture is running...")
    elif state["status"] == "Finished":
        st.success("Capture finished.")
    elif state["status"] == "Stopped":
        st.warning("Capture stopped.")
    elif state["status"] == "Error":
        st.error(f"Capture failed: {state['error']}")
    else:
        st.caption(f"Status: {state['status']}")

    metric_col1, metric_col2 = st.columns(2)

    metric_col1.metric(
        "Packets Analyzed",
        state["packet_count"],
    )

    metric_col2.metric(
        "Capture Status",
        state["status"],
    )


show_capture_controls()
report_path = REPORT_FILES[selected_report]

# ----------------------------------
# 4. Dashboard refresh function
# ----------------------------------

@st.fragment(run_every="2s")
def display_dashboard():
    """Reload and display the selected CSV report."""

    st.caption(
        f"Selected report: {report_path.name}"
    )

    if not report_path.exists():
        st.warning(
            f"{report_path.name} not found. "
            "Run NETSENTRY in Demo or Live mode first."
        )
        return

    try:
        # Read the latest saved CSV on every refresh
        df = pd.read_csv(report_path)

    except (
        OSError,
        pd.errors.ParserError,
        UnicodeDecodeError,
    ) as error:
        st.error(f"Could not read CSV report: {error}")
        return

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        st.error(
            "Missing columns: " + ", ".join(missing_columns)
        )
        return

    if df.empty:
        st.info(
            "The report is empty. Generate a demo report "
            "or capture some packets first."
        )
        return

    # ----------------------------------
    # 5. Clean and prepare data
    # ----------------------------------

    df["protocol"] = (
        df["protocol"]
        .fillna("Unknown")
        .astype(str)
        .str.upper()
    )

    df["source_ip"] = (
        df["source_ip"].fillna("Unknown").astype(str)
    )

    df["destination_ip"] = (
        df["destination_ip"].fillna("Unknown").astype(str)
    )

    df["packet_length_bytes"] = pd.to_numeric(
        df["packet_length_bytes"],
        errors="coerce",
    ).fillna(0)

    df["destination_port"] = (
        df["destination_port"]
        .fillna("")
        .astype(str)
        .replace("nan", "")
    )

    df["timestamp_utc"] = pd.to_datetime(
        df["timestamp_utc"],
        errors="coerce",
        utc=True,
    )

    
    # ----------------------------------
    # Traffic Alerts
    # ----------------------------------

    st.divider()
    st.header("🚨 Traffic Alerts")

    alert_records = df.fillna("").to_dict(orient="records")
    alerts = detect_traffic_alerts(alert_records)

    for alert in alerts:
        if alert.startswith("High traffic:"):
            st.warning(alert)
        elif alert.startswith("Large packet detected:"):
            st.warning(alert)
        elif alert == "No alerts triggered.":
            st.success(alert)
        else:
            st.info(alert)


    # ----------------------------------
    # 6. Calculate traffic metrics
    # ----------------------------------

    total_packets = len(df)

    total_bytes = int(
        df["packet_length_bytes"].sum()
    )

    average_size = (
        total_bytes / total_packets
        if total_packets > 0
        else 0
    )

    protocol_counts = df["protocol"].value_counts()

    # ----------------------------------
    # 7. Traffic overview
    # ----------------------------------

    st.divider()
    st.header("📊 Traffic Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Packets",
        f"{total_packets:,}",
    )

    col2.metric(
        "Total Bytes",
        f"{total_bytes:,} B",
    )

    col3.metric(
        "Average Packet Size",
        f"{average_size:.2f} B",
    )

    col4.metric(
        "Unique Protocols",
        str(df["protocol"].nunique()),
    )

    # ----------------------------------
    # 8. Protocol and source IP charts
    # ----------------------------------

    st.divider()
    st.header("📈 Traffic Analysis")

    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("Protocol Distribution")

        protocol_chart = (
            protocol_counts
            .rename_axis("Protocol")
            .reset_index(name="Packets")
        )

        st.bar_chart(
            protocol_chart,
            x="Protocol",
            y="Packets",
        )

        st.dataframe(
            protocol_chart,
            width="stretch",
            hide_index=True,
        )

    with right_col:
        st.subheader("Top Source IPs")

        source_counts = (
            df["source_ip"]
            .value_counts()
            .head(5)
            .rename_axis("Source IP")
            .reset_index(name="Packets")
        )

        st.bar_chart(
            source_counts,
            x="Source IP",
            y="Packets",
        )

        st.dataframe(
            source_counts,
            width="stretch",
            hide_index=True,
        )

    # ----------------------------------
    # 9. Destination port chart
    # ----------------------------------

    st.divider()
    st.subheader("Destination Port Statistics")

    ports_df = df[
        df["destination_port"].str.strip() != ""
    ]

    if ports_df.empty:
        st.info("No destination port data is available.")
    else:
        port_counts = (
            ports_df["destination_port"]
            .value_counts()
            .head(10)
            .rename_axis("Destination Port")
            .reset_index(name="Packets")
        )

        st.bar_chart(
            port_counts,
            x="Destination Port",
            y="Packets",
        )

    # ----------------------------------
    # 10. Packet records and filter
    # ----------------------------------

    st.divider()
    st.header("📋 Packet Records")

    available_protocols = [
        "All",
        *sorted(df["protocol"].unique().tolist()),
    ]

    selected_protocol = st.selectbox(
        "Filter by Protocol",
        available_protocols,
        key="packet_protocol_filter",
    )

    filtered_df = df.copy()

    if selected_protocol != "All":
        filtered_df = filtered_df[
            filtered_df["protocol"] == selected_protocol
        ]

    filtered_df = filtered_df.sort_values(
        "timestamp_utc",
        ascending=False,
        na_position="last",
    )

    st.caption(
        f"Showing {len(filtered_df)} of "
        f"{total_packets} packets."
    )

    st.dataframe(
        filtered_df[REQUIRED_COLUMNS],
        width="stretch",
        hide_index=True,
    )

    # ----------------------------------
    # 11. Download report
    # ----------------------------------

    csv_data = df[REQUIRED_COLUMNS].to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="⬇️ Download CSV Report",
        data=csv_data,
        file_name=report_path.name,
        mime="text/csv",
        width="stretch",
        key="download_traffic_csv",
    )

    # ----------------------------------
    # 12. Refresh status
    # ----------------------------------

    st.divider()

    st.caption(
        "Last dashboard refresh: "
        + datetime.now().astimezone().strftime(
            "%d-%m-%Y %I:%M:%S %p"
        )
    )

    if auto_refresh:
        st.caption(
            f"Automatic refresh enabled: every "
            f"{refresh_seconds} seconds."
        )
    else:
        st.caption("Automatic refresh is disabled.")

    st.caption(
        "NETSENTRY | Metadata analysis only | "
        "Monitor only networks you are authorized to use."
    )


# ----------------------------------
# 13. Start dashboard display
# ----------------------------------

display_dashboard()
