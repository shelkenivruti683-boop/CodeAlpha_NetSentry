
import streamlit as st
import pandas as pd
import plotly.express as px
from network_sniffer.alerts import detect_traffic_alerts
from network_sniffer.analyzer import analyze_packet
from network_sniffer.capture import demo_packets
from network_sniffer.exporter import export_csv


st.set_page_config(
    page_title="NetSentry | Network Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ NetSentry")
st.caption("Network Traffic Analyzer | Cybersecurity Project")

st.info(
    "Demo mode uses synthetic packets. "
    "No real network traffic is captured in this dashboard."
)

if st.button("Analyze Demo Traffic", type="primary"):
    records = [
        analyze_packet(packet)
        for packet in demo_packets()
    ]
    records = [record for record in records if record is not None]

    if records:
        df = pd.DataFrame(records)
        st.session_state["traffic_df"] = df

if "traffic_df" in st.session_state:
    df = st.session_state["traffic_df"].copy()

    st.subheader("Traffic Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Packets", len(df))
    col2.metric("Protocols", df["protocol"].nunique())
    col3.metric("Total Bytes", int(df["packet_length_bytes"].sum()))

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Protocol Distribution")
        protocol_counts = (
            df["protocol"].value_counts().rename_axis("Protocol")
            .reset_index(name="Packets")
        )
        fig = px.pie(
            protocol_counts,
            names="Protocol",
            values="Packets",
            hole=0.45,
            title="Packets by Protocol",
        )
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Packet Size")
        fig = px.bar(
            df,
            x="protocol",
            y="packet_length_bytes",
            color="protocol",
            labels={
                "protocol": "Protocol",
                "packet_length_bytes": "Packet Size (bytes)",
            },
        )
        st.plotly_chart(fig, use_container_width=True)
    st.subheader("Traffic Alerts")

    alert_records = df.to_dict(orient="records")
    alerts = detect_traffic_alerts(alert_records)

    for alert in alerts:
        if alert == "No alerts triggered.":
            st.success(alert)
        elif alert == "No traffic data available to analyze.":
            st.info(alert)
        else:
            st.warning(alert)

    st.subheader("Packet Details")

    protocols = ["All"] + sorted(df["protocol"].unique().tolist())
    selected_protocol = st.selectbox("Filter by protocol", protocols)

    if selected_protocol != "All":
        df = df[df["protocol"] == selected_protocol]

    search_ip = st.text_input("Search source or destination IP")

    if search_ip.strip():
        mask = (
            df["source_ip"].str.contains(search_ip, regex=False)
            | df["destination_ip"].str.contains(search_ip, regex=False)
        )
        df = df[mask]

    st.dataframe(df, use_container_width=True, hide_index=True)

    csv_data = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download CSV Report",
        data=csv_data,
        file_name="netsentry_traffic_report.csv",
        mime="text/csv",
    )

else:
    st.warning("Click 'Analyze Demo Traffic' to generate the dashboard.")
