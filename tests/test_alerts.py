
from network_sniffer.alerts import detect_traffic_alerts


def test_high_traffic_alert():
    records = [
        {
            "source_ip": "192.0.2.10",
            "packet_length_bytes": 100
        }
        for _ in range(10)
    ]

    alerts = detect_traffic_alerts(records)

    assert any("High traffic" in alert for alert in alerts)


def test_large_packet_alert():
    records = [
        {
            "source_ip": "192.0.2.10",
            "packet_length_bytes": 1600
        }
    ]

    alerts = detect_traffic_alerts(records)

    assert any("Large packet detected" in alert for alert in alerts)


def test_normal_traffic_has_no_alert():
    records = [
        {
            "source_ip": "192.0.2.10",
            "packet_length_bytes": 100
        }
    ]

    alerts = detect_traffic_alerts(records)

    assert alerts == ["No alerts triggered."]


def test_empty_records():
    assert detect_traffic_alerts([]) == [
        "No traffic data available to analyze."
    ]
