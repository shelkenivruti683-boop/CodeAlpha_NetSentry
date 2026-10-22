
import pytest

from network_sniffer.capture import live_capture


def test_rejects_zero_packet_count():
    with pytest.raises(ValueError, match=r"count must be between 1 and 10"):
        live_capture(0, callback=lambda packet: None)


def test_rejects_packet_count_above_limit():
    with pytest.raises(ValueError, match=r"count must be between 1 and 10"):
        live_capture(11, callback=lambda packet: None)


def test_rejects_missing_interface(monkeypatch):
    monkeypatch.setattr(
        "network_sniffer.capture.list_interfaces",
        lambda: ["test-interface"],
    )

    with pytest.raises(ValueError, match="select a network interface"):
        live_capture(1, callback=lambda packet: None)


def test_rejects_unknown_interface(monkeypatch):
    monkeypatch.setattr(
        "network_sniffer.capture.list_interfaces",
        lambda: ["test-interface"],
    )

    with pytest.raises(ValueError, match="Unknown interface"):
        live_capture(
            1,
            callback=lambda packet: None,
            interface="invalid-interface",
        )


def test_capture_finishes_when_no_packets_arrive(monkeypatch, capsys):
    from network_sniffer import capture

    monkeypatch.setattr(
        capture,
        "list_interfaces",
        lambda: ["test-interface"],
    )

    monkeypatch.setattr(
        capture,
        "sniff",
        lambda **kwargs: None,
    )

    # Simulate time passing beyond the 30-second limit.
    times = iter([0, 0, 31, 31])
    monkeypatch.setattr(
        capture.time,
        "monotonic",
        lambda: next(times, 31),
    )

    capture.live_capture(
        1,
        callback=lambda packet: None,
        interface="test-interface",
    )

    output = capsys.readouterr().out
    assert "Raw packets received: 0" in output
    assert "Packet capture finished." in output

def test_capture_error_is_propagated(monkeypatch):
    from network_sniffer import capture

    monkeypatch.setattr(
        capture,
        "list_interfaces",
        lambda: ["test-interface"],
    )

    def fake_sniff(**kwargs):
        raise RuntimeError("Simulated capture failure")

    monkeypatch.setattr(capture, "sniff", fake_sniff)

    monkeypatch.setattr(capture.time, "monotonic", lambda: 0)

    with pytest.raises(RuntimeError, match="Simulated capture failure"):
        capture.live_capture(
            1,
            callback=lambda packet: None,
            interface="test-interface",
        )
