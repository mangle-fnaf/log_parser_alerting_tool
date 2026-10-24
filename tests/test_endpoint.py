import datetime

from src.main import detect_endpoint_scanning

#tests whether access to multiple unique endpoints from the same IP is detected as endpoint scanning behaviour.
def test_endpoint_scanning_detection():
    events = []

    for i in range(6):
        events.append({
            "timestamp": datetime.datetime(2024, 10, 5, 10, 0, i),
            "ip": "1.1.1.1",
            "method": "GET",
            "path": f"/page{i}",
            "status": "200",
            "user_agent": "Mozilla"
        })

    alerts = detect_endpoint_scanning(events)

    assert len(alerts) > 0
    assert alerts[0]["type"] == "endpoint_scan"