import datetime

from src.main import detect_high_volume

#tests whether a large number of requests from the same IP are detected as high volume activity.
def test_high_volume_detection():
    events = []

    for i in range(12):
        events.append({
            "timestamp": datetime.datetime(2024, 10, 5, 10, 0, 0),
            "ip": "1.1.1.1",
            "method": "GET",
            "path": "/home",
            "status": "200",
            "user_agent": "Mozilla"
        })

    alerts = detect_high_volume(events)

    assert len(alerts) > 0
    assert alerts[0]["type"] == "high_volume"