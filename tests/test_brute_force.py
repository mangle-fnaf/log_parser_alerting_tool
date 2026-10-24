import datetime

from src.main import detect_bruteforce

#tests whether repeated failed login attempts within the configured time window are detected as a brute force attack.
def test_bruteforce_detection():
    events = [
        {
            "timestamp": datetime.datetime(2024, 10, 5, 10, 0, 0),
            "ip": "1.1.1.1",
            "method": "POST",
            "path": "/login",
            "status": "401",
            "user_agent": "Mozilla"
        },
        {
            "timestamp": datetime.datetime(2024, 10, 5, 10, 0, 2),
            "ip": "1.1.1.1",
            "method": "POST",
            "path": "/login",
            "status": "401",
            "user_agent": "Mozilla"
        },
        {
            "timestamp": datetime.datetime(2024, 10, 5, 10, 0, 4),
            "ip": "1.1.1.1",
            "method": "POST",
            "path": "/login",
            "status": "401",
            "user_agent": "Mozilla"
        }
    ]

    alerts = detect_bruteforce(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "bruteforce"