import datetime

from src.main import dedupe_alerts

#tests whether deduplication keeps the strongest alert when multiple alerts exist for the same IP and rule type.
def test_dedupe_keeps_strongest_alert():
    alerts = [
        {
            "ip": "1.1.1.1",
            "type": "high_volume",
            "reason": "10 requests in 5s",
            "severity": "medium",
            "time": datetime.datetime.now()
        },
        {
            "ip": "1.1.1.1",
            "type": "high_volume",
            "reason": "20 requests in 5s",
            "severity": "medium",
            "time": datetime.datetime.now()
        }
    ]

    result = dedupe_alerts(alerts)

    assert len(result) == 1
    assert result[0]["reason"] == "20 requests in 5s"