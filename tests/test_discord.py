import datetime

from src import main

#tests whether discord alerting exits safely when no webhook URL is configured.
def test_send_alert_no_webhook(monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_URL", "")

    alerts = [{
        "ip": "1.1.1.1",
        "time": datetime.datetime.now(),
        "reason": "Test",
        "type": "test",
        "severity": "low"
    }]

    main.send_alert(alerts)
