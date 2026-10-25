import datetime
import os

from src.main import export_json

#tests whether alerts can be exported to a JSON file successfully.
def test_export_json_creates_file():
    alerts = [{
        "ip": "1.1.1.1",
        "time": datetime.datetime.now(),
        "reason": "Test Alert",
        "type": "test",
        "severity": "low"
    }]

    export_json(alerts)

    assert os.path.exists("alerts")