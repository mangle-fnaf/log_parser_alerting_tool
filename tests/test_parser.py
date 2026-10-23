from src.main import parse_log_line

#tests whether a valid log line is parsed correctly and all expected fields are returned.
def test_parse_valid_log():
    line = "2024-10-05 10:01:01 192.168.0.10 GET /login 401 curl/7.88.1"

    result = parse_log_line(line)

    assert result is not None
    assert result["ip"] == "192.168.0.10"
    assert result["path"] == "/login"
    assert result["status"] == "401"


#tests whether invalid log entries return None rather than causing errors.
def test_parse_invalid_log():
    result = parse_log_line("bad log line")

    assert result is None
