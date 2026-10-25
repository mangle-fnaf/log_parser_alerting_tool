from src.main import enrich_geoip

#tests whether GeoIP enrichment handles invalid IP addresses without crashing.
def test_geoip_invalid_ip():
    alerts = [{
        "ip": "not_an_ip"
    }]

    result = enrich_geoip(alerts)

    assert "geoip" in result[0]