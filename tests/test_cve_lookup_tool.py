from unittest.mock import MagicMock, patch

from agent.tools.cve_lookup_tool import CveLookupClient


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-99999",
                "descriptions": [{"lang": "en", "value": "A test vulnerability description."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}, "baseSeverity": "HIGH"}
                    ]
                },
                "published": "2023-01-01T00:00:00.000",
            }
        }
    ]
}


def test_cve_lookup_parses_response_and_caches():
    client = CveLookupClient()
    client._last_call = 0  # avoid sleeping in the test

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_NVD_RESPONSE

    with patch("agent.tools.cve_lookup_tool.requests.get", return_value=mock_resp) as mock_get:
        result1 = client.lookup("Node.js", "20.3.0")
        result2 = client.lookup("Node.js", "20.3.0")  # should hit cache, not call again

    assert mock_get.call_count == 1  # second call used the cache
    assert len(result1.records) == 1
    assert result1.records[0].cve_id == "CVE-2023-99999"
    assert result1.records[0].cvss_v3_score == 7.5
    assert result2.records[0].cve_id == "CVE-2023-99999"


def test_cve_lookup_handles_non_200_gracefully():
    client = CveLookupClient()
    client._last_call = 0

    mock_resp = MagicMock()
    mock_resp.status_code = 503

    with patch("agent.tools.cve_lookup_tool.requests.get", return_value=mock_resp):
        result = client.lookup("SomeProduct", "1.0")

    assert result.records == []
    assert result.error is not None
    assert "503" in result.error


def test_cve_lookup_handles_network_error_gracefully():
    import requests

    client = CveLookupClient()
    client._last_call = 0

    with patch("agent.tools.cve_lookup_tool.requests.get", side_effect=requests.ConnectionError("boom")):
        result = client.lookup("SomeProduct", "1.0")

    assert result.records == []
    assert "boom" in result.error
