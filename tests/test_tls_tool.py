import ssl
from unittest.mock import MagicMock, patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.tls_tool import run_tls_check


def make_config(target="https://10.15.20.21:3001"):
    return RunConfig(
        target_origin=target,
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_tls_check_not_applicable_for_plain_http(tmp_path):
    cfg = make_config(target="http://10.15.20.21:3001")
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)
    result = run_tls_check(cfg, evidence)
    assert result.applicable is False
    assert result.issues == []


def test_tls_check_flags_weak_protocol_and_expiring_cert(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    import datetime

    fake_cert = MagicMock()
    fake_cert.subject.rfc4514_string.return_value = "CN=10.15.20.21"
    fake_cert.issuer.rfc4514_string.return_value = "CN=Some Real CA"
    fake_cert.subject.get_attributes_for_oid.return_value = []
    fake_cert.issuer.get_attributes_for_oid.return_value = []
    fake_cert.not_valid_after_utc = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3)

    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.1"
    mock_ssock.getpeercert.return_value = b"fake-der-bytes"
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = False

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_ssock

    with patch("agent.tools.tls_tool.socket.create_connection", return_value=mock_sock), \
         patch("agent.tools.tls_tool.ssl.create_default_context", return_value=mock_ctx), \
         patch("agent.tools.tls_tool.ssl.SSLContext", return_value=mock_ctx), \
         patch("agent.tools.tls_tool.x509.load_der_x509_certificate", return_value=fake_cert):
        result = run_tls_check(cfg, evidence)

    assert result.applicable is True
    kinds = {i.kind for i in result.issues}
    assert "weak_protocol" in kinds
    assert "expiring_soon" in kinds


def test_tls_check_handles_connection_failure(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    with patch("agent.tools.tls_tool.socket.create_connection", side_effect=OSError("connection refused")):
        result = run_tls_check(cfg, evidence)

    assert result.applicable is True
    assert result.error is not None
    assert "connection refused" in result.error
