from agent.config import RunConfig


def make_config(target="http://10.15.20.21:3001"):
    return RunConfig(
        target_origin=target,
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_in_scope_url_allowed():
    cfg = make_config()
    assert cfg.is_in_scope("http://10.15.20.21:3001/rest/products")


def test_out_of_scope_host_blocked():
    cfg = make_config()
    assert not cfg.is_in_scope("http://evil.example.com/")


def test_out_of_scope_different_ip_blocked():
    cfg = make_config()
    assert not cfg.is_in_scope("http://10.15.20.22:3001/")


def test_non_http_scheme_blocked():
    cfg = make_config()
    assert not cfg.is_in_scope("file:///etc/passwd")
    assert not cfg.is_in_scope("ftp://10.15.20.21/")
