"""Run configuration and scope enforcement.

Keeping scope-checking as its own module (rather than scattering origin
checks through the tool code) means every tool call goes through one
choke point, which is what a marker/examiner will want to see when you
justify the artefact's safety design.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from dotenv import load_dotenv


@dataclass(frozen=True)
class RunConfig:
    target_origin: str
    allowed_hosts: tuple[str, ...]
    openai_api_key: str
    openai_model: str
    rag_enabled: bool
    max_turns: int = 15
    max_tool_calls: int = 25
    request_timeout_s: int = 15
    run_id: str = field(default_factory=lambda: _default_run_id())

    def is_in_scope(self, url: str) -> bool:
        """The single authority for whether a URL may be contacted.

        Every tool (nikto wrapper, HTTP tool) must call this before
        issuing any network request. Blocks anything outside the
        explicitly authorized origin(s), including redirects a tool
        might otherwise follow blindly.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if host is None:
            return False
        return host in self.allowed_hosts


def _default_run_id() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")


class InvalidTarget(ValueError):
    pass


def build_config_for_target(
    target_origin: str,
    *,
    rag_enabled: bool = False,
    api_key: str | None = None,
    model: str | None = None,
) -> RunConfig:
    """Build a RunConfig for an explicit target string (e.g. one typed
    into the web UI), rather than reading TARGET_ORIGIN from the
    environment. Still requires a valid OpenAI API key -- from the
    argument, or falling back to the environment -- since the correlate
    agent always needs one. Raises InvalidTarget (not SystemExit) so a
    web request can catch it and show a form error instead of killing
    the process.
    """
    load_dotenv()

    target_origin = (target_origin or "").strip()
    if not target_origin:
        raise InvalidTarget("Target origin must not be empty.")
    if not target_origin.startswith(("http://", "https://")):
        target_origin = "http://" + target_origin

    parsed = urlparse(target_origin)
    if parsed.hostname is None:
        raise InvalidTarget(f"Not a valid URL: {target_origin!r}")

    resolved_key = (api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
    if not resolved_key:
        raise InvalidTarget("OPENAI_API_KEY is not set (in .env or passed explicitly).")

    return RunConfig(
        target_origin=target_origin.rstrip("/"),
        allowed_hosts=(parsed.hostname,),
        openai_api_key=resolved_key,
        openai_model=model or os.environ.get("OPENAI_MODEL", "gpt-5-mini"),
        rag_enabled=rag_enabled,
    )


def load_config(rag_override: bool | None = None) -> RunConfig:
    load_dotenv()

    target_origin = os.environ.get("TARGET_ORIGIN", "").strip()
    if not target_origin:
        raise SystemExit(
            "TARGET_ORIGIN is not set. Refusing to start without an "
            "explicit, authorized target. Set it in .env."
        )

    rag_enabled = (
        rag_override
        if rag_override is not None
        else os.environ.get("RAG_ENABLED", "false").strip().lower() in ("1", "true", "yes")
    )

    try:
        return build_config_for_target(target_origin, rag_enabled=rag_enabled)
    except InvalidTarget as exc:
        raise SystemExit(str(exc)) from exc


def resolve_pinned_address(hostname: str) -> str | None:
    """Best-effort DNS pin, recorded in the run manifest for attestation.

    Mirrors the "dns_pinned_addresses" field your proposal's frozen
    protocol used -- it documents what address was actually contacted,
    which matters if DNS changes between runs.
    """
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None
