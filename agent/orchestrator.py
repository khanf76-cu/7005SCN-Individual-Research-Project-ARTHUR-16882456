"""Orchestrator: runs recon -> nmap -> va (in parallel, since they're
independent) -> correlate, under one run_id / evidence directory.

Parallelising recon/nmap/va is safe because each uses its own tool
subprocess and the scoped HTTP calls are independent requests; nmap and
nikto both target the same host but are separate processes, not shared
mutable state. Correlate always runs last since it depends on all three
outputs.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .agents.correlate_agent import CorrelateAgentResult, run_correlate_agent
from .agents.nmap_agent import NmapAgentResult, run_nmap_agent
from .agents.recon_agent import ReconAgentResult, run_recon_agent
from .agents.va_agent import VaAgentResult, run_va_agent
from .config import RunConfig, resolve_pinned_address
from .evidence import EvidenceLogger

HERE = Path(__file__).resolve().parent


@dataclass
class OrchestratorResult:
    run_id: str
    target_origin: str
    recon: ReconAgentResult | None = None
    nmap: NmapAgentResult | None = None
    va: VaAgentResult | None = None
    correlate: CorrelateAgentResult | None = None
    errors: dict[str, str] = field(default_factory=dict)
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "target_origin": self.target_origin,
            "recon": asdict(self.recon) if self.recon else None,
            "nmap": asdict(self.nmap) if self.nmap else None,
            "va": asdict(self.va) if self.va else None,
            "correlate": asdict(self.correlate) if self.correlate else None,
            "errors": self.errors,
            "duration_s": self.duration_s,
        }


def run_full_assessment(
    config: RunConfig,
    out_dir: Path,
    *,
    corpus_dir: Path | None = None,
    skip_nmap: bool = False,
    progress_callback=None,
) -> OrchestratorResult:
    """progress_callback(stage: str, status: str, result=None) is called
    at the start and end of each stage, so a caller (e.g. the web UI)
    can show live status without polling internal state. `result` is
    the agent's dataclass result (ReconAgentResult etc.), passed only
    on a "completed" or "skipped" call, so a live view can render that
    agent's findings the moment it finishes -- independently of the
    other two agents it ran alongside."""

    def notify(stage: str, status: str, result=None) -> None:
        if progress_callback:
            progress_callback(stage, status, result)

    evidence = EvidenceLogger(run_id=config.run_id, out_dir=out_dir)
    pinned_ip = resolve_pinned_address(config.allowed_hosts[0])
    evidence.write_manifest(
        {
            "run_id": config.run_id,
            "target_origin": config.target_origin,
            "allowed_hosts": list(config.allowed_hosts),
            "dns_pinned_address": pinned_ip,
            "rag_enabled": config.rag_enabled,
            "model": config.openai_model,
            "skip_nmap": skip_nmap,
            "created_at_utc": time.time(),
        }
    )
    evidence.log("RUN_START", pipeline="multi-agent", target=config.target_origin)

    result = OrchestratorResult(run_id=config.run_id, target_origin=config.target_origin)
    started = time.time()

    stage_evidence = {
        "recon": EvidenceLogger(run_id=f"{config.run_id}-recon", out_dir=out_dir / "recon"),
        "nmap": EvidenceLogger(run_id=f"{config.run_id}-nmap", out_dir=out_dir / "nmap"),
        "va": EvidenceLogger(run_id=f"{config.run_id}-va", out_dir=out_dir / "va"),
    }

    def _run_recon():
        notify("recon", "running")
        try:
            r = run_recon_agent(config, stage_evidence["recon"])
            notify("recon", "completed", r)
            return ("recon", r, None)
        except Exception as exc:  # noqa: BLE001 -- isolate one agent's failure from the rest
            notify("recon", "failed")
            return ("recon", None, str(exc))

    def _run_nmap():
        if skip_nmap:
            skipped = NmapAgentResult()
            notify("nmap", "skipped", skipped)
            return ("nmap", skipped, None)
        notify("nmap", "running")
        try:
            r = run_nmap_agent(config, stage_evidence["nmap"])
            notify("nmap", "completed", r)
            return ("nmap", r, None)
        except Exception as exc:  # noqa: BLE001
            notify("nmap", "failed")
            return ("nmap", None, str(exc))

    def _run_va():
        notify("va", "running")
        try:
            r = run_va_agent(config, stage_evidence["va"])
            notify("va", "completed", r)
            return ("va", r, None)
        except Exception as exc:  # noqa: BLE001
            notify("va", "failed")
            return ("va", None, str(exc))

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(_run_recon), pool.submit(_run_nmap), pool.submit(_run_va)]
        for fut in futures:
            name, value, error = fut.result()
            if error:
                result.errors[name] = error
            setattr(result, name, value)

    notify("correlate", "running")
    try:
        correlate_evidence = EvidenceLogger(run_id=f"{config.run_id}-correlate", out_dir=out_dir / "correlate")
        result.correlate = run_correlate_agent(
            config,
            correlate_evidence,
            recon_findings=(result.recon.findings if result.recon else []),
            nmap_findings=(result.nmap.findings if result.nmap else []),
            va_findings=(result.va.findings if result.va else []),
            corpus_dir=corpus_dir,
        )
        notify("correlate", "completed", result.correlate)
    except Exception as exc:  # noqa: BLE001
        result.errors["correlate"] = str(exc)
        notify("correlate", "failed")

    result.duration_s = time.time() - started
    evidence.log("RUN_END", duration_s=result.duration_s, errors=result.errors)
    return result
