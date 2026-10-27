"""Correlate agent: merges recon/nmap/va findings, enriches with live CVE
lookups, pulls RAG context, and asks GPT-5-mini to produce a final,
de-duplicated, risk-ranked report.

This is the only agent that calls the LLM and the only one that reaches
the open internet (via cve_lookup_tool, for public CVE data only -- see
that module's docstring). Its output is the artefact's final report:
JSON-serialisable, and what the web UI renders to HTML/PDF.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from openai import OpenAI

from ..config import RunConfig
from ..evidence import EvidenceLogger
from ..findings import Finding
from ..rag import RagCorpus
from ..tools.cve_lookup_tool import CveLookupClient

SYSTEM_PROMPT = """You are a senior penetration tester writing the final \
correlated report for an authorized security assessment. You are given:
1. Raw findings from three specialist agents (recon, nmap, va/nikto).
2. Live CVE data looked up for the exact product/version strings nmap \
detected, from the public NVD database.
3. Retrieved reference material on common vulnerability classes.

Your job:
- De-duplicate findings that describe the same underlying issue seen by \
more than one agent (e.g. nikto flags a path that recon's dirbrute also \
found).
- For each finding, assign a final severity (info/low/medium/high/\
critical) and confidence (confirmed/suspected), using the CVE data to \
upgrade confidence/severity ONLY when a looked-up CVE genuinely matches \
the detected product and version -- do not assume a CVE applies just \
because the product name is similar.
- Never invent a finding that isn't backed by evidence in the input. If \
evidence is weak or ambiguous, say so explicitly rather than rounding up \
to a confirmed vulnerability.
- Write a short executive summary (3-5 sentences) in your own words.
- Return STRICT JSON only, matching the schema given in the user message.
"""

OUTPUT_SCHEMA_HINT = """Return a JSON object with exactly this shape:
{
  "executive_summary": "string",
  "overall_risk_rating": "low|medium|high|critical",
  "findings": [
    {
      "title": "string",
      "category": "string",
      "severity": "info|low|medium|high|critical",
      "confidence": "confirmed|suspected",
      "endpoint": "string",
      "evidence": "string, cite which agent(s) and what was observed",
      "related_cves": ["CVE-XXXX-XXXXX", ...],
      "source_agents": ["recon","nmap","va"]
    }
  ],
  "deduplication_notes": "string describing what was merged, if anything"
}
"""


# Previously the raw findings JSON was hard-sliced at 12,000 characters,
# which silently cut off whatever came last (in practice ZAP's alerts,
# since VA findings are appended after recon/nmap) and could cut the JSON
# mid-object. Now every finding is sent. Repeated alerts are grouped
# losslessly (all endpoints kept, with an occurrence count) so the model
# sees one entry per distinct issue instead of ~100 near-identical copies.
MAX_EVIDENCE_CHARS = 400

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def compact_findings(findings: list[Finding]) -> list[dict]:
    """Group identical observations without discarding any of them.

    Findings sharing agent, tool, title, category and severity become one
    group listing every endpoint they were seen on plus an occurrence
    count. Groups are ordered highest-severity first.
    """
    groups: dict[tuple, dict] = {}
    for f in findings:
        tool = (f.extra or {}).get("tool", "")
        key = (f.source_agent, tool, f.title, f.category, f.severity)
        g = groups.get(key)
        if g is None:
            g = {
                "source_agent": f.source_agent,
                "tool": tool,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "occurrences": 0,
                "endpoints": [],
                "sample_evidence": (f.evidence or "")[:MAX_EVIDENCE_CHARS],
            }
            groups[key] = g
        g["occurrences"] += 1
        if f.confidence == "confirmed":
            g["confidence"] = "confirmed"
        if f.endpoint and f.endpoint not in g["endpoints"]:
            g["endpoints"].append(f.endpoint)

    return sorted(
        groups.values(),
        key=lambda g: (-_SEVERITY_RANK.get(g["severity"], 0), -g["occurrences"], g["title"]),
    )


@dataclass
class CorrelateAgentResult:
    executive_summary: str = ""
    overall_risk_rating: str = "info"
    findings: list[dict] = field(default_factory=list)
    deduplication_notes: str = ""
    cve_lookups_performed: int = 0
    rag_retrievals: int = 0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_s: float = 0.0
    raw_input_finding_count: int = 0
    grouped_finding_count: int = 0


def run_correlate_agent(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    recon_findings: list[Finding],
    nmap_findings: list[Finding],
    va_findings: list[Finding],
    corpus_dir: Path | None = None,
) -> CorrelateAgentResult:
    started = time.time()
    evidence.log("AGENT_START", agent="correlate")

    all_findings = recon_findings + nmap_findings + va_findings
    cve_client = CveLookupClient()
    cve_lookups = 0
    cve_context_lines: list[str] = []

    # Look up CVEs for every detected service with a product+version,
    # from the nmap agent's output specifically (that's the only agent
    # with reliable version strings).
    for f in nmap_findings:
        if f.category != "service_version":
            continue
        product = f.extra.get("product")
        version = f.extra.get("version")
        if not product:
            continue

        lookup = cve_client.lookup(product, version)
        cve_lookups += 1
        evidence.log(
            "CVE_LOOKUP",
            query=lookup.query,
            result_count=len(lookup.records),
            error=lookup.error,
        )
        if lookup.records:
            for rec in lookup.records[:3]:
                cve_context_lines.append(
                    f"- {product} {version or ''}: {rec.cve_id} "
                    f"(CVSS {rec.cvss_v3_score or 'n/a'}, {rec.severity or 'n/a'}) "
                    f"-- {rec.description[:200]}"
                )
        elif lookup.error:
            cve_context_lines.append(f"- {product} {version or ''}: CVE lookup failed: {lookup.error}")
        else:
            cve_context_lines.append(f"- {product} {version or ''}: no CVEs found in NVD for this query")

    # RAG retrieval: pull reference material relevant to the categories
    # of findings actually seen this run, so the model gets grounded
    # context on the specific vuln classes in play.
    rag_retrievals = 0
    rag_context = ""
    if corpus_dir is not None:
        corpus = RagCorpus(corpus_dir)
        query_terms = " ".join(
            sorted({f.category for f in all_findings} | {f.title for f in all_findings[:5]})
        )
        retrieved = corpus.retrieve(query_terms, k=5)
        rag_retrievals = len(retrieved)
        if retrieved:
            evidence.log(
                "RAG_RETRIEVAL",
                query=query_terms[:300],
                retrieved_doc_ids=[d.doc_id for d in retrieved],
                scores=[d.score for d in retrieved],
            )
            rag_context = "\n\n".join(f"[{d.doc_id}]\n{d.text}" for d in retrieved)

    # Every finding is included (no truncation); identical observations
    # are grouped with an occurrence count and full endpoint list.
    groups = compact_findings(all_findings)
    findings_json = json.dumps(groups, indent=1)
    evidence.log(
        "CORRELATE_INPUT_PREPARED",
        agent="correlate",
        raw_finding_count=len(all_findings),
        grouped_finding_count=len(groups),
        findings_chars=len(findings_json),
    )

    user_content = (
        OUTPUT_SCHEMA_HINT
        + "\n\nRAW FINDINGS (JSON, grouped: identical observations merged with an "
        "'occurrences' count and the full list of endpoints):\n"
        + findings_json
        + "\n\nLIVE CVE DATA FOR DETECTED SERVICE VERSIONS:\n"
        + ("\n".join(cve_context_lines) if cve_context_lines else "(no service versions available to look up)")
        + "\n\nRETRIEVED REFERENCE MATERIAL:\n"
        + (rag_context if rag_context else "(RAG disabled or no relevant material found)")
    )

    client = OpenAI(api_key=config.openai_api_key)
    evidence.log("MODEL_CALL", agent="correlate", input_finding_count=len(all_findings))
    response = client.chat.completions.create(
        model=config.openai_model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        response_format={"type": "json_object"},
    )

    choice = response.choices[0]
    usage = response.usage
    raw_text = choice.message.content or "{}"

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        evidence.log("MODEL_RESPONSE_PARSE_ERROR", agent="correlate", raw_preview=raw_text[:500])
        parsed = {
            "executive_summary": "Model response could not be parsed as JSON. See raw evidence log.",
            "overall_risk_rating": "unknown",
            "findings": [f.to_dict() for f in all_findings],
            "deduplication_notes": "Deduplication not performed due to a model response parse error.",
        }

    evidence.log(
        "MODEL_RESPONSE",
        agent="correlate",
        finding_count=len(parsed.get("findings", [])),
        overall_risk_rating=parsed.get("overall_risk_rating"),
    )

    result = CorrelateAgentResult(
        executive_summary=parsed.get("executive_summary", ""),
        overall_risk_rating=parsed.get("overall_risk_rating", "unknown"),
        findings=parsed.get("findings", []),
        deduplication_notes=parsed.get("deduplication_notes", ""),
        cve_lookups_performed=cve_lookups,
        rag_retrievals=rag_retrievals,
        model_calls=1,
        input_tokens=usage.prompt_tokens if usage else 0,
        output_tokens=usage.completion_tokens if usage else 0,
        duration_s=time.time() - started,
        raw_input_finding_count=len(all_findings),
        grouped_finding_count=len(groups),
    )
    evidence.log(
        "AGENT_END",
        agent="correlate",
        final_finding_count=len(result.findings),
        duration_s=result.duration_s,
    )
    return result
