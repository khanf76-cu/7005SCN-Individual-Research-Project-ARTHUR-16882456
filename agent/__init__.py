"""From-scratch LLM pentest agent for 7005SCN Individual Research Project.

Original coursework artefact. Orchestrates an LLM (via the OpenAI API) over
a small, fixed toolset (nikto + scoped HTTP requests), with an optional
RAG (retrieval-augmented generation) layer that injects relevant
cybersecurity knowledge-base passages into the agent's context before each
decision. Every tool call, model call, and retrieval event is logged to
disk so a run can be independently scored against a ground-truth register
and compared across RAG-on / RAG-off conditions.

Authorized-target use only. See README.md.
"""

__version__ = "0.1.0"
