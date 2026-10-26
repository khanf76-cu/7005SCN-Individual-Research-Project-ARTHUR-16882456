from pathlib import Path

from agent.rag import RagCorpus

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"


def test_corpus_loads_documents():
    corpus = RagCorpus(CORPUS_DIR)
    assert corpus.document_count >= 4


def test_retrieve_returns_relevant_doc_for_sql_injection_query():
    corpus = RagCorpus(CORPUS_DIR)
    results = corpus.retrieve("SQL injection login form error message", k=2)
    assert results
    assert any("sql" in r.doc_id.lower() for r in results)


def test_retrieve_returns_nothing_for_empty_corpus(tmp_path: Path):
    corpus = RagCorpus(tmp_path)
    assert corpus.document_count == 0
    assert corpus.retrieve("anything") == []


def test_retrieve_respects_min_score_floor():
    corpus = RagCorpus(CORPUS_DIR)
    # An extremely unrelated query should return nothing above the floor.
    results = corpus.retrieve("recipe for banana bread baking", k=3, min_score=0.9)
    assert results == []
