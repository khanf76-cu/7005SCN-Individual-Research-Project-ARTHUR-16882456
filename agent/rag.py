"""Minimal retrieval-augmented generation layer.

Deliberately simple and dependency-light (TF-IDF cosine similarity, not
a hosted vector DB) so the whole retrieval path is auditable in ~80 lines
-- appropriate for a dissertation artefact where you need to explain and
defend every component, versus a black-box embeddings API.

Corpus format: a folder of .md/.txt files under corpus/, each one
document (e.g. an OWASP Top 10 entry, a CVE summary, a nikto OSVDB
reference). See corpus/README.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class RetrievedDoc:
    doc_id: str
    source_path: str
    score: float
    text: str


class RagCorpus:
    def __init__(self, corpus_dir: Path):
        self.corpus_dir = corpus_dir
        self._doc_ids: list[str] = []
        self._paths: list[Path] = []
        self._texts: list[str] = []
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._load()

    def _load(self) -> None:
        files = sorted(
            [p for p in self.corpus_dir.rglob("*") if p.suffix in (".md", ".txt")]
        )
        for p in files:
            text = p.read_text(encoding="utf-8", errors="ignore")
            if not text.strip():
                continue
            self._doc_ids.append(p.stem)
            self._paths.append(p)
            self._texts.append(text)

        if not self._texts:
            return

        self._vectorizer = TfidfVectorizer(stop_words="english", max_features=20000)
        self._matrix = self._vectorizer.fit_transform(self._texts)

    @property
    def document_count(self) -> int:
        return len(self._texts)

    def retrieve(self, query: str, k: int = 3, min_score: float = 0.05) -> list[RetrievedDoc]:
        if self._vectorizer is None or self._matrix is None:
            return []

        query_vec = self._vectorizer.transform([query])
        sims = cosine_similarity(query_vec, self._matrix)[0]
        ranked = sorted(range(len(sims)), key=lambda i: sims[i], reverse=True)

        results: list[RetrievedDoc] = []
        for idx in ranked[:k]:
            score = float(sims[idx])
            if score < min_score:
                continue
            results.append(
                RetrievedDoc(
                    doc_id=self._doc_ids[idx],
                    source_path=str(self._paths[idx]),
                    score=score,
                    text=self._texts[idx][:1500],  # cap context injected per doc
                )
            )
        return results
