# RAG corpus

Each `.md`/`.txt` file in this directory (recursively) is one retrievable
document. Keep documents short and focused (one vulnerability class, one
CVE family, one OWASP category) so retrieval returns something specific
rather than a diluted mega-document.

This starter set is small and intentionally generic (public OWASP-style
guidance, written from scratch, no copyrighted text copied in) so you can
run and test the pipeline immediately. For the real E2/E3-style
comparison, expand this with more specific, cited references (MITRE
ATT&CK technique summaries you write in your own words, CVE descriptions
you paraphrase, etc.) and record the corpus's SHA-256 + document count in
your report for reproducibility, the way the frozen protocol in your
proposal did.
