"""Append-only JSONL evidence logging.

Every tool call, model call, and retrieval event is written here as it
happens (not buffered and written at the end), so a crashed or killed run
still leaves a usable partial record -- the same principle your proposal's
"preserve evidence" objective calls for.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class EvidenceLogger:
    run_id: str
    out_dir: Path

    def __post_init__(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.out_dir / "evidence.jsonl"
        self._manifest_path = self.out_dir / "run_manifest.json"

    def log(self, event_type: str, **fields: Any) -> dict:
        record = {
            "ts_utc": time.time(),
            "run_id": self.run_id,
            "event_type": event_type,
            **fields,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        return record

    def write_manifest(self, manifest: dict) -> None:
        self._manifest_path.write_text(json.dumps(manifest, indent=2, default=str))

    @property
    def evidence_path(self) -> Path:
        return self._path
