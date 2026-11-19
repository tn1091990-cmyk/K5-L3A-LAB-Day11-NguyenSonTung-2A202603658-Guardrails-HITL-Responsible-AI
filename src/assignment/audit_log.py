"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store a request and its start time; use a generated ID if omitted."""
        request_id = request_id or f"{user_id}:{len(self.logs)}:{datetime.now(timezone.utc).timestamp()}"
        self._open[request_id] = datetime.now(timezone.utc).timestamp()
        self.logs.append({
            "request_id": request_id, "user_id": user_id, "input": text,
            "started_at": utc_now_iso(),
        })
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the matching request record with outcome and latency."""
        request_id = request_id or next(
            (entry["request_id"] for entry in reversed(self.logs)
             if entry["user_id"] == user_id and "output" not in entry), None
        )
        entry = next((e for e in reversed(self.logs) if e.get("request_id") == request_id), None)
        if entry is None:
            request_id = self.record_input(user_id=user_id, text="", request_id=request_id)
            entry = self.logs[-1]
        entry.update({
            "output": text, "blocked": bool(blocked), "layer": layer,
            "latency_ms": round(max(0, datetime.now(timezone.utc).timestamp() - self._open.pop(request_id, datetime.now(timezone.utc).timestamp())) * 1000, 2),
            "completed_at": utc_now_iso(),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
