"""Local-first research workspaces for authorized Sentinel assessments."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinel.knowledge_graph import KnowledgeGraph, build_knowledge_graph
from sentinel.models import ScanReport


@dataclass(frozen=True, slots=True)
class StoredScan:
    """A scan record stored in a local research workspace."""

    scan_id: int
    target: str
    started_at: str
    finished_at: str
    stored_at: str
    version: str
    findings_count: int
    errors_count: int

    def as_dict(self) -> dict[str, str | int]:
        """Return a JSON-friendly scan summary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stored_at": self.stored_at,
            "version": self.version,
            "findings_count": self.findings_count,
            "errors_count": self.errors_count,
        }


@dataclass(frozen=True, slots=True)
class WorkspaceNote:
    """A local user-authored research note associated with a target or scan."""

    note_id: int
    target: str
    content: str
    tags: tuple[str, ...]
    scan_id: int | None
    favorite: bool
    created_at: str

    def as_dict(self) -> dict[str, str | int | bool | list[str] | None]:
        """Return a JSON-friendly note representation."""
        return {
            "note_id": self.note_id,
            "target": self.target,
            "content": self.content,
            "tags": list(self.tags),
            "scan_id": self.scan_id,
            "favorite": self.favorite,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class ScanComparison:
    """A deterministic, non-interpretive comparison of two stored scans."""

    previous_scan_id: int
    current_scan_id: int
    target: str
    new_findings: tuple[dict[str, str], ...]
    resolved_findings: tuple[dict[str, str], ...]
    changed_modules: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """Return a presentation-neutral comparison payload."""
        return {
            "previous_scan_id": self.previous_scan_id,
            "current_scan_id": self.current_scan_id,
            "target": self.target,
            "new_findings": list(self.new_findings),
            "resolved_findings": list(self.resolved_findings),
            "changed_modules": list(self.changed_modules),
            "summary": {
                "new_findings": len(self.new_findings),
                "resolved_findings": len(self.resolved_findings),
                "changed_modules": len(self.changed_modules),
            },
            "notice": (
                "Changes are observations from non-destructive scans. Validate scope and "
                "impact manually before treating any change as a security issue."
            ),
        }


class WorkspaceStore:
    """Persist scan history and notes in one local SQLite database."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def save_scan(self, report: ScanReport, config: dict[str, Any]) -> int:
        """Store one immutable scan snapshot and return its local identifier."""
        stored_at = datetime.now(UTC).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    target, started_at, finished_at, stored_at, version, findings_count,
                    errors_count, report_json, config_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.target,
                    report.started_at,
                    report.finished_at,
                    stored_at,
                    report.version,
                    report.statistics.get("findings", 0),
                    report.statistics.get("errors", 0),
                    json.dumps(report.as_dict(), sort_keys=True, default=str),
                    json.dumps(config, sort_keys=True, default=str),
                ),
            )
            scan_id = cursor.lastrowid
            if scan_id is None:  # pragma: no cover - sqlite always returns this for INSERT.
                raise RuntimeError("SQLite did not return an identifier for the stored scan.")
            return scan_id

    def list_scans(self, target: str | None = None, limit: int = 20) -> list[StoredScan]:
        """Return newest stored scans, optionally limited to one exact target."""
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        query = (
            "SELECT id, target, started_at, finished_at, stored_at, version, findings_count, "
            "errors_count FROM scans"
        )
        parameters: tuple[object, ...]
        if target:
            query += " WHERE target = ?"
            parameters = (target, limit)
        else:
            parameters = (limit,)
        query += " ORDER BY id DESC LIMIT ?"
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._stored_scan(row) for row in rows]

    def get_scan_data(self, scan_id: int) -> dict[str, Any]:
        """Load an exact immutable scan snapshot from the workspace."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT report_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if row is None:
            raise ValueError(f"No scan with id {scan_id} exists in {self.path}.")
        loaded = json.loads(str(row["report_json"]))
        if not isinstance(loaded, dict):  # pragma: no cover - defensive database guard.
            raise ValueError(f"Stored scan {scan_id} has an invalid report payload.")
        return loaded

    def compare_scans(self, previous_scan_id: int, current_scan_id: int) -> ScanComparison:
        """Compare saved observations and module outputs without assigning impact."""
        previous = self.get_scan_data(previous_scan_id)
        current = self.get_scan_data(current_scan_id)
        previous_target = str(previous.get("target", ""))
        current_target = str(current.get("target", ""))
        if not previous_target or previous_target != current_target:
            raise ValueError("Scans must have the same exact target before they can be compared.")
        previous_findings = _finding_map(previous)
        current_findings = _finding_map(current)
        new_keys = sorted(set(current_findings) - set(previous_findings))
        resolved_keys = sorted(set(previous_findings) - set(current_findings))
        return ScanComparison(
            previous_scan_id=previous_scan_id,
            current_scan_id=current_scan_id,
            target=current_target,
            new_findings=tuple(current_findings[key] for key in new_keys),
            resolved_findings=tuple(previous_findings[key] for key in resolved_keys),
            changed_modules=tuple(_changed_modules(previous, current)),
        )

    def graph_for_scan(self, scan_id: int) -> KnowledgeGraph:
        """Build a graph from local scan data without sending any network request."""
        return build_knowledge_graph(self.get_scan_data(scan_id), scan_id=scan_id)

    def add_note(
        self,
        target: str,
        content: str,
        tags: list[str] | None = None,
        scan_id: int | None = None,
        favorite: bool = False,
    ) -> int:
        """Add a local workspace note; it is never transmitted by Sentinel."""
        clean_target = target.strip()
        clean_content = content.strip()
        if not clean_target:
            raise ValueError("A note requires a target.")
        if not clean_content:
            raise ValueError("A note cannot be empty.")
        clean_tags = tuple(sorted({tag.strip() for tag in tags or [] if tag.strip()}))
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO notes (target, content, tags_json, scan_id, favorite, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    clean_target,
                    clean_content,
                    json.dumps(clean_tags),
                    scan_id,
                    int(favorite),
                    datetime.now(UTC).isoformat(),
                ),
            )
            note_id = cursor.lastrowid
            if note_id is None:  # pragma: no cover - sqlite always returns this for INSERT.
                raise RuntimeError("SQLite did not return an identifier for the stored note.")
            return note_id

    def search_notes(self, query: str, limit: int = 50) -> list[WorkspaceNote]:
        """Search local note text, targets, and tags without external services."""
        if not query.strip():
            return []
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        pattern = f"%{query.strip()}%"
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, target, content, tags_json, scan_id, favorite, created_at
                FROM notes
                WHERE target LIKE ? OR content LIKE ? OR tags_json LIKE ?
                ORDER BY favorite DESC, id DESC
                LIMIT ?
                """,
                (pattern, pattern, pattern, limit),
            ).fetchall()
        return [self._workspace_note(row) for row in rows]

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    version TEXT NOT NULL,
                    findings_count INTEGER NOT NULL,
                    errors_count INTEGER NOT NULL,
                    report_json TEXT NOT NULL,
                    config_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS scans_target_stored_at
                    ON scans(target, stored_at DESC);
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY,
                    target TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    scan_id INTEGER,
                    favorite INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                );
                CREATE INDEX IF NOT EXISTS notes_target_created_at
                    ON notes(target, created_at DESC);
                """
            )

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _stored_scan(row: sqlite3.Row) -> StoredScan:
        return StoredScan(
            scan_id=int(row["id"]),
            target=str(row["target"]),
            started_at=str(row["started_at"]),
            finished_at=str(row["finished_at"]),
            stored_at=str(row["stored_at"]),
            version=str(row["version"]),
            findings_count=int(row["findings_count"]),
            errors_count=int(row["errors_count"]),
        )

    @staticmethod
    def _workspace_note(row: sqlite3.Row) -> WorkspaceNote:
        tags = json.loads(str(row["tags_json"]))
        tag_values = tuple(str(tag) for tag in tags) if isinstance(tags, list) else ()
        scan_value = row["scan_id"]
        return WorkspaceNote(
            note_id=int(row["id"]),
            target=str(row["target"]),
            content=str(row["content"]),
            tags=tag_values,
            scan_id=int(scan_value) if scan_value is not None else None,
            favorite=bool(row["favorite"]),
            created_at=str(row["created_at"]),
        )


def _finding_map(report: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Fingerprint observations for comparison without making vulnerability claims."""
    findings: dict[str, dict[str, str]] = {}
    modules = report.get("modules", [])
    if not isinstance(modules, list):
        return findings
    for module in modules:
        if not isinstance(module, dict):
            continue
        for finding in module.get("findings", []):
            if not isinstance(finding, dict):
                continue
            data = {
                "module": str(finding.get("module", module.get("module", "unknown"))),
                "title": str(finding.get("title", "Untitled observation")),
                "severity": str(finding.get("severity", "info")),
                "evidence": str(finding.get("evidence", "")),
                "url": str(finding.get("url", "")),
            }
            fingerprint = hashlib.sha256(
                json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            findings[fingerprint] = data
    return findings


def _changed_modules(previous: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Report module-level data changes while retaining raw details in stored scans."""

    def module_map(report: dict[str, Any]) -> dict[str, object]:
        modules = report.get("modules", [])
        if not isinstance(modules, list):
            return {}
        return {
            str(module.get("module", "unknown")): module.get("data", {})
            for module in modules
            if isinstance(module, dict)
        }

    before = module_map(previous)
    after = module_map(current)
    return [
        name
        for name in sorted(set(before) | set(after))
        if json.dumps(before.get(name), sort_keys=True, default=str)
        != json.dumps(after.get(name), sort_keys=True, default=str)
    ]
