"""SQLite baseline storage for local, authorized asset change tracking."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinel.asset_probe import AssetObservation


@dataclass(frozen=True, slots=True)
class AssetDelta:
    """A new or changed asset observation compared with the prior local baseline."""

    target: str
    changes: tuple[str, ...]
    previous_status_code: int | None
    status_code: int
    previous_content_length: int | None
    content_length: int | None
    technologies: tuple[str, ...]


class AssetStateStore:
    """Store only small header-derived baselines in a local SQLite database."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def record(self, scope_name: str, observations: list[AssetObservation]) -> list[AssetDelta]:
        """Compare observations, atomically update the baseline, and return deltas only."""
        now = datetime.now(UTC).isoformat()
        deltas: list[AssetDelta] = []
        with self._connection() as connection:
            for observation in observations:
                prior = connection.execute(
                    """
                    SELECT status_code, content_length
                    FROM asset_baselines
                    WHERE scope_name = ? AND target = ?
                    """,
                    (scope_name, observation.target),
                ).fetchone()
                prior_status = int(prior[0]) if prior is not None else None
                prior_length = int(prior[1]) if prior is not None and prior[1] is not None else None
                changes = _changes(prior_status, prior_length, observation)
                if changes:
                    deltas.append(
                        AssetDelta(
                            target=observation.target,
                            changes=changes,
                            previous_status_code=prior_status,
                            status_code=observation.status_code,
                            previous_content_length=prior_length,
                            content_length=observation.content_length,
                            technologies=observation.technologies,
                        )
                    )
                connection.execute(
                    """
                    INSERT INTO asset_baselines (
                        scope_name, target, status_code, content_length, technologies_json,
                        first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scope_name, target) DO UPDATE SET
                        status_code = excluded.status_code,
                        content_length = excluded.content_length,
                        technologies_json = excluded.technologies_json,
                        last_seen_at = excluded.last_seen_at
                    """,
                    (
                        scope_name,
                        observation.target,
                        observation.status_code,
                        observation.content_length,
                        json.dumps(observation.technologies),
                        now,
                        now,
                    ),
                )
        return deltas

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS asset_baselines (
                    scope_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    content_length INTEGER,
                    technologies_json TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    PRIMARY KEY(scope_name, target)
                )
                """
            )

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection


def _changes(
    prior_status: int | None, prior_length: int | None, observation: AssetObservation
) -> tuple[str, ...]:
    if prior_status is None:
        return ("new",)
    changes: list[str] = []
    if prior_status != observation.status_code:
        changes.append("status changed")
    if (
        prior_length is not None
        and observation.content_length is not None
        and prior_length != observation.content_length
    ):
        changes.append("content length changed")
    return tuple(changes)
