"""Repository layer for scans and reports."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnscope.domain.models import Component, Finding, RequestRecord, Scan
from vulnscope.storage.database import ComponentRow, FindingRow, ScanRow, TrafficRow
from vulnscope.utils.text import redact_secrets


class ScanRepository:
    """Persist and retrieve scan aggregates."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, scan: Scan) -> None:
        """Insert or replace a scan."""

        existing = self.session.get(ScanRow, scan.id)
        if existing:
            self.session.delete(existing)
            self.session.flush()
        row = ScanRow(
            id=scan.id,
            target=scan.target,
            profile=scan.profile,
            status=scan.status,
            authenticated=1 if scan.authenticated else 0,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            metadata_json=scan.metadata,
        )
        self.session.add(row)
        self.session.flush()
        for finding in scan.findings:
            data = finding.model_dump(mode="json")
            data["request"] = redact_secrets(data.get("request", ""))
            data["response"] = redact_secrets(data.get("response", ""))
            self.session.add(
                FindingRow(
                    id=finding.id,
                    scan_id=scan.id,
                    title=finding.title,
                    severity=finding.severity.value,
                    category=finding.category,
                    confidence=finding.confidence,
                    risk_score=finding.risk_score,
                    payload=finding.payload,
                    url=finding.url,
                    data=data,
                )
            )
        for item in scan.traffic:
            data = item.model_dump(mode="json")
            data["request_preview"] = redact_secrets(data.get("request_preview", ""))
            data["response_preview"] = redact_secrets(data.get("response_preview", ""))
            self.session.add(
                TrafficRow(
                    id=item.id,
                    scan_id=scan.id,
                    method=item.method,
                    url=item.url,
                    status_code=item.status_code,
                    duration_ms=item.duration_ms,
                    size_bytes=item.size_bytes,
                    data=data,
                )
            )
        for component in scan.components:
            self.session.add(
                ComponentRow(
                    scan_id=scan.id,
                    name=component.name,
                    version=component.version,
                    source=component.source,
                    confidence=component.confidence,
                )
            )
        self.session.commit()

    def list_scans(self, limit: int = 20) -> list[Scan]:
        """Return recent scans."""

        statement = select(ScanRow).order_by(ScanRow.started_at.desc()).limit(limit)
        rows = self.session.scalars(statement).all()
        return [self._to_scan(row) for row in rows]

    def get(self, scan_id: str) -> Scan | None:
        """Return one scan by ID."""

        row = self.session.get(ScanRow, scan_id)
        return self._to_scan(row) if row else None

    def _to_scan(self, row: ScanRow) -> Scan:
        return Scan(
            id=row.id,
            target=row.target,
            profile=row.profile,
            authenticated=bool(row.authenticated),
            started_at=row.started_at,
            finished_at=row.finished_at,
            status=row.status,
            findings=[Finding.model_validate(item.data) for item in row.findings],
            traffic=[RequestRecord.model_validate(item.data) for item in row.traffic],
            components=[
                Component(
                    name=item.name,
                    version=item.version,
                    source=item.source,
                    confidence=item.confidence,
                )
                for item in row.components
            ],
            metadata=row.metadata_json or {},
        )
