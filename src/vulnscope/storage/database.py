"""SQLite database schema and session helpers."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

from vulnscope.utils.files import ensure_dir


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


class ScanRow(Base):
    """Stored scan row."""

    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(String(2048), index=True)
    profile: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    authenticated: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    findings: Mapped[list[FindingRow]] = relationship(cascade="all, delete-orphan")
    traffic: Mapped[list[TrafficRow]] = relationship(cascade="all, delete-orphan")
    components: Mapped[list[ComponentRow]] = relationship(cascade="all, delete-orphan")


class FindingRow(Base):
    """Stored finding row."""

    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(128), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[float] = mapped_column(Float)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str] = mapped_column(String(2048))
    data: Mapped[dict[str, Any]] = mapped_column(JSON)


class TrafficRow(Base):
    """Stored HTTP traffic metadata."""

    __tablename__ = "traffic"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(String(2048))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)


class ComponentRow(Base):
    """Stored detected component."""

    __tablename__ = "components"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(128))
    confidence: Mapped[int] = mapped_column(Integer)


class SettingRow(Base):
    """Stored application setting."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class CustomRuleRow(Base):
    """Stored custom rule source."""

    __tablename__ = "custom_rules"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    yaml_source: Mapped[str] = mapped_column(Text)


def make_engine(database_path: str) -> Engine:
    """Create a SQLite engine and ensure parent directory exists."""

    path = Path(database_path)
    ensure_dir(path.parent)
    return create_engine(f"sqlite:///{path}", future=True)


def init_database(database_path: str) -> Engine:
    """Create all database tables."""

    engine = make_engine(database_path)
    Base.metadata.create_all(engine)
    return engine


def session_factory(database_path: str) -> sessionmaker[Session]:
    """Return a configured SQLAlchemy session factory."""

    engine = init_database(database_path)
    return sessionmaker(engine, expire_on_commit=False, future=True)
