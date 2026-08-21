from __future__ import annotations

import enum
import uuid
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    student = "student"
    researcher = "researcher"
    administrator = "administrator"


class Severity(str, enum.Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class User(Base, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120))
    organization: Mapped[str] = mapped_column(String(180), default="Independent learner")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.student, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    projects: Mapped[list[Project]] = relationship(back_populates="owner")


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[str] = mapped_column(Text, default="127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
    status: Mapped[str] = mapped_column(String(30), default="active")
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner: Mapped[User] = relationship(back_populates="projects")
    assets: Mapped[list[Asset]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="project", cascade="all, delete-orphan")


class ProjectMember(Base, TimestampMixin):
    __tablename__ = "project_members"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    permission: Mapped[str] = mapped_column(String(30), default="viewer")


class AuthorizationRecord(Base, TimestampMixin):
    __tablename__ = "authorization_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    target: Mapped[str] = mapped_column(String(255))
    purpose: Mapped[str] = mapped_column(Text)
    approved_scope: Mapped[str] = mapped_column(Text)
    policy_accepted: Mapped[bool] = mapped_column(Boolean)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (Index("ix_asset_project_address", "project_id", "ip_address", unique=True),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    ip_address: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="active")
    probable_os: Mapped[str] = mapped_column(String(100), default="Unknown")
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    project: Mapped[Project] = relationship(back_populates="assets")
    services: Mapped[list[Service]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("authorization_records.id"))
    name: Mapped[str] = mapped_column(String(140))
    target: Mapped[str] = mapped_column(String(255))
    profile: Mapped[str] = mapped_column(String(50))
    ports: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    services_found: Mapped[int] = mapped_column(Integer, default=0)
    findings_found: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    project: Mapped[Project] = relationship(back_populates="scans")


class ScanTarget(Base, TimestampMixin):
    __tablename__ = "scan_targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    normalized_target: Mapped[str] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(24), default="pending")


class Service(Base, TimestampMixin):
    __tablename__ = "services"
    __table_args__ = (Index("ix_service_asset_port", "asset_id", "port", "protocol", unique=True),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(12), default="tcp")
    name: Mapped[str] = mapped_column(String(80), default="unknown")
    product: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tls: Mapped[bool] = mapped_column(Boolean, default=False)
    asset: Mapped[Asset] = relationship(back_populates="services")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True, index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(220))
    description: Mapped[str] = mapped_column(Text)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str | None] = mapped_column(String(80), nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    assigned_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    analyst_notes: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0)


class VulnerabilityReference(Base, TimestampMixin):
    __tablename__ = "vulnerability_references"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    identifier: Mapped[str] = mapped_column(String(80))
    product: Mapped[str] = mapped_column(String(120))
    version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    severity_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    match_confidence: Mapped[int] = mapped_column(Integer, default=50)
    source_url: Mapped[str | None] = mapped_column(String(500), nullable=True)


class TrafficRecord(Base, TimestampMixin):
    __tablename__ = "traffic_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    destination: Mapped[str] = mapped_column(String(64), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), index=True)
    packets: Mapped[int] = mapped_column(Integer, default=1)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    retain_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(140))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    rule_type: Mapped[str] = mapped_column(String(50))
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    built_in: Mapped[bool] = mapped_column(Boolean, default=False)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    rule_id: Mapped[str | None] = mapped_column(ForeignKey("detection_rules.id"), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(140))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[str] = mapped_column(Text)
    investigation: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="new")
    assigned_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class AssessmentTemplate(Base, TimestampMixin):
    __tablename__ = "assessment_templates"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text)
    framework: Mapped[str] = mapped_column(String(100))
    controls: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Assessment(Base, TimestampMixin):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    template_id: Mapped[str] = mapped_column(ForeignKey("assessment_templates.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(180))
    status: Mapped[str] = mapped_column(String(30), default="in_progress")
    score: Mapped[float] = mapped_column(Float, default=0)
    maturity_score: Mapped[float] = mapped_column(Float, default=0)
    residual_risk: Mapped[float] = mapped_column(Float, default=100)


class AssessmentResponse(Base, TimestampMixin):
    __tablename__ = "assessment_responses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    control_id: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(100), index=True)
    response: Mapped[str] = mapped_column(String(30), default="not_reviewed")
    notes: Mapped[str] = mapped_column(Text, default="")
    evidence_reference: Mapped[str] = mapped_column(String(500), default="")
    owner: Mapped[str] = mapped_column(String(120), default="")
    target_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    remediation_plan: Mapped[str] = mapped_column(Text, default="")


class RemediationTask(Base, TimestampMixin):
    __tablename__ = "remediation_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(220))
    priority: Mapped[str] = mapped_column(String(30), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="open")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)


class Report(Base, TimestampMixin):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    report_type: Mapped[str] = mapped_column(String(30))
    format: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(180))
    content: Mapped[dict[str, Any]] = mapped_column(JSON)
    human_validation_required: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)

