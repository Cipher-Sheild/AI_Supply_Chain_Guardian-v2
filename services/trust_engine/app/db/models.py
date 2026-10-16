"""
SQLAlchemy models for the unified schema.
Only trust_engine imports this module and connects to Postgres directly.
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Float, Text, ForeignKey, DateTime, Integer, Boolean, JSON
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import declarative_base, relationship

JSONB = JSONB().with_variant(JSON(), "sqlite")
Base = declarative_base()


def gen_uuid():
    return str(uuid.uuid4())


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    artifact_type = Column(String, nullable=False)
    ai_tool_source = Column(String, nullable=True)
    content_hash = Column(Text, nullable=True)
    submitted_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="artifact")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    artifact_id = Column(UUID(as_uuid=False), ForeignKey("artifacts.id"), nullable=False)
    status = Column(String, default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    artifact = relationship("Artifact", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    trust_score = relationship("TrustScore", back_populates="scan", uselist=False)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String, unique=True, nullable=False)
    tool_backend = Column(String, nullable=True)
    version = Column(String, nullable=True)

    findings = relationship("Finding", back_populates="agent")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False)
    agent_id = Column(UUID(as_uuid=False), ForeignKey("agents.id"), nullable=False)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    location = Column(Text, nullable=True)
    raw_payload = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    agent = relationship("Agent", back_populates="findings")
    dependency_detail = relationship("DependencyDetail", back_populates="finding", uselist=False)
    secret_detail = relationship("SecretDetail", back_populates="finding", uselist=False)
    docker_detail = relationship("DockerDetail", back_populates="finding", uselist=False)


class DependencyDetail(Base):
    __tablename__ = "dependency_detail"

    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), primary_key=True)
    package_name = Column(String, nullable=False)
    ecosystem = Column(String, nullable=False)
    exists_in_registry = Column(Boolean, nullable=False)
    hallucination_score = Column(Float, nullable=True)

    finding = relationship("Finding", back_populates="dependency_detail")


class SecretDetail(Base):
    __tablename__ = "secret_detail"

    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), primary_key=True)
    secret_type = Column(String, nullable=False)
    entropy_score = Column(Float, nullable=True)

    finding = relationship("Finding", back_populates="secret_detail")


class DockerDetail(Base):
    __tablename__ = "docker_detail"

    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), primary_key=True)
    cve_id = Column(String, nullable=True)
    base_image = Column(String, nullable=True)

    finding = relationship("Finding", back_populates="docker_detail")


class TrustScore(Base):
    __tablename__ = "trust_scores"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False, unique=True)
    overall_score = Column(Float, nullable=False)
    agent_breakdown = Column(JSONB, nullable=True)
    computed_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="trust_score")

class ScanSnapshot(Base):
    __tablename__ = "scan_snapshots"
    request_id = Column(String, primary_key=True)
    tenant_id = Column(String(64),nullable=False,default='owner',server_default='owner',index=True)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False, unique=True)
    payload = Column(JSONB, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class AgentExecution(Base):
    __tablename__ = "agent_executions"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False)
    agent_id = Column(UUID(as_uuid=False), ForeignKey("agents.id"), nullable=False)
    file = Column(Text)
    status = Column(String, nullable=False)
    payload = Column(JSONB, nullable=False)
