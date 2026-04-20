from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CVERun(Base):
    __tablename__ = "cve_runs"
    __table_args__ = (
        UniqueConstraint("job_id", name="uq_cve_runs_job_id"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("task_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32))
    phase: Mapped[str] = mapped_column(String(32))
    stop_reason: Mapped[str | None] = mapped_column(String(64))
    summary_json: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )


class CVEPatchArtifact(Base):
    __tablename__ = "cve_patch_artifacts"

    patch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_runs.run_id", ondelete="CASCADE"),
        nullable=False,
    )
    candidate_url: Mapped[str] = mapped_column(Text)
    patch_type: Mapped[str] = mapped_column(String(32))
    download_status: Mapped[str] = mapped_column(String(32))
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.artifact_id", ondelete="SET NULL"),
    )
    patch_meta_json: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )


class CVESearchNode(Base):
    __tablename__ = "cve_search_nodes"
    __table_args__ = (
        UniqueConstraint("run_id", "node_id", name="uq_cve_search_nodes_run_node_id"),
    )

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_runs.run_id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(Text)
    depth: Mapped[int] = mapped_column(Integer)
    host: Mapped[str] = mapped_column(String(255))
    page_role: Mapped[str] = mapped_column(String(64))
    fetch_status: Mapped[str] = mapped_column(String(32))
    content_excerpt: Mapped[str | None] = mapped_column(Text)
    heuristic_features_json: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )


class CVESearchEdge(Base):
    __tablename__ = "cve_search_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "from_node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            ondelete="CASCADE",
            name="fk_cve_search_edges_from_node",
        ),
        ForeignKeyConstraint(
            ["run_id", "to_node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            ondelete="CASCADE",
            name="fk_cve_search_edges_to_node",
        ),
    )

    edge_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_runs.run_id", ondelete="CASCADE"),
        nullable=False,
    )
    from_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    to_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(64))
    anchor_text: Mapped[str | None] = mapped_column(Text)
    link_context: Mapped[str | None] = mapped_column(Text)
    selected_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )


class CVESearchDecision(Base):
    __tablename__ = "cve_search_decisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            name="fk_cve_search_decisions_run_node",
        ),
    )

    decision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_runs.run_id", ondelete="CASCADE"),
        nullable=False,
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_search_nodes.node_id", ondelete="SET NULL"),
    )
    decision_type: Mapped[str] = mapped_column(String(64))
    model_name: Mapped[str | None] = mapped_column(String(128))
    input_json: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    output_json: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    validated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("FALSE"),
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )


class CVECandidateArtifact(Base):
    __tablename__ = "cve_candidate_artifacts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "source_node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            name="fk_cve_candidate_artifacts_run_source_node",
        ),
        UniqueConstraint(
            "run_id",
            "canonical_key",
            name="uq_cve_candidate_artifacts_run_canonical_key",
        ),
    )

    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_runs.run_id", ondelete="CASCADE"),
        nullable=False,
    )
    source_node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cve_search_nodes.node_id", ondelete="SET NULL"),
    )
    candidate_url: Mapped[str] = mapped_column(Text)
    candidate_type: Mapped[str] = mapped_column(String(64))
    canonical_key: Mapped[str] = mapped_column(String(512))
    download_status: Mapped[str] = mapped_column(String(32))
    validation_status: Mapped[str] = mapped_column(String(32))
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.artifact_id", ondelete="SET NULL"),
    )
    evidence_json: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
    )
