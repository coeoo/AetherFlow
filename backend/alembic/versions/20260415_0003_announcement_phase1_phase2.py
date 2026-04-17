from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260415_0003"
down_revision = "20260413_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "announcement_sources",
        sa.Column(
            "source_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column("schedule_cron", sa.String(length=64), nullable=False),
        sa.Column(
            "config_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "delivery_policy_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )

    op.create_table(
        "announcement_runs",
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entry_mode", sa.String(length=32), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("trigger_fetch_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("title_hint", sa.String(length=256), nullable=True),
        sa.Column(
            "input_snapshot_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "summary_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["task_jobs.job_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["announcement_sources.source_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["trigger_fetch_id"],
            ["source_fetch_records.fetch_id"],
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("job_id", name="uq_announcement_runs_job_id"),
    )

    op.create_table(
        "announcement_documents",
        sa.Column(
            "document_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("language", sa.String(length=16), nullable=True),
        sa.Column("source_item_key", sa.String(length=256), nullable=True),
        sa.Column("content_dedup_hash", sa.String(length=128), nullable=False),
        sa.Column("source_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "normalized_text_artifact_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("content_excerpt", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["announcement_runs.run_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["announcement_sources.source_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_artifact_id"],
            ["artifacts.artifact_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["normalized_text_artifact_id"],
            ["artifacts.artifact_id"],
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("run_id", name="uq_announcement_documents_run_id"),
        sa.UniqueConstraint(
            "source_id",
            "source_item_key",
            name="uq_announcement_documents_source_item_per_source",
        ),
    )

    op.create_table(
        "announcement_intelligence_packages",
        sa.Column(
            "package_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column(
            "affected_products_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "iocs_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "remediation_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "evidence_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("analyst_summary", sa.Text(), nullable=False),
        sa.Column(
            "notify_recommended",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["announcement_runs.run_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["announcement_documents.document_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "run_id",
            name="uq_announcement_intelligence_packages_run_id",
        ),
        sa.UniqueConstraint(
            "document_id",
            name="uq_announcement_intelligence_packages_document_id",
        ),
    )


def downgrade() -> None:
    op.drop_table("announcement_intelligence_packages")
    op.drop_table("announcement_documents")
    op.drop_table("announcement_runs")
    op.drop_table("announcement_sources")
