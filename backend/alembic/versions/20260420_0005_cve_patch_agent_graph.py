from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260420_0005"
down_revision = "20260417_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_search_nodes",
        sa.Column(
            "node_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("page_role", sa.String(length=64), nullable=False),
        sa.Column("fetch_status", sa.String(length=32), nullable=False),
        sa.Column("content_excerpt", sa.Text(), nullable=True),
        sa.Column(
            "heuristic_features_json",
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
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["cve_runs.run_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "run_id",
            "node_id",
            name="uq_cve_search_nodes_run_node_id",
        ),
    )

    op.create_table(
        "cve_search_edges",
        sa.Column(
            "edge_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("from_node_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("to_node_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("edge_type", sa.String(length=64), nullable=False),
        sa.Column("anchor_text", sa.Text(), nullable=True),
        sa.Column("link_context", sa.Text(), nullable=True),
        sa.Column("selected_by", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["cve_runs.run_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "from_node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            ondelete="CASCADE",
            name="fk_cve_search_edges_from_node",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "to_node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            ondelete="CASCADE",
            name="fk_cve_search_edges_to_node",
        ),
    )

    op.create_table(
        "cve_search_decisions",
        sa.Column(
            "decision_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("node_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("decision_type", sa.String(length=64), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=True),
        sa.Column(
            "input_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "output_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "validated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["cve_runs.run_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["cve_search_nodes.node_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            name="fk_cve_search_decisions_run_node",
        ),
    )

    op.create_table(
        "cve_candidate_artifacts",
        sa.Column(
            "candidate_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_node_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("candidate_url", sa.Text(), nullable=False),
        sa.Column("candidate_type", sa.String(length=64), nullable=False),
        sa.Column("canonical_key", sa.String(length=512), nullable=False),
        sa.Column("download_status", sa.String(length=32), nullable=False),
        sa.Column("validation_status", sa.String(length=32), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "evidence_json",
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
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["cve_runs.run_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_node_id"],
            ["cve_search_nodes.node_id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "source_node_id"],
            ["cve_search_nodes.run_id", "cve_search_nodes.node_id"],
            name="fk_cve_candidate_artifacts_run_source_node",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.artifact_id"],
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "run_id",
            "canonical_key",
            name="uq_cve_candidate_artifacts_run_canonical_key",
        ),
    )


def downgrade() -> None:
    op.drop_table("cve_candidate_artifacts")
    op.drop_table("cve_search_decisions")
    op.drop_table("cve_search_edges")
    op.drop_table("cve_search_nodes")
