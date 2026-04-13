from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260410_0002"
down_revision = "20260410_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "task_attempt_artifacts",
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id"],
            ["task_attempts.attempt_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.artifact_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("attempt_id", "artifact_id"),
    )

    op.create_table(
        "runtime_heartbeats",
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("instance_name", sa.String(length=128), nullable=False),
        sa.Column(
            "heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
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
        sa.PrimaryKeyConstraint("role", "instance_name"),
    )


def downgrade() -> None:
    op.drop_table("runtime_heartbeats")
    op.drop_table("task_attempt_artifacts")
