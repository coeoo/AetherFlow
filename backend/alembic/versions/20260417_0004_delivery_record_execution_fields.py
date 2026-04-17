from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20260417_0004"
down_revision = "20260415_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "delivery_records",
        sa.Column(
            "delivery_kind",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'production'"),
        ),
    )
    op.add_column(
        "delivery_records",
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "delivery_records",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )

    op.alter_column("delivery_records", "delivery_kind", server_default=None)
    op.alter_column("delivery_records", "updated_at", server_default=None)


def downgrade() -> None:
    op.drop_column("delivery_records", "updated_at")
    op.drop_column("delivery_records", "scheduled_at")
    op.drop_column("delivery_records", "delivery_kind")
