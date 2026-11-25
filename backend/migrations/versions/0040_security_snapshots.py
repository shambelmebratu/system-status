"""Hourly security snapshots for Security → Compare (hour to hour, day to day, week to week, month to month)"""
from alembic import op
import sqlalchemy as sa

revision = "0040_security_snapshots"
down_revision = "0039_pause_timeout_ms"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("security_snapshots",
                    sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
                    sa.Column("data", sa.Text(), nullable=False, server_default="{}"))
    op.create_index("ix_security_snapshots_ts", "security_snapshots", ["ts"])


def downgrade():
    op.drop_index("ix_security_snapshots_ts", table_name="security_snapshots")
    op.drop_table("security_snapshots")
