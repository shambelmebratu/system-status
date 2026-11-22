"""Pause a server or service (stop checks and alerts, or only mute alerts) until a time or until resumed; service timeouts in milliseconds"""
from alembic import op
import sqlalchemy as sa

revision = "0039_pause_timeout_ms"
down_revision = "0038_check_daily"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("servers", "services"):
        op.add_column(table, sa.Column("pause_mode", sa.String(10)))                    # "monitor" (no checks, no alerts) | "alerts" (checks, no alerts)
        op.add_column(table, sa.Column("paused_until", sa.DateTime(timezone=True)))     # NULL with a mode = until someone resumes it
        op.add_column(table, sa.Column("paused_by", sa.String(320)))
        op.add_column(table, sa.Column("pause_reason", sa.String(200)))
    op.add_column("services", sa.Column("timeout_ms", sa.Integer()))
    op.execute("UPDATE services SET timeout_ms = timeout_seconds * 1000 WHERE timeout_seconds IS NOT NULL")


def downgrade():
    op.drop_column("services", "timeout_ms")
    for table in ("servers", "services"):
        for column in ("pause_reason", "paused_by", "paused_until", "pause_mode"):
            op.drop_column(table, column)
