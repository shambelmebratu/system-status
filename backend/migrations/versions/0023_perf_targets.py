"""response-time targets (percentile + threshold + window) on servers and services"""
from alembic import op
import sqlalchemy as sa

revision = "0023_perf_targets"
down_revision = "0022_monitor_alert_settings"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("servers", "services"):
        op.add_column(table, sa.Column("perf_percentile", sa.String(length=4), nullable=True))
        op.add_column(table, sa.Column("perf_threshold_ms", sa.Integer(), nullable=True))
        op.add_column(table, sa.Column("perf_window_minutes", sa.Integer(), nullable=True))


def downgrade():
    for table in ("servers", "services"):
        op.drop_column(table, "perf_window_minutes")
        op.drop_column(table, "perf_threshold_ms")
        op.drop_column(table, "perf_percentile")
