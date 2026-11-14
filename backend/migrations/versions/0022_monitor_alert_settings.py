"""per-monitor alert settings: alert types, channels and reminder interval"""
from alembic import op
import sqlalchemy as sa

revision = "0022_monitor_alert_settings"
down_revision = "0021_traffic_samples"
branch_labels = None
depends_on = None
TABLES = ("servers", "services", "clusters")


def upgrade():
    for table in TABLES:
        op.add_column(table, sa.Column("alert_events", sa.String(length=100), nullable=True))
        op.add_column(table, sa.Column("alert_channels", sa.String(length=200), nullable=True))
        op.add_column(table, sa.Column("alert_reminder_minutes", sa.Integer(), nullable=True))


def downgrade():
    for table in TABLES:
        op.drop_column(table, "alert_reminder_minutes")
        op.drop_column(table, "alert_channels")
        op.drop_column(table, "alert_events")
