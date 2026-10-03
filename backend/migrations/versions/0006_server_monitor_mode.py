"""add explicit server ping-only and agent monitor modes"""
from alembic import op
import sqlalchemy as sa

revision = "0006_server_monitor_mode"
down_revision = "0005_alert_delivery_retry"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("monitor_mode", sa.String(20), nullable=False, server_default="agent"))
    op.alter_column("servers", "endpoint", existing_type=sa.String(length=500), nullable=False, server_default="")


def downgrade():
    op.alter_column("servers", "endpoint", existing_type=sa.String(length=500), server_default=None)
    op.drop_column("servers", "monitor_mode")