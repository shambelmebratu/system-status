"""configure ping and host check interval per server"""
from alembic import op
import sqlalchemy as sa

revision = "0007_server_check_interval"
down_revision = "0006_server_monitor_mode"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("check_interval_seconds", sa.Integer(), nullable=False, server_default="60"))


def downgrade():
    op.drop_column("servers", "check_interval_seconds")