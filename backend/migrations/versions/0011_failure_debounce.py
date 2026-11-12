"""consecutive failure counters for alert debouncing"""
from alembic import op
import sqlalchemy as sa

revision = "0011_failure_debounce"
down_revision = "0010_history_incidents_push"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("servers", sa.Column("fail_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("services", sa.Column("fail_count", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    op.drop_column("services", "fail_count")
    op.drop_column("servers", "fail_count")
