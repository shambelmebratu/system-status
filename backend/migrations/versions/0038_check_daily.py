"""Daily uptime per monitor, stored (filled in by the worker): long uptime ranges no longer count millions of check results"""
from alembic import op
import sqlalchemy as sa

revision = "0038_check_daily"
down_revision = "0037_confirm_checks"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("check_daily",
        sa.Column("day", sa.Date(), primary_key=True), sa.Column("target_type", sa.String(20), primary_key=True), sa.Column("target_id", sa.Integer(), primary_key=True),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"), sa.Column("ok", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    op.drop_table("check_daily")
