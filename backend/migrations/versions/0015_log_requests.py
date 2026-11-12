"""on-demand log requests executed by agents"""
from alembic import op
import sqlalchemy as sa

revision = "0015_log_requests"
down_revision = "0014_scheduled_messages"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "log_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_log_requests_server_status", "log_requests", ["server_id", "status"])


def downgrade():
    op.drop_table("log_requests")
