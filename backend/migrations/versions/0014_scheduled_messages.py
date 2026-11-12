"""scheduled messages to notification channels"""
from alembic import op
import sqlalchemy as sa

revision = "0014_scheduled_messages"
down_revision = "0013_agent_enrollment"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scheduled_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("channel_ids", sa.Text(), nullable=False),
        sa.Column("repeat", sa.String(length=10), nullable=False),
        sa.Column("time_of_day", sa.String(length=5), nullable=False),
        sa.Column("days_of_week", sa.String(length=20), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pending_channel_ids", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=20), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scheduled_messages_next_run_at", "scheduled_messages", ["next_run_at"])


def downgrade():
    op.drop_table("scheduled_messages")
