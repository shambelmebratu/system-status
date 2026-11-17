"""DevOps: heartbeat (cron job) monitors, maintenance windows, SLOs and error budgets"""
from alembic import op
import sqlalchemy as sa

revision = "0031_devops"
down_revision = "0030_qa"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("heartbeats",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(100), nullable=False), sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("token", sa.Text(), nullable=False), sa.Column("token_hash", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("period_seconds", sa.Integer(), nullable=False, server_default="86400"), sa.Column("grace_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("last_ping_at", sa.DateTime(timezone=True)), sa.Column("last_start_at", sa.DateTime(timezone=True)),
        sa.Column("last_duration_ms", sa.Float()), sa.Column("alert_events", sa.String(100)), sa.Column("alert_channels", sa.String(200)), sa.Column("alert_reminder_minutes", sa.Integer()),
        sa.Column("fail_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("last_status", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)), sa.Column("last_error", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("heartbeat_pings",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("heartbeat_id", sa.Integer(), sa.ForeignKey("heartbeats.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("duration_ms", sa.Float()), sa.Column("message", sa.Text()), sa.Column("ip", sa.String(64)))
    op.create_index("ix_heartbeat_pings_hb_time", "heartbeat_pings", ["heartbeat_id", "ts"])
    op.create_table("maintenance_windows",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("title", sa.String(150), nullable=False), sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False, index=True), sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("targets", sa.Text()), sa.Column("suppress_alerts", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("show_on_status", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(320)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("slos",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(100), nullable=False), sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False), sa.Column("objective", sa.Float(), nullable=False), sa.Column("window_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("burn_alerts", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("alert_state", sa.String(20)), sa.Column("alert_state_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(320)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    op.drop_table("slos")
    op.drop_table("maintenance_windows")
    op.drop_index("ix_heartbeat_pings_hb_time", table_name="heartbeat_pings")
    op.drop_table("heartbeat_pings")
    op.drop_table("heartbeats")
