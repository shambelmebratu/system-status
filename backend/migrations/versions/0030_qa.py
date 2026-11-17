"""QA: content checks on services, multi-step API tests with run history, DNS and domain monitors"""
from alembic import op
import sqlalchemy as sa

revision = "0030_qa"
down_revision = "0029_db_auth_source"
branch_labels = None
depends_on = None

ALERTS = lambda: [sa.Column("alert_events", sa.String(100)), sa.Column("alert_channels", sa.String(200)), sa.Column("alert_reminder_minutes", sa.Integer()),  # noqa: E731
                  sa.Column("fail_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("last_status", sa.String(20), nullable=False, server_default="unknown"),
                  sa.Column("last_checked_at", sa.DateTime(timezone=True)), sa.Column("last_error", sa.Text())]


def upgrade():
    op.add_column("services", sa.Column("keyword", sa.String(200), nullable=True))
    op.add_column("services", sa.Column("keyword_mode", sa.String(10), nullable=False, server_default="contains"))
    op.create_table("api_tests",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(100), nullable=False), sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("steps", sa.Text(), nullable=False), sa.Column("variables", sa.Text()), *ALERTS(),
        sa.Column("last_run_at", sa.DateTime(timezone=True)), sa.Column("last_duration_ms", sa.Float()), sa.Column("created_by", sa.String(320)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_table("test_runs",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("test_id", sa.Integer(), sa.ForeignKey("api_tests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), index=True), sa.Column("duration_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(10), nullable=False), sa.Column("trigger", sa.String(340), nullable=False, server_default="schedule"),
        sa.Column("results", sa.Text(), nullable=False), sa.Column("error", sa.Text()))
    op.create_index("ix_test_runs_test_time", "test_runs", ["test_id", "started_at"])
    op.create_table("dns_monitors",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(100), nullable=False), sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("record_types", sa.String(60), nullable=False, server_default="A,AAAA,MX,NS,TXT"), sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("baseline", sa.Text()), sa.Column("current", sa.Text()),
        sa.Column("changed_at", sa.DateTime(timezone=True)), sa.Column("check_expiry", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expiry_alert_days", sa.String(60)), sa.Column("domain_expires_at", sa.DateTime(timezone=True)), sa.Column("registrar", sa.String(200)),
        sa.Column("expiry_checked_at", sa.DateTime(timezone=True)), sa.Column("expiry_error", sa.Text()), sa.Column("expiry_alerted", sa.Integer()), *ALERTS(),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))


def downgrade():
    op.drop_table("dns_monitors")
    op.drop_index("ix_test_runs_test_time", table_name="test_runs")
    op.drop_table("test_runs")
    op.drop_table("api_tests")
    op.drop_column("services", "keyword_mode")
    op.drop_column("services", "keyword")
