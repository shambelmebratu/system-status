"""initial monitoring schema"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("users", sa.Column("id", sa.Integer, primary_key=True), sa.Column("email", sa.String(320), nullable=False, unique=True), sa.Column("password_hash", sa.Text, nullable=False), sa.Column("role", sa.String(30), nullable=False, server_default="admin"), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("servers", sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(100), nullable=False), sa.Column("endpoint", sa.String(500), nullable=False), sa.Column("agent_token", sa.Text), sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()), sa.Column("cpu_threshold", sa.Float, nullable=False, server_default="85"), sa.Column("memory_threshold", sa.Float, nullable=False, server_default="90"), sa.Column("disk_threshold", sa.Float, nullable=False, server_default="85"), sa.Column("load_threshold", sa.Float, nullable=False, server_default="10"), sa.Column("swap_threshold", sa.Float, nullable=False, server_default="80"), sa.Column("last_status", sa.String(20), nullable=False, server_default="unknown"), sa.Column("last_checked_at", sa.DateTime(timezone=True)), sa.Column("last_error", sa.Text), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("services", sa.Column("id", sa.Integer, primary_key=True), sa.Column("server_id", sa.Integer, sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False), sa.Column("name", sa.String(100), nullable=False), sa.Column("url", sa.String(500), nullable=False), sa.Column("expected_status", sa.Integer, nullable=False, server_default="200"), sa.Column("interval_seconds", sa.Integer, nullable=False, server_default="60"), sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()), sa.Column("last_status", sa.String(20), nullable=False, server_default="unknown"), sa.Column("last_checked_at", sa.DateTime(timezone=True)), sa.Column("last_latency_ms", sa.Float), sa.Column("last_error", sa.Text))
    op.create_table("channels", sa.Column("id", sa.Integer, primary_key=True), sa.Column("name", sa.String(100), nullable=False), sa.Column("type", sa.String(30), nullable=False, server_default="telegram"), sa.Column("token", sa.Text), sa.Column("chat_id", sa.String(200)), sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("alert_events", sa.Column("id", sa.Integer, primary_key=True), sa.Column("target_type", sa.String(30), nullable=False), sa.Column("target_id", sa.Integer, nullable=False), sa.Column("severity", sa.String(20), nullable=False), sa.Column("message", sa.Text, nullable=False), sa.Column("sent", sa.Boolean, nullable=False, server_default=sa.false()), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))


def downgrade():
    for table in ("alert_events", "channels", "services", "servers", "users"):
        op.drop_table(table)
